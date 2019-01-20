use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::Signature;

pub const CURRENT_TX_VERSION: u64 = 1;

/// Instance of a transaction that contains all necessary data to validate it.
pub struct Tx {
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (sec)
    pub mintime: u64,

    /// Timestamp after which tx is invalid (sec)
    pub maxtime: u64,

    /// Program representing the transaction
    pub program: Vec<u8>,

    /// Aggregated signature of the txid
    pub signature: Signature,

    /// Constraint system proof for all the constraints
    pub proof: R1CSProof,
}

/// Represents a verified transaction: a txid and a list of state updates.
pub struct VerifiedTx {
    /// Transaction ID
    pub txid: [u8; 32],
    // TBD: list of txlog inputs, outputs and nonces to be inserted/deleted in the blockchain state.
}

/// The ZkVM state used to validate a transaction.
struct VM<'tx, 'transcript, 'gens> {
    version: u64,
    mintime: u64,
    maxtime: u64,
    program: &'tx [u8],
    tx_signature: Signature,
    cs_proof: R1CSProof,

    extension: bool,
    unique: bool,
    stack: Vec<Item<'tx>>,

    current_run: Run<'tx>,
    run_stack: Vec<Run<'tx>>,
    txlog: Vec<[u8; 32]>,
    signtx_keys: Vec<CompressedRistretto>,
    deferred_operations: Vec<PointOp>,
    variables: Vec<VariableCommitment>,
    cs: r1cs::Verifier<'transcript, 'gens>,
}

impl<'tx, 'transcript, 'gens> VM<'tx, 'transcript, 'gens> {
    /// Creates a new instance of ZkVM with the appropriate parameters
    pub fn verify(tx: &Tx, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        // Allow extension opcodes if tx version is above the currently supported one.
        let extension = tx.version > CURRENT_TX_VERSION;

        // Construct a CS verifier to be used during ZkVM execution.
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs"); // XXX: spec does not specify this
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(&bp_gens, &pc_gens, &mut r1cs_transcript);

        let mut vm = VM {
            version: tx.version,
            mintime: tx.mintime,
            maxtime: tx.maxtime,
            program: &tx.program,
            tx_signature: tx.signature,
            cs_proof: tx.proof.clone(),

            extension,
            unique: false,
            stack: Vec::new(),

            current_run: Run {
                program: &tx.program,
                offset: 0,
            },
            run_stack: Vec::new(),
            txlog: Vec::new(),
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
            variables: Vec::new(),
            cs,
        };

        vm.run()?;

        // TODO: check signatures and proofs

        unimplemented!()
    }

    fn run(&mut self) -> Result<(), VMError> {
        loop {
            if !self.step()? {
                break;
            }
        }
        Ok(())
    }

    /// Returns a flag indicating whether to continue the execution
    fn step(&mut self) -> Result<bool, VMError> {
        // Have we reached the end of the current program?
        if self.current_run.offset == self.current_run.program.len() {
            // Do we have more programs to run?
            if let Some(run) = self.run_stack.pop() {
                // Continue with the previously remembered program
                self.current_run = run;
                return Ok(true);
            } else {
                // Finish the execution
                return Ok(false);
            }
        }

        // Read the next instruction and advance the program state.
        let (instr, instrsize) = Instruction::parse(&self.current_run.program[self.current_run.offset..])
            .ok_or(VMError::MalformedInstruction)?;

        // Immediately update the offset for the next instructions
        self.current_run.offset += instrsize;

        match instr {
            Instruction::Push(len) => {
                let range = self.current_run.offset-len .. self.current_run.offset;
                self.stack.push(Item::Data(Data{
                    bytes: &self.current_run.program[range]
                }));
            },
            Instruction::Drop => {
                self.stack.pop().ok_or(VMError::StackUnderflow)?.to_copyable()?
            },
            Instruction::Dup(i) => {
                if i >= self.stack.len() {
                    return Err(VMError::StackUnderflow);
                }
                let item = self.stack[self.stack.len() - i - 1].copy()?;
                self.stack.push(item);
            },
            Instruction::Roll(i) => {
                if i >= self.stack.len() {
                    return Err(VMError::StackUnderflow);
                }
                let item = self.stack.remove(self.stack.len() - i - 1);
                self.stack.push(item);
            },
            Instruction::Input => {
                // TBD: pop parse input structure
                self.stack.pop().ok_or()
            }
            _ => unimplemented!()
        }

        return Ok(true);
    }

    
}

enum Item<'tx> {
    Data(Data<'tx>),
    Contract(Contract<'tx>),
    Value(Value<'tx>),
    WideValue(WideValue<'tx>),
}

impl<'tx> Item<'tx> {
    fn to_copyable(self) -> Result<Item<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(Item::Data(x)),
            // TBD: variable, expression, constraint are also copyable
            _ => Err(VMError::TypeNotCopyable)
        }
    }

    fn to_data(self) -> Result<Data<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData)
        }
    }

    fn copy(&self) -> Result<Item<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(Item::Data(x)),
            // TBD: variable, expression, constraint are also copyable
            _ => Err(VMError::TypeNotCopyable)
        }
    }
}

#[derive(Copy,Clone)]
struct Data<'tx> {
    bytes: &'tx [u8],
}

struct Contract<'tx> {
    payload: Vec<Item<'tx>>,
    predicate: Predicate,
}

struct Value<'tx> {
}

struct WideValue<'tx> {
}

struct Run<'tx> {
    program: &'tx [u8],
    offset: usize,
}

enum VariableCommitment {
    /// Variable is not attached to the CS yet,
    /// so its commitment is replaceable via `reblind`.
    Detached(CompressedRistretto),

    /// Variable is attached to the CS yet and has index in CS,
    /// so its commitment is no longer replaceable via `reblind`.
    Attached(CompressedRistretto, usize),
}
