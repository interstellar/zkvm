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
use crate::types::*;
use crate::tx::{self,Tx,VerifiedTx,LogEntry};

/// The ZkVM state used to validate a transaction.
struct VM<'tx, 'transcript, 'gens> {
    version: u64,
    mintime: u64,
    maxtime: u64,
    program: &'tx [u8],
    tx_signature: Signature,
    cs_proof: R1CSProof,

    // is true when tx version is in the future and
    // we allow treating unassigned opcodes as no-ops.
    extension: bool,

    // set to true by `input` and `nonce` instructions
    // when the txid is guaranteed to be unique.
    unique: bool,

    // stack of all items in the VM
    stack: Vec<Item<'tx>>,

    current_run: Run<'tx>,
    run_stack: Vec<Run<'tx>>,
    txlog: Vec<tx::LogEntry<'tx>>,
    signtx_keys: Vec<CompressedRistretto>,
    deferred_operations: Vec<PointOp>,
    variables: Vec<VariableCommitment>,
    cs: r1cs::Verifier<'transcript, 'gens>,
}

impl<'tx, 'transcript, 'gens> VM<'tx, 'transcript, 'gens> {
    /// Creates a new instance of ZkVM with the appropriate parameters
    pub fn verify(tx: &Tx, bp_gens: &BulletproofGens) -> Result<VerifiedTx, VMError> {
        // Allow extension opcodes if tx version is above the currently supported one.
        let extension = tx.version > tx::CURRENT_VERSION;

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

        if vm.stack.len() > 0 {
            return Err(VMError::StackNotClean);
        }

        if vm.unique == false {
            return Err(VMError::NotUniqueTxid);   
        }

        // TBD: let txid = TxID::from_txlog(&self.txlog);

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
            .ok_or(VMError::FormatError)?;

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
                let _: CopyableItem = self.pop_item()?.to_copyable()?;
            },
            Instruction::Dup(i) => {
                if i >= self.stack.len() {
                    return Err(VMError::StackUnderflow);
                }
                let item_idx = self.stack.len() - i - 1;
                let item = self.stack[item_idx].dup()?.clone();
                self.stack.push(item.into());
            },
            Instruction::Roll(i) => {
                if i >= self.stack.len() {
                    return Err(VMError::StackUnderflow);
                }
                let item = self.stack.remove(self.stack.len() - i - 1);
                self.stack.push(item);
            },
            Instruction::Input => {
                let serialized_input = self.pop_data()?;
                let (contract, _, utxo) = tx::parse_input(serialized_input.bytes)?;
                self.stack.push(Item::Contract(contract));
                self.txlog.push(tx::LogEntry::Input(utxo));
                self.unique = true;
            },
            Instruction::Ext(_) => {
                if self.extension {
                    // if extensions are allowed by tx version,
                    // unknown opcodes are treated as no-ops.
                } else {
                    return Err(VMError::ExtensionsNotAllowed)
                }
            }
            _ => unimplemented!()
        }

        return Ok(true);
    }

    fn pop_item(&mut self) -> Result<Item<'tx>, VMError> {
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn pop_data(&mut self) -> Result<Data<'tx>, VMError> {
        self.pop_item()?.to_data()
    }
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

