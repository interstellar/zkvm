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
use crate::tx::{self, LogEntry, Tx, VerifiedTx};
use crate::types::*;

/// The ZkVM state used to validate a transaction.
pub struct VM<'tx, 'transcript, 'gens> {
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
    txlog: Vec<LogEntry<'tx>>,
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
        let (instr, instr_size) =
            Instruction::parse(&self.current_run.program[self.current_run.offset..])
                .ok_or(VMError::FormatError)?;

        // Immediately update the offset for the next instructions
        self.current_run.offset += instr_size;

        match instr {
            Instruction::Push(len) => self.pushdata(len)?,
            Instruction::Drop => self.drop()?,
            Instruction::Dup(i) => self.dup(i)?,
            Instruction::Roll(i) => self.roll(i)?,
            Instruction::Const => unimplemented!(),
            Instruction::Var => unimplemented!(),
            Instruction::Alloc => unimplemented!(),
            Instruction::Mintime => unimplemented!(),
            Instruction::Maxtime => unimplemented!(),
            Instruction::Neg => unimplemented!(),
            Instruction::Add => unimplemented!(),
            Instruction::Mul => unimplemented!(),
            Instruction::Eq => unimplemented!(),
            Instruction::Range(_) => unimplemented!(),
            Instruction::And => unimplemented!(),
            Instruction::Or => unimplemented!(),
            Instruction::Verify => unimplemented!(),
            Instruction::Blind => unimplemented!(),
            Instruction::Reblind => unimplemented!(),
            Instruction::Unblind => unimplemented!(),
            Instruction::Issue => self.issue()?,
            Instruction::Borrow => unimplemented!(),
            Instruction::Retire => unimplemented!(),
            Instruction::Qty => unimplemented!(),
            Instruction::Flavor => unimplemented!(),
            Instruction::Cloak(m, n) => self.cloak(m, n)?,
            Instruction::Import => unimplemented!(),
            Instruction::Export => unimplemented!(),
            Instruction::Input => self.input()?,
            Instruction::Output(k) => self.output(k)?,
            Instruction::Contract(_) => unimplemented!(),
            Instruction::Nonce => self.nonce()?,
            Instruction::Log => unimplemented!(),
            Instruction::Signtx => unimplemented!(),
            Instruction::Call => unimplemented!(),
            Instruction::Left => unimplemented!(),
            Instruction::Right => unimplemented!(),
            Instruction::Delegate => unimplemented!(),
            Instruction::Ext(opcode) => self.ext(opcode)?,
        }

        return Ok(true);
    }

    fn pushdata(&mut self, len: usize) -> Result<(), VMError> {
        let range = self.current_run.offset - len..self.current_run.offset;
        self.stack.push(Item::Data(Data {
            bytes: &self.current_run.program[range],
        }));
        Ok(())
    }

    fn drop(&mut self) -> Result<(), VMError> {
        match self.pop_item()? {
            Item::Data(_) => Ok(()),
            Item::Variable(_) => Ok(()),
            Item::Expression(_) => Ok(()),
            Item::Constraint(_) => Ok(()),
            _ => Err(VMError::TypeNotCopyable),
        }
    }

    fn dup(&mut self, i: usize) -> Result<(), VMError> {
        if i >= self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item_idx = self.stack.len() - i - 1;
        let item = match &self.stack[item_idx] {
            Item::Data(x) => Item::Data(*x),
            Item::Variable(x) => Item::Variable(x.clone()),
            Item::Expression(x) => Item::Expression(x.clone()),
            Item::Constraint(x) => Item::Constraint(x.clone()),
            _ => return Err(VMError::TypeNotCopyable),
        };
        self.push_item(item);
        Ok(())
    }

    fn roll(&mut self, i: usize) -> Result<(), VMError> {
        if i >= self.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item = self.stack.remove(self.stack.len() - i - 1);
        self.push_item(item);
        Ok(())
    }

    fn nonce(&mut self) -> Result<(), VMError> {
        let predicate = Predicate(self.pop_item()?.to_data()?.to_point()?);
        let contract = Contract {
            predicate,
            payload: Vec::new(),
        };
        self.txlog.push(LogEntry::Nonce(predicate, self.maxtime));
        self.push_item(contract);
        self.unique = true;
        Ok(())
    }

    fn issue(&mut self) -> Result<(), VMError> {
        let predicate = Predicate(self.pop_item()?.to_data()?.to_point()?);
        let flv = self.pop_item()?.to_variable()?;
        let qty = self.pop_item()?.to_variable()?;

        // TBD:
        // 1. Pops [point](#point) `pred`.
        // 2. Pops [variable](#variable-type) `flv`; if the variable is detached, attaches it.
        // 3. Pops [variable](#variable-type) `qty`; if the variable is detached, attaches it.
        // 4. Creates a [value](#value-type) with variables `qty` and `flv` for quantity and flavor, respectively.
        // 5. Computes the _flavor_ scalar defined by the [predicate](#predicate) `pred` using the following [transcript-based](#transcript) protocol:
        //     ```
        //     T = Transcript("ZkVM.issue")
        //     T.commit("predicate", pred)
        //     flavor = T.challenge_scalar("flavor")
        //     ```
        // 6. Checks that the `flv` has unblinded commitment to `flavor` by [deferring the point operation](#deferred-point-operations):
        //     ```
        //     flv == flavor·B
        //     ```
        // 7. Adds a 64-bit range proof for the `qty` to the [constraint system](#constraint-system) (see [Cloak protocol](https://github.com/interstellar/spacesuit/blob/master/spec.md) for the range proof definition).
        // 8. Adds an [issue entry](#issue-entry) to the [transaction log](#transaction-log).
        // 9. Creates a [contract](#contract-type) with the value as the only [payload](#contract-payload), protected by the predicate `pred`.

        // The value is now issued into the contract that must be unlocked
        // using one of the contract instructions: [`signtx`](#signx), [`delegate`](#delegate) or [`call`](#call).

        // Fails if:
        // * `pred` is not a valid [point](#point),
        // * `flv` or `qty` are not [variable types](#variable-type).

        // let contract = Contract {
        //     predicate,
        //     payload: Vec::new(),
        // };
        // self.txlog.push(LogEntry::Issue(qty commitment, flv commitment));
        // self.push_item(contract);
        // self.unique = true;
        unimplemented!();
        Ok(())
    }

    fn input(&mut self) -> Result<(), VMError> {
        let serialized_input = self.pop_item()?.to_data()?;
        let (contract, _, utxo) = tx::parse_input(serialized_input.bytes)?;
        self.push_item(contract);
        self.txlog.push(LogEntry::Input(utxo));
        self.unique = true;
        Ok(())
    }

    fn output(&mut self, k: usize) -> Result<(), VMError> {
        // TBD:
        unimplemented!()
    }

    fn cloak(&mut self, m: usize, n: usize) -> Result<(), VMError> {
        // TBD:...
        unimplemented!()
    }

    fn ext(&mut self, _: u8) -> Result<(), VMError> {
        if self.extension {
            // if extensions are allowed by tx version,
            // unknown opcodes are treated as no-ops.
            Ok(())
        } else {
            Err(VMError::ExtensionsNotAllowed)
        }
    }

    fn pop_item(&mut self) -> Result<Item<'tx>, VMError> {
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn push_item<I>(&mut self, item: I)
    where
        I: Into<Item<'tx>>,
    {
        self.stack.push(item.into())
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
