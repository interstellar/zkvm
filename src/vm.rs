use core::ops::Range;
use std::collections::vec_deque::VecDeque;
use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit;
use std::iter::FromIterator;

use crate::encoding;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::*;
use crate::transcript::TranscriptProtocol;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;

/// Current tx version determines which extension opcodes are treated as noops (see VM.extension flag).
pub const CURRENT_VERSION: u64 = 1;

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x01;


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
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (sec)
    pub mintime: u64,

    /// Timestamp after which tx is invalid (sec)
    pub maxtime: u64,

    /// Transaction ID
    pub id: TxID,

    // List of inputs, outputs and nonces to be inserted/deleted in the blockchain state.
    pub log: Vec<Entry>,
}

pub struct State<CS: r1cs::ConstraintSystem> {
    mintime: u64,
    maxtime: u64,

    // is true when tx version is in the future and
    // we allow treating unassigned opcodes as no-ops.
    extension: bool,

    // set to true by `input` and `nonce` instructions
    // when the txid is guaranteed to be unique.
    unique: bool,

    // stack of all items in the VM
    stack: Vec<Item>,

    current_run: Run,
    run_stack: Vec<Run>,
    txlog: Vec<Entry>,
    variable_commitments: Vec<VariableCommitment>,
    cs: CS,
}

/// An state of running a single program string.
/// VM consists of a stack of such _Runs_.
/// The slices begin at the next instruction to be processed.
enum Run {
    /// Prover's running program
    ProgramWitness(VecDeque<Instruction>),

    /// Verifier's running program is a slice into a tx.program
    Program(Range<usize>)
}

/// And indirect reference to a high-level variable within a constraint system.
/// Variable types store index of such commitments that allows replacing them.
pub struct VariableCommitment {
    /// Pedersen commitment to a variable
    commitment: CompressedRistretto,

    /// Attached/detached state
    /// None if the variable is not attached to the CS yet,
    /// so its commitment is replaceable via `reblind`.
    /// Some if variable is attached to the CS yet and has an index in CS,
    /// so its commitment is no longer replaceable via `reblind`.
    variable: Option<r1cs::Variable>,

    /// Witness value and its blinding factor for the commitment
    witness: Option<CommitmentWitness>,
}

/// `VM` is a common trait for verifier's and prover's instances of ZkVM
/// that implements instructions generically.
pub trait VM {
    /// Concrete type implementing CS API: r1cs::Verifier or r1cs::Prover
    type CS: r1cs::ConstraintSystem;

    /// Returns the reference to the state object
    fn state(&mut self) -> &mut State<Self::CS>;
}

impl<CS: r1cs::ConstraintSystem> State<CS> {

    pub fn new(
        version: u64,
        mintime: u64,
        maxtime: u64,
        program_range: Range<usize>,
        cs: CS
    ) {
        State{
            mintime,
            maxtime,
            extension: version > CURRENT_VERSION,
            unique: false,
            stack: Vec::new(),
            current_run: Run::Program(program_range),
            run_stack: Vec::new(),
            txlog: vec![Entry::Header(version, mintime, maxtime)],
            variable_commitments: Vec::new(),
            cs,
        }
    }
}

/// Internal implementation of VM common to both prover and verifier
pub trait VMInternal: VM {

    /// Runs through the entire program and nested programs until completion.
    fn run(&mut self) -> Result<TxID, VMError> {
        loop {
            if !self.step()? {
                break;
            }
        }

        if self.state().stack.len() > 0 {
            return Err(VMError::StackNotClean);
        }

        if self.state().unique == false {
            return Err(VMError::NotUniqueTxid);
        }

        let txid = TxID::from_log(&self.state().txlog[..]);
        
        Ok(txid)
    }

    fn finish_run(&self) -> bool {
        let state = self.state();
        // Do we have more programs to run?
        if let Some(run) = state.run_stack.pop() {
            // Continue with the previously remembered program
            state.current_run = run;
            return true;
        }
        // Finish the execution
        return false;
    }

    /// Returns a flag indicating whether to continue the execution
    fn step(&mut self) -> Result<bool, VMError> {
        if let Some(instr) = self.next_instruction() {
            // Attempt to read the next instruction and advance the program state
            match instr {
                // the data is just a slice, so the clone would copy the slice struct,
                // not the actual buffer of bytes.
                Instruction::Push(data) => self.pushdata(data)?,
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
                Instruction::Retire => self.retire()?,
                Instruction::Qty => unimplemented!(),
                Instruction::Flavor => unimplemented!(),
                Instruction::Cloak(m, n) => self.cloak(m, n)?,
                Instruction::Import => unimplemented!(),
                Instruction::Export => unimplemented!(),
                Instruction::Input => self.input()?,
                Instruction::Output(k) => self.output(k)?,
                Instruction::Contract(k) => self.contract(k)?,
                Instruction::Nonce => self.nonce()?,
                Instruction::Log => unimplemented!(),
                Instruction::Signtx => self.signtx()?,
                Instruction::Call => unimplemented!(),
                Instruction::Left => unimplemented!(),
                Instruction::Right => unimplemented!(),
                Instruction::Delegate => unimplemented!(),
                Instruction::Ext(opcode) => self.ext(opcode)?,
            }
            return Ok(true);
        } else {
            // Reached the end of the current program
            return Ok(self.finish_run());
        }
    }

    fn pushdata(&mut self, data: Data) -> Result<(), VMError> {
        self.state().push_item(data);
        Ok(())
    }

    fn drop(&mut self) -> Result<(), VMError> {
        let state = self.state();
        match state.pop_item()? {
            Item::Data(_) => Ok(()),
            Item::Variable(_) => Ok(()),
            Item::Expression(_) => Ok(()),
            Item::Constraint(_) => Ok(()),
            _ => Err(VMError::TypeNotCopyable),
        }
    }

    fn dup(&mut self, i: usize) -> Result<(), VMError> {
        let state = self.state();
        if i >= state.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item_idx = state.stack.len() - i - 1;
        let item = match &state.stack[item_idx] {
            // Call some item method implemented for verifier/prover
            // item.dup_item()
            Item::Data(x) => Item::Data(*x),
            Item::Variable(x) => Item::Variable(x.clone()),
            Item::Expression(x) => Item::Expression(x.clone()),
            Item::Constraint(x) => Item::Constraint(x.clone()),
            _ => return Err(VMError::TypeNotCopyable),
        };
        state.push_item(item);
        Ok(())
    }

    fn roll(&mut self, i: usize) -> Result<(), VMError> {
        let state = self.state();
        if i >= state.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let item = state.stack.remove(state.stack.len() - i - 1);
        state.push_item(item);
        Ok(())
    }

    fn nonce(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let predicate = Predicate(state.pop_item()?.to_data()?.to_point()?);
        let contract = Contract {
            predicate,
            payload: Vec::new(),
        };
        state.txlog.push(Entry::Nonce(predicate, state.maxtime));
        state.push_item(contract);
        state.unique = true;
        Ok(())
    }

    fn issue(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let predicate = Predicate(state.pop_item()?.to_data()?.to_point()?);
        let flv = state.pop_item()?.to_variable()?;
        let qty = state.pop_item()?.to_variable()?;

        let (flv_point, _) = self.attach_variable(flv);
        let (qty_point, _) = self.attach_variable(qty);

        let value = Value { qty, flv };

        let flv_scalar = Value::issue_flavor(&predicate);
        // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
        self.deferred_operations.push(PointOp {
            primary: Some(flv_scalar),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), flv_point)],
        });

        let qty_expr = self.variable_to_expression(qty);
        self.add_range_proof(64, qty_expr)?;

        self.txlog.push(Entry::Issue(qty_point, flv_point));

        let contract = Contract {
            predicate,
            payload: vec![PortableItem::Value(value)],
        };

        self.push_item(contract);
        Ok(())
    }

    fn retire(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let value = state.pop_item()?.to_value()?;
        let qty = self.get_variable_commitment(value.qty);
        let flv = self.get_variable_commitment(value.flv);
        state.txlog.push(Entry::Retire(qty, flv));
        Ok(())
    }

    /// _input_ **input** → _contract_
    fn input(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let serialized_input = state.pop_item()?.to_data()?;
        let (contract, _, utxo) = self.decode_input(serialized_input.bytes)?;
        state.push_item(contract);
        state.txlog.push(Entry::Input(utxo));
        state.unique = true;
        Ok(())
    }

    /// _items... predicate_ **output:_k_** → ø
    fn output(&mut self, k: usize) -> Result<(), VMError> {
        let state = self.state();
        let predicate = Predicate(state.pop_item()?.to_data()?.to_point()?);

        if k > state.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let payload = state
            .stack
            .drain(state.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        let output = self.encode_output(Contract { predicate, payload });
        state.txlog.push(Entry::Output(output));
        Ok(())
    }

    fn contract(&mut self, k: usize) -> Result<(), VMError> {
        let state = self.state();
        let predicate = Predicate(state.pop_item()?.to_data()?.to_point()?);

        if k > state.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        let payload = state
            .stack
            .drain(state.stack.len() - k..)
            .map(|item| item.to_portable())
            .collect::<Result<Vec<_>, _>>()?;

        state.push_item(Contract { predicate, payload });
        Ok(())
    }

    fn cloak(&mut self, m: usize, n: usize) -> Result<(), VMError> {
        let state = self.state();
        // _widevalues commitments_ **cloak:_m_:_n_** → _values_
        // Merges and splits `m` [wide values](#wide-value-type) into `n` [values](#values).

        if m > state.stack.len() || n > state.stack.len() {
            return Err(VMError::StackUnderflow);
        }
        // Now that individual m and n are bounded by the (not even close to overflow) stack size,
        // we can add them together.
        // This does not overflow if the stack size is below 2^30 items.
        assert!(state.stack.len() < (1usize << 30));
        if (m + 2 * n) > state.stack.len() {
            return Err(VMError::StackUnderflow);
        }

        let mut output_values: Vec<Value> = Vec::with_capacity(2 * n);

        let mut cloak_ins: Vec<spacesuit::AllocatedValue> = Vec::with_capacity(m);
        let mut cloak_outs: Vec<spacesuit::AllocatedValue> = Vec::with_capacity(2 * n);

        // Make cloak outputs and output values using (qty,flv) commitments
        for _ in 0..n {
            let flv = state.pop_item()?.to_data()?.to_point()?;
            let qty = state.pop_item()?.to_data()?.to_point()?;

            let qty = state.make_variable(qty);
            let flv = state.make_variable(flv);

            let value = Value { qty, flv };
            let cloak_value = self.value_to_cloak_value(&value);

            // insert in the same order as they are on stack (the deepest item will be at index 0)
            output_values.insert(0, value);
            cloak_outs.insert(0, cloak_value);
        }

        // Make cloak inputs out of wide values
        for _ in 0..m {
            let item = state.pop_item()?;
            let walue = self.item_to_wide_value(item)?;

            let cloak_value = self.wide_value_to_cloak_value(&walue);

            // insert in the same order as they are on stack (the deepest item will be at index 0)
            cloak_ins.insert(0, cloak_value);
        }

        spacesuit::cloak(&mut self.cs, cloak_ins, cloak_outs).map_err(|_| VMError::FormatError)?;

        // Push in the same order.
        for v in output_values.into_iter() {
            state.push_item(v);
        }

        Ok(())
    }

    // Prover:
    // - remember the KeyType (Scalar) in a list and make a sig later.
    // Verifier:
    // - remember the KeyType (Point) in a list and check a sig later.
    // Both: put the payload onto the stack.
    // _contract_ **signtx** → _results..._
    fn signtx(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let contract = state.pop_item()?.to_contract()?;
        state.signtx_keys.push(VerificationKey(contract.predicate.0));
        for item in contract.payload.into_iter() {
            state.push_item(item);
        }
        Ok(())
    }

    fn ext(&mut self, _: u8) -> Result<(), VMError> {
        let state = self.state();
        if state.extension {
            // if extensions are allowed by tx version,
            // unknown opcodes are treated as no-ops.
            Ok(())
        } else {
            Err(VMError::ExtensionsNotAllowed)
        }
    }

    // Return the next instruction, if it exists, and advance the 
    // program state pointer.
    fn next_instruction(&mut self) -> Option<Instruction> {
        // Maybe implemented by each type, or in the Run type? 
        // let (instr, instr_size) =
        //     Instruction::parse(&txprogram, self.state().current_run.range)?;

        // // Immediately update the offset for the next instructions
        // self.state().current_run.offset += instr_size;
        unimplemented!();
    }

    // Unimplemented functions
     fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
        unimplemented!();
    }
}

impl<T: VM> VMInternal for T {}


impl<CS: r1cs::ConstraintSystem> State<CS> {

    fn push_item<T>(&mut self, item: T)
    where
        T: Into<Item>,
    {
        self.stack.push(item.into())
    }

    fn pop_item(&mut self) -> Result<Item, VMError> {
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn make_variable(&mut self, commitment: Data) -> Result<Variable, VMError> {
        let index = self.variable_commitments.len();

        // TBD: if data has witness, coerce to commitment witness.
        self.variable_commitments
            .push(VariableCommitment::Detached(commitment.into()));
        Variable { index }
    }
}


// Utility methods


/*

impl<transcript, 'gens> VM<'transcript, 'gens> {

    fn attach_variable(&mut self, var: Variable) -> (CompressedRistretto, r1cs::Variable) {
        // This subscript never fails because the variable is created only via `make_variable`.
        match self.variable_commitments[var.index] {
            VariableCommitment::Detached(p) => {
                let r1cs_var = self.cs.commit(p);
                self.variable_commitments[var.index] = VariableCommitment::Attached(p, r1cs_var);
                (p, r1cs_var)
            }
            VariableCommitment::Attached(p, r1cs_var) => (p, r1cs_var),
        }
    }

    fn value_to_cloak_value(&mut self, value: &Value) -> spacesuit::AllocatedValue {
        spacesuit::AllocatedValue {
            q: self.attach_variable(value.qty).1,
            f: self.attach_variable(value.flv).1,
            // TBD: maintain assignments inside Value types in order to use ZkVM to compute the R1CS proof
            assignment: None,
        }
    }

    fn wide_value_to_cloak_value(&mut self, walue: &WideValue) -> spacesuit::AllocatedValue {
        spacesuit::AllocatedValue {
            q: walue.r1cs_qty,
            f: walue.r1cs_flv,
            // TBD: maintain assignments inside WideValue types in order to use ZkVM to compute the R1CS proof
            assignment: None,
        }
    }

    fn item_to_wide_value(&mut self, item: Item) -> Result<WideValue, VMError> {
        match item {
            Item::Value(value) => Ok(WideValue {
                r1cs_qty: self.attach_variable(value.qty).1,
                r1cs_flv: self.attach_variable(value.flv).1,
            }),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    fn item_to_expression(&mut self, item: Item) -> Result<Expression, VMError> {
        match item {
            Item::Variable(v) => Ok(self.variable_to_expression(v)),
            Item::Expression(expr) => Ok(expr),
            _ => Err(VMError::TypeNotExpression),
        }
    }

    fn variable_to_expression(&mut self, var: Variable) -> Expression {
        let (_, r1cs_var) = self.attach_variable(var);
        Expression {
            terms: vec![(r1cs_var, Scalar::one())],
        }
    }

    /// Parses the input and returns the instantiated contract, txid and UTXO identifier.
    fn decode_input(&mut self, input: &'tx [u8]) -> Result<(Contract, TxID, UTXO), VMError> {
        //        Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>

        let (txid, output) = encoding::read_u8x32(input)?;
        let txid = TxID(txid);
        let contract = self.decode_output(output)?;
        let utxo = UTXO::from_output(output, &txid);
        Ok((contract, txid, utxo))
    }

    /// Parses the output and returns an instantiated contract.
    fn decode_output(&mut self, output: &'tx [u8]) -> Result<(Contract), VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let (predicate, payload) = encoding::read_point(output)?;
        let predicate = Predicate(predicate);

        let (k, mut items) = encoding::read_usize(payload)?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > items.len() {
            return Err(VMError::FormatError);
        }

        let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
        for _ in 0..k {
            let (item_type, rest) = encoding::read_u8(items)?;
            let item = match item_type {
                DATA_TYPE => {
                    let (len, rest) = encoding::read_usize(rest)?;
                    let (bytes, rest) = encoding::read_bytes(len, rest)?;
                    items = rest;
                    PortableItem::Data(Data { bytes })
                }
                VALUE_TYPE => {
                    let (qty, rest) = encoding::read_point(rest)?;
                    let (flv, rest) = encoding::read_point(rest)?;

                    let qty = self.make_variable(qty);
                    let flv = self.make_variable(flv);

                    items = rest;
                    PortableItem::Value(Value { qty, flv })
                }
                _ => return Err(VMError::FormatError),
            };
            payload.push(item);
        }

        Ok(Contract { predicate, payload })
    }

    fn encode_output(&mut self, contract: Contract) -> Vec<u8> {
        let mut output = Vec::with_capacity(contract.output_size());
        encoding::write_point(&contract.predicate.0, &mut output);
        encoding::write_u32(contract.payload.len() as u32, &mut output);

        for item in contract.payload.iter() {
            match item {
                PortableItem::Data(d) => {
                    encoding::write_u8(DATA_TYPE, &mut output);
                    encoding::write_u32(d.bytes.len() as u32, &mut output);
                    encoding::write_bytes(d.bytes, &mut output);
                }
                PortableItem::Value(v) => {
                    encoding::write_u8(VALUE_TYPE, &mut output);
                    let qty = self.get_variable_commitment(v.qty);
                    let flv = self.get_variable_commitment(v.flv);
                    encoding::write_point(&qty, &mut output);
                    encoding::write_point(&flv, &mut output);
                }
            }
        }

        output
    }

    fn add_range_proof(&mut self, bitrange: usize, expr: Expression) -> Result<(), VMError> {
        spacesuit::range_proof(
            &mut self.cs,
            r1cs::LinearCombination::from_iter(expr.terms),
            // TBD: maintain the assignment for the expression and provide it here
            None,
            bitrange,
        )
        .map_err(|_| VMError::R1CSInconsistency)
    }
}

impl Contract {
    fn output_size(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => size += 1 + 4 + d.bytes.len(),
                PortableItem::Value(_) => size += 1 + 64,
            }
        }
        size
    }
}

*/