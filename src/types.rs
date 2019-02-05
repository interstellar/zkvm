//! Core ZkVM stack types: data, variables, values, contracts etc.

use core::ops::Range;
use crate::transcript::TranscriptProtocol;
use bulletproofs::r1cs;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::ops::Instruction;
use crate::txlog::UTXO;
use crate::errors::VMError;
use crate::encoding::Subslice;
use crate::vm::VM;

#[derive(Debug)]
pub enum Item {
    Data(Data),
    Contract(Contract),
    Value(Value),
    WideValue(WideValue),
    Variable(Variable),
    Expression(Expression),
    Constraint(Constraint),
}

#[derive(Debug)]
pub enum PortableItem {
    Data(Data),
    Value(Value),
}

#[derive(Debug)]
pub enum Data {
    Opaque(Vec<u8>),
    Witness(DataWitness)
}

pub enum Program {
    Opaque(Range<usize>),
    Witness(Vec<Instruction>)
}

#[derive(Debug)]
pub struct Contract {
    pub(crate) payload: Vec<PortableItem>,
    pub(crate) predicate: Predicate,
}

#[derive(Debug)]
pub struct Value {
    pub(crate) qty: Variable,
    pub(crate) flv: Variable,
}

#[derive(Debug)]
pub struct WideValue {
    pub(crate) r1cs_qty: r1cs::Variable,
    pub(crate) r1cs_flv: r1cs::Variable,
    pub(crate) witness: Option<(Scalar, Scalar)>
}

#[derive(Copy, Clone, Debug)]
pub struct Variable {
    pub(crate) index: usize,
    // the witness is located indirectly in vm::VariableCommitment
}

#[derive(Clone, Debug)]
pub struct Expression {
    /// Terms of the expression
    pub(crate) terms: Vec<(r1cs::Variable, Scalar)>,
}

#[derive(Clone, Debug)]
pub enum Constraint {
    Eq(Expression,Expression),
    And(Vec<Constraint>),
    Or(Vec<Constraint>),
    // no witness needed as it's normally true/false and we derive it on the fly during processing.
    // this also allows us not to wrap this enum in a struct.
}

#[derive(Debug)]
pub enum Predicate {
    Opaque(CompressedRistretto),
    Witness(Box<PredicateWitness>),
}

#[derive(Clone,Debug)]
pub enum Commitment {
    Opaque(CompressedRistretto),
    Open(Box<CommitmentWitness>),
}

#[derive(Debug)]
pub enum Input{
    Opaque(Vec<u8>),
    Witness(Box<(Contract,UTXO)>),
}

/// Prover's representation of the witness.
#[derive(Debug)]
pub enum DataWitness {
    Program(Vec<Instruction>),
    Predicate(Box<PredicateWitness>), // maybe having Predicate and one more indirection would be cleaner - lets see how it plays out
    Commitment(Box<CommitmentWitness>),
    Scalar(Box<Scalar>),
    Input(Box<(Contract, UTXO)>),
}

/// Prover's representation of the predicate tree with all the secrets
#[derive(Debug)]
pub enum PredicateWitness {
    Key(Scalar),
    Program(Vec<Instruction>),
    Or(Box<(PredicateWitness, PredicateWitness)>),
}

impl PredicateWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        unimplemented!()
    }
}

/// Prover's representation of the commitment secret: witness and blinding factor
#[derive(Clone,Debug)]
pub struct CommitmentWitness {
    value: Scalar,
    blinding: Scalar,
}

impl Commitment {
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Commitment::Opaque(x) => *x,
            Commitment::Open(w) => w.to_point(),
        }
    }
}

impl Predicate {
    pub fn to_point(&self) -> CompressedRistretto {
        match self {
            Predicate::Opaque(point) => *point,
            Predicate::Witness(witness) => witness.to_point(), 
        }
    }
}

impl CommitmentWitness {
    pub fn to_point(&self) -> CompressedRistretto {
        let gens = PedersenGens::default();
        gens.commit(self.value, self.blinding).compress()
    }
}

impl Item{
 
    // Downcasts to Data type
    pub fn to_data(self) -> Result<Data, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData),
        }
    }

    // Downcasts to a portable type
    pub fn to_portable(self) -> Result<PortableItem, VMError> {
        match self {
            Item::Data(x) => Ok(PortableItem::Data(x)),
            Item::Value(x) => Ok(PortableItem::Value(x)),
            _ => Err(VMError::TypeNotPortable),
        }
    }

    // Downcasts to Variable type
    pub fn to_variable(self) -> Result<Variable, VMError> {
        match self {
            Item::Variable(v) => Ok(v),
            _ => Err(VMError::TypeNotVariable),
        }
    }

    // Downcasts to Expression type (Variable is NOT casted to Expression)
    pub fn to_expression(self) -> Result<Expression, VMError> {
        match self {
            Item::Expression(expr) => Ok(expr),
            _ => Err(VMError::TypeNotExpression),
        }
    }

    // Downcasts to Value type
    pub fn to_value(self) -> Result<Value, VMError> {
        match self {
            Item::Value(v) => Ok(v),
            _ => Err(VMError::TypeNotValue),
        }
    }


    // Downcasts to WideValue type (Value is NOT casted to WideValue)
    pub fn to_wide_value(self) -> Result<WideValue, VMError> {
        match self {
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    // Downcasts to Contract type
    pub fn to_contract(self) -> Result<Contract, VMError> {
        match self {
            Item::Contract(c) => Ok(c),
            _ => Err(VMError::TypeNotContract),
        }
    }
}

impl Data {

    /// Downcast to a Predicate type.
    pub fn to_predicate(self) -> Result<Predicate, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = Subslice::new(&data).read_point()?;
                Ok(Predicate::Opaque(point))
            }
            Data::Witness(witness) => {
                match witness {
                    DataWitness::Predicate(w) => Ok(Predicate::Witness(w)),
                    _ => Err(VMError::TypeNotPredicate),
                }
            }
            
        }
    }

    pub fn to_commitment(self) -> Result<Commitment, VMError> {
        match self {
            Data::Opaque(data) => {
                let point = Subslice::new(&data).read_point()?;
                Ok(Commitment::Opaque(point))
            }
            Data::Witness(witness) => {
                match witness {
                    DataWitness::Commitment(w) => Ok(Commitment::Open(w)),
                    _ => Err(VMError::TypeNotCommitment),
                }
            }
        }
    }

    pub fn to_input(self) -> Result<Input, VMError> {
        match self {
            Data::Opaque(data) => {
                Ok(Input::Opaque(data))
            }
            Data::Witness(witness) => {
                match witness {
                    DataWitness::Input(w) => Ok(Input::Witness(w)),
                    _ => Err(VMError::TypeNotInput),
                }
            }
        }
    }

    // pub fn to_u8x32(self, program: &[u8]) ->Result<[u8; 32], VMError> {
    //     let mut buf = [0u8; 32];
    //     let range = self.ensure_length(32)?;
    //     let prog_slice = program.get(range).ok_or(VMError::FormatError)?;
    //     buf.copy_from_slice(prog_slice);
    //     Ok(buf)
    // }

    // pub fn to_point(self, program: &[u8]) -> Result<CompressedRistretto, VMError> {
    //     let point = match self {
    //         Data::Opaque(_) => CompressedRistretto(self.to_u8x32(program)?),
    //         Data::Witness(_) => unimplemented!(),
    //     };
    //     Ok(point)
    // }

    // /// Ensures the length of the data string
    // pub fn ensure_length(self, len: usize) -> Result<Range<usize>, VMError> {
    //     let range = match self {
    //         Data::Opaque(range) => range,
    //         Data::Witness(_) => return Err(VMError::DataNotOpaque)
    //     };
    //     if range.len() != len {
    //         return Err(VMError::FormatError);
    //     }
    //     Ok(range)
    // }

    // /// Converts a bytestring to a 32-byte array
    // pub fn to_u8x32(self) -> Result<[u8; 32], VMError> {
    //     let mut buf = [0u8; 32];
    //     buf.copy_from_slice(self.ensure_length(32)?.bytes);
    //     Ok(buf)
    // }

    // /// Converts a bytestring to a compressed point
    // pub fn to_point(self) -> Result<CompressedRistretto, VMError> {
    //     Ok(CompressedRistretto(self.to_u8x32()?))
    // }

    // /// Converts a bytestring to a canonical scalar
    // pub fn to_scalar(self) -> Result<Scalar, VMError> {
    //     Scalar::from_canonical_bytes(self.to_u8x32()?).ok_or(VMError::FormatError)
    // }
}

impl Value {
    /// Computes a flavor as defined by the `issue` instruction from a predicate.
    pub fn issue_flavor(predicate: &Predicate) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", predicate.0.as_bytes());
        t.challenge_scalar(b"flavor")
    }
}

impl Input {
    pub fn spend<CS, D> (self, vm: &mut VM<CS, D>) -> Result<(Contract, UTXO), VMError> {
        match self {
            Opaque(data) => {
                Self::decode_input(vm, data)
            }
            Witness(w) => {
                unimplemented!()
            }
        }
    }

    fn decode_input(vm: &mut VM, data: Vec<u8>) -> Result<(Contract, UTXO), VMError> {
        let slice = Subslice::new(&data);
        let txid = TxID(slice.read_u8x32()?);
        let contract = Self::decode_output(slice)?;
        let utxo = UTXO::from_output(slice, &txid);
        Ok((contract, utxo))
    }

    fn decode_output<'a>(output: Subslice<'a>) -> Result<(Contract), VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let predicate = Predicate(output.read_point(output)?);
        let k = output.read_size()?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > output.len() {
            return Err(VMError::FormatError);
        }

        let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
        for _ in 0..k {
            let item = match output.read_u8()? {
                DATA_TYPE => {
                    let len = output.read_size()?;
                    let bytes = output.read_bytes(len)?;
                    PortableItem::Data(Data { bytes })
                }
                VALUE_TYPE => {
                    let qty = output.read_point()?;
                    let flv = output.read_point()?;

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

    /// Parses the output and returns an instantiated contract.
    fn decode_output(&mut self, output: &[u8]) -> Result<(Contract), VMError> {
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

        // TODO: replace the slices themselves with a tracking of the indices.

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
}

// Upcasting all types to Item

impl From<Data> for Item {
    fn from(x: Data) -> Self {
        Item::Data(x)
    }
}

impl From<Value> for Item {
    fn from(x: Value) -> Self {
        Item::Value(x)
    }
}

impl From<WideValue> for Item {
    fn from(x: WideValue) -> Self {
        Item::WideValue(x)
    }
}

impl From<Contract> for Item {
    fn from(x: Contract) -> Self {
        Item::Contract(x)
    }
}

impl From<Variable> for Item {
    fn from(x: Variable) -> Self {
        Item::Variable(x)
    }
}

impl From<Expression> for Item {
    fn from(x: Expression) -> Self {
        Item::Expression(x)
    }
}

impl From<Constraint> for Item {
    fn from(x: Constraint) -> Self {
        Item::Constraint(x)
    }
}

// Upcast a portable item to any item
impl From<PortableItem> for Item {
    fn from(portable: PortableItem) -> Self {
        match portable {
            PortableItem::Data(x) => Item::Data(x),
            PortableItem::Value(x) => Item::Value(x),
        }
    }
}
