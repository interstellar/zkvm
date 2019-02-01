//! Core ZkVM stack types: data, variables, values, contracts etc.

use crate::errors::VMError;
use crate::predicate::Predicate;

use crate::transcript::TranscriptProtocol;
use bulletproofs::r1cs;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// A trait for the stack item: data, value, contract etc.
pub trait ItemTrait {
    /// The parameter for the type of the items that are "data types".
    type DataType: DataTrait + Into<Self>;
    type ContractType: ContractTrait;

    /// Downcasts any item to a data item
    fn to_data(self) -> Result<Self::DataType, VMError>;

    /// Downcasts to a portable type
    fn to_portable(self) -> Result<PortableItem<Self::DataType>, VMError>;

    /// Downcasts to Variable type
    fn to_variable(self) -> Result<Variable, VMError>;

    /// Downcasts to Expression type (Variable is NOT casted to Expression)
    fn to_expression(self) -> Result<Expression, VMError>;

    /// Downcasts to Value type
    fn to_value(self) -> Result<Value, VMError>;

    /// Downcasts to WideValue type (Value is NOT casted to WideValue)
    fn to_wide_value(self) -> Result<WideValue, VMError>;

    /// Downcasts to Contract type
    fn to_contract(self) -> Result<Self::ContractType, VMError>;
}

/// A trait for the "data" items on the stack.
/// Prover impls that trait for concrete structures: commitments, predicates etc,
/// while the verifier uses a simple byteslice for all of these things.
pub trait DataTrait: Clone {
    // TODO: methods to convert to points, predicates, pubkeys etc
}

/// A trait for the contract type.
/// The verifier implements `Contract` with simple data types and a predicate as a compressed point,
/// while the prover has rich data structures in place of data and a whole predicate tree.
pub trait ContractTrait {
    // TODO: we may be forced to add associated types for data type here eventually
}

#[derive(Debug)]
pub enum Item<'tx> {
    Data(Data<'tx>),
    Contract(Contract<'tx>),
    Value(Value),
    WideValue(WideValue),
    Variable(Variable),
    Expression(Expression),
    Constraint(Constraint),
}

#[derive(Debug)]
pub enum PortableItem<D:DataTrait> {
    Data(D),
    Value(Value),
}

#[derive(Copy, Clone, Debug)]
pub struct Data<'tx> {
    pub(crate) bytes: &'tx [u8],
}

#[derive(Debug)]
pub struct Contract<'tx> {
    pub(crate) payload: Vec<PortableItem<Data<'tx>>>,
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
}

#[derive(Copy, Clone, Debug)]
pub struct Variable {
    pub(crate) index: usize,
}

#[derive(Clone, Debug)]
pub struct Expression {
    pub(crate) terms: Vec<(r1cs::Variable, Scalar)>,
}

#[derive(Clone, Debug)]
pub struct Constraint {
    // TBD
}

impl<'tx> DataTrait for Data<'tx> {

}

impl<'tx> ItemTrait for Item<'tx>{
    type DataType = Data<'tx>;
    type ContractType = Contract<'tx>;

    // Downcasts to Data type
    fn to_data(self) -> Result<Data<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData),
        }
    }

    // Downcasts to a portable type
    fn to_portable(self) -> Result<PortableItem<Self::DataType>, VMError> {
        match self {
            Item::Data(x) => Ok(PortableItem::Data(x)),
            Item::Value(x) => Ok(PortableItem::Value(x)),
            _ => Err(VMError::TypeNotPortable),
        }
    }

    // Downcasts to Variable type
    fn to_variable(self) -> Result<Variable, VMError> {
        match self {
            Item::Variable(v) => Ok(v),
            _ => Err(VMError::TypeNotVariable),
        }
    }

    // Downcasts to Expression type (Variable is NOT casted to Expression)
    fn to_expression(self) -> Result<Expression, VMError> {
        match self {
            Item::Expression(expr) => Ok(expr),
            _ => Err(VMError::TypeNotExpression),
        }
    }

    // Downcasts to Value type
    fn to_value(self) -> Result<Value, VMError> {
        match self {
            Item::Value(v) => Ok(v),
            _ => Err(VMError::TypeNotValue),
        }
    }


    // Downcasts to WideValue type (Value is NOT casted to WideValue)
    fn to_wide_value(self) -> Result<WideValue, VMError> {
        match self {
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
        }
    }

    // Downcasts to Contract type
    fn to_contract(self) -> Result<Contract<'tx>, VMError> {
        match self {
            Item::Contract(c) => Ok(c),
            _ => Err(VMError::TypeNotContract),
        }
    }
}

impl<'tx> Data<'tx> {
    /// Ensures the length of the data string
    pub fn ensure_length(self, len: usize) -> Result<Data<'tx>, VMError> {
        if self.bytes.len() != len {
            return Err(VMError::FormatError);
        }
        Ok(self)
    }

    /// Converts a bytestring to a 32-byte array
    pub fn to_u8x32(self) -> Result<[u8; 32], VMError> {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(self.ensure_length(32)?.bytes);
        Ok(buf)
    }

    /// Converts a bytestring to a compressed point
    pub fn to_point(self) -> Result<CompressedRistretto, VMError> {
        Ok(CompressedRistretto(self.to_u8x32()?))
    }

    /// Converts a bytestring to a canonical scalar
    pub fn to_scalar(self) -> Result<Scalar, VMError> {
        Scalar::from_canonical_bytes(self.to_u8x32()?).ok_or(VMError::FormatError)
    }
}

impl Value {
    /// Computes a flavor as defined by the `issue` instruction from a predicate.
    pub fn issue_flavor(predicate: &Predicate) -> Scalar {
        let mut t = Transcript::new(b"ZkVM.issue");
        t.commit_bytes(b"predicate", predicate.0.as_bytes());
        t.challenge_scalar(b"flavor")
    }
}

// Upcasting all types to Item

impl<'tx> From<Data<'tx>> for Item<'tx> {
    fn from(x: Data<'tx>) -> Self {
        Item::Data(x)
    }
}

impl<'tx> From<Value> for Item<'tx> {
    fn from(x: Value) -> Self {
        Item::Value(x)
    }
}

impl<'tx> From<WideValue> for Item<'tx> {
    fn from(x: WideValue) -> Self {
        Item::WideValue(x)
    }
}

impl<'tx> From<Contract<'tx>> for Item<'tx> {
    fn from(x: Contract<'tx>) -> Self {
        Item::Contract(x)
    }
}

impl<'tx> From<Variable> for Item<'tx> {
    fn from(x: Variable) -> Self {
        Item::Variable(x)
    }
}

impl<'tx> From<Expression> for Item<'tx> {
    fn from(x: Expression) -> Self {
        Item::Expression(x)
    }
}

impl<'tx> From<Constraint> for Item<'tx> {
    fn from(x: Constraint) -> Self {
        Item::Constraint(x)
    }
}

// Upcast a portable item to any item
impl<D, I> Into<I> for PortableItem<D>
where 
D: DataTrait, 
I: ItemTrait<DataType=D>,
{
    fn into(self) -> I {
        match self {
            PortableItem::Data(x) => Item::Data(x),
            PortableItem::Value(x) => Item::Value(x),
        }
    }
}
