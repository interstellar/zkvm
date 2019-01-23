//! Core ZkVM stack types: data, variables, values, contracts etc.

use crate::errors::VMError;
use crate::predicate::Predicate;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

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
pub enum PortableItem<'tx> {
    Data(Data<'tx>),
    Value(Value),
}

#[derive(Copy, Clone, Debug)]
pub struct Data<'tx> {
    pub(crate) bytes: &'tx [u8],
}

#[derive(Debug)]
pub struct Contract<'tx> {
    pub(crate) payload: Vec<PortableItem<'tx>>,
    pub(crate) predicate: Predicate,
}

#[derive(Debug)]
pub struct Value {
    pub(crate) qty: Variable,
    pub(crate) flv: Variable,
}

#[derive(Debug)]
pub struct WideValue {
    // TBD
}

#[derive(Clone, Debug)]
pub struct Variable {
    pub(crate) index: usize,
}

#[derive(Clone, Debug)]
pub struct Expression {
    // TBD
}

#[derive(Clone, Debug)]
pub struct Constraint {
    // TBD
}

impl<'tx> Item<'tx> {
    // Downcasts to Data type
    pub fn to_data(self) -> Result<Data<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData),
        }
    }

    // Downcasts to Variable type
    pub fn to_variable(self) -> Result<Variable, VMError> {
        match self {
            Item::Variable(v) => Ok(v),
            _ => Err(VMError::TypeNotVariable),
        }
    }

    // Downcasts to Expression type (Variable is casted to Expression)
    pub fn to_expression(self) -> Result<Expression, VMError> {
        match self {
            Item::Variable(v) => Ok(v.into()),
            Item::Expression(expr) => Ok(expr),
            _ => Err(VMError::TypeNotVariable),
        }
    }

    // Downcasts to Value type
    pub fn to_value(self) -> Result<Value, VMError> {
        match self {
            Item::Value(v) => Ok(v),
            _ => Err(VMError::TypeNotValue),
        }
    }

    // Downcasts to WideValue type (Value is casted to WideValue)
    pub fn to_wide_value(self) -> Result<WideValue, VMError> {
        match self {
            Item::Value(v) => Ok(v.into()),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue),
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


// Upcasting Value to Wide Value

impl From<Value> for WideValue {
    fn from(_: Value) -> Self {
        WideValue{
            // TBD.
        }
    }
}

// Upcasting Variable to Expression

impl From<Variable> for Expression {
    fn from(x: Variable) -> Self {
        Expression {
            // TBD
        }
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
impl<'tx> From<PortableItem<'tx>> for Item<'tx> {
    fn from(portable: PortableItem<'tx>) -> Self {
        match portable {
            PortableItem::Data(x) => Item::Data(x),
            PortableItem::Value(x) => Item::Value(x),
        }
    }
}
