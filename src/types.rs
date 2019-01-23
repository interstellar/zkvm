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

#[derive(Clone, Debug)]
pub enum CopyableItem<'tx> {
    Data(Data<'tx>),
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
    // TBD
}

#[derive(Debug)]
pub struct WideValue {
    // TBD
}

impl From<Value> for WideValue {
    fn from(_: Value) -> Self {
        WideValue{
            // TBD.
        }
    }
}

#[derive(Clone, Debug)]
pub struct Variable {
    // TBD
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
    /// Downcasts an item to a CopyableItem if possible.
    pub fn to_copyable(self) -> Result<CopyableItem<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(CopyableItem::Data(x)),
            // TBD: variable, expression, constraint are also copyable
            _ => Err(VMError::TypeNotCopyable),
        }
    }

    /// Copies an item if it's copyable.
    pub fn dup(&self) -> Result<CopyableItem<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(CopyableItem::Data(*x)),
            // TBD: variable, expression, constraint are also copyable
            _ => Err(VMError::TypeNotCopyable),
        }
    }

    pub fn to_data(self) -> Result<Data<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData),
        }
    }

    pub fn to_value(self) -> Result<Value, VMError> {
        match self {
            Item::Value(v) => Ok(v),
            _ => Err(VMError::TypeNotValue),
        }
    }

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

// Upcast a copyable item to any item
impl<'tx> From<CopyableItem<'tx>> for Item<'tx> {
    fn from(copyable: CopyableItem<'tx>) -> Self {
        match copyable {
            CopyableItem::Data(x) => Item::Data(x),
            CopyableItem::Variable(x) => Item::Variable(x),
            CopyableItem::Expression(x) => Item::Expression(x),
            CopyableItem::Constraint(x) => Item::Constraint(x),
        }
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
