//! Core ZkVM stack types: data, variables, values, contracts etc.

use crate::predicate::Predicate;
use crate::errors::VMError;

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
    fn from(v: Value) -> Self {
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
            _ => Err(VMError::TypeNotCopyable)
        }
    }

    /// Copies an item if it's copyable.
    pub fn dup(&self) -> Result<CopyableItem<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(CopyableItem::Data(*x)),
            // TBD: variable, expression, constraint are also copyable
            _ => Err(VMError::TypeNotCopyable)
        }
    }

    pub fn to_data(self) -> Result<Data<'tx>, VMError> {
        match self {
            Item::Data(x) => Ok(x),
            _ => Err(VMError::TypeNotData)
        }
    }

    pub fn to_value(self) -> Result<Value, VMError> {
        match self {
            Item::Value(v) => Ok(v),
            _ => Err(VMError::TypeNotValue)
        }
    }

    pub fn to_wide_value(self) -> Result<WideValue, VMError> {
        match self {
            Item::Value(v) => Ok(v.into()),
            Item::WideValue(w) => Ok(w),
            _ => Err(VMError::TypeNotWideValue)
        }
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
