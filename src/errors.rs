//! Errors related to proving and verifying proofs.

/// Represents an error in proof creation, verification, or parsing.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum VMError {
    /// This error occurs when an individual point operation failed.
    #[fail(display = "Point operation failed.")]
    PointOperationFailed,

    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Point decoding failed.")]
    InvalidPoint,

    /// This error occurs when VM instruction is malformed
    #[fail(display = "Instruction is malformed.")]
    MalformedInstruction,

    /// This error occurs when an instruction requires a copyable type, but a linear type is encountered.
    #[fail(display = "Item is not a copyable type.")]
    TypeNotCopyable,

    /// This error occurs when an instruction requires a copyable type, but a linear type is encountered.
    #[fail(display = "Item is not a data string.")]
    TypeNotData,

    /// This error occurs when VM does not have enough items on the stack
    #[fail(display = "Stack does not have enough items")]
    StackUnderflow,
}
