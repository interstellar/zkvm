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
}
