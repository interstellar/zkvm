use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

use super::errors::VMError;

/// Deferred point operation.
pub struct PointOp {
    /// Weight for the primary generator.
    /// None stands for zero.
    pub primary: Option<Scalar>,   // B

    /// Weight for the secondary generator.
    /// None stands for zero.
    pub secondary: Option<Scalar>, // B_blinding aka B2

    /// Weights for arbitrary points.
    pub arbitrary: Vec<(CompressedRistretto, Scalar)>
}

impl PointOp {
    /// Non-batched verification of an individual point operation.
    pub fn verify(&self) -> Result<(), VMError> {

        unimplemented!()
    }
}
