use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};

use super::errors::VMError;

/// Deferred point operation.
pub struct PointOp {
    /// Weight for the primary generator.
    /// None stands for zero.
    pub primary: Option<Scalar>, // B

    /// Weight for the secondary generator.
    /// None stands for zero.
    pub secondary: Option<Scalar>, // B_blinding aka B2

    /// Weights for arbitrary points.
    pub arbitrary: Vec<(Scalar, CompressedRistretto)>,
}

impl PointOp {
    /// Non-batched verification of an individual point operation.
    pub fn verify(self, gens: &PedersenGens) -> Result<(), VMError> {
        let (mut weights, points): (Vec<_>, Vec<_>) = self.arbitrary.into_iter().unzip();
        let mut points: Vec<_> = points.into_iter().map(|p| p.decompress()).collect();

        if let Some(w) = self.primary {
            weights.push(w);
            points.push(Some(gens.B));
        }
        if let Some(w) = self.secondary {
            weights.push(w);
            points.push(Some(gens.B_blinding));
        }

        let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or_else(|| VMError::PointOperationFailed)?;

        if !check.is_identity() {
            return Err(VMError::PointOperationFailed);
        }

        Ok(())
    }
}
