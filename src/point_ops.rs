use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

/// Deferred point operation.
pub struct PointOp {
	primary: Scalar,   // B
	secondary: Scalar, // B_blinding aka B2
	random: Vec<(CompressedRistretto, Scalar)>
}
