//! Defines the VerificationKey type used to verify Schnorr signatures.

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct VerificationKey(pub CompressedRistretto);

impl VerificationKey {

    // Constructs a VerificationKey from the private key.
    pub fn from_secret(privkey: &Scalar) -> Self {
        let gens = PedersenGens::default();
        VerificationKey((privkey * gens.B).compress())
    }
}
