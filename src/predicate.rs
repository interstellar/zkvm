//! Implementation of a predicate tree.
//! Inspired by Taproot by Greg Maxwell and G'root by Anthony Towns.
//! Operations:
//! - disjunction: P = L + f(L,R)*B
//! - program_commitment: P = h(prog)*B2

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::PedersenGens;
use merlin::Transcript;
use crate::transcript::TranscriptProtocol;
use crate::point_ops::PointOp;
use crate::errors::VMError;

/// Predicate is represented by a compressed Ristretto point.
pub struct Predicate(CompressedRistretto);

impl Predicate {

    pub fn transcript() -> Transcript {
        Transcript::new(b"ZkVM.predicate")
    }

    /// Computes a disjunction of two predicates.
    pub fn or(&self, right: &Predicate, gens: &PedersenGens) -> Result<Predicate, VMError> {
        let mut t = Predicate::transcript();
        t.commit_point(b"L", &self.0);
        t.commit_point(b"R", &right.0);
        let f = t.challenge_scalar(b"f");
        let l = self.0.decompress().ok_or(VMError::InvalidPoint)?;
        Ok(Predicate((l + f * gens.B).compress()))
    }

    /// Verifies whether the current predicate is a disjunction of two others.
    /// Returns a `PointOp` instance that can be verified in a batch with other operations.
    /// Transcript `t` must be the cloned `Predicate::transcript()`. It is provided explicitly
    /// in order to reuse the precomputed instance.
    pub fn prove_or(&self, left: &Predicate, right: &Predicate, mut t: Transcript) -> PointOp {
        t.commit_point(b"L", &left.0);
        t.commit_point(b"R", &right.0);
        let f = t.challenge_scalar(b"f");

        // P == L + f*B   ->   0 == -P + L + f*B
        PointOp {
            primary: Some(f),
            secondary: None,
            arbitrary: vec![(self.0, -Scalar::one()), (left.0, Scalar::one())]
        }
    }
}
