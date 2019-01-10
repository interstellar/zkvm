//! Implementation of a Schnorr signature protocol.
//! 1. Prover and verifier obtain a [transcript](#transcript) `T` defined
//!    by the context in which the signature is used (see [`signtx`](#signtx),
//!    [`delegate`](#delegate)). The transcript is assumed to be already bound to the _message_
//!    and the [verification key](#verification-key) `P`.
//! 2. Prover creates a _secret nonce_: a randomly sampled [scalar](#scalar-type) `r`.
//! 3. Prover commits to nonce:
//!     ```text
//!     R = r·B
//!     ```
//! 4. Prover sends `R` to the verifier.
//! 5. Prover and verifier write the nonce commitment `R` to the transcript:
//!     ```text
//!     T.commit("R", R)
//!     ```
//! 6. Prover and verifier compute a Fiat-Shamir challenge scalar `e` using the transcript:
//!     ```text
//!     e = T.challenge_scalar("e")
//!     ```
//! 7. Prover blinds the secret `dlog(P)` using the nonce and the challenge:
//!     ```text
//!     s = r + e·dlog(P)
//!     ```
//! 8. Prover sends `s` to the verifier.
//! 9. Verifier checks the relation:
//!     ```text
//!     s·B == R + e·P
//!     ```

#![allow(non_snake_case)]
use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::transcript::TranscriptProtocol;
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[derive(Copy, Clone, Debug)]
pub struct Signature {
    R: CompressedRistretto,
    s: Scalar,
}

impl Signature {
    
}

// Serialization
impl Signature {
    /// Encodes the signature as a 64-byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.R.as_bytes());
        buf[32..].copy_from_slice(self.s.as_bytes());
        buf
    }
}
