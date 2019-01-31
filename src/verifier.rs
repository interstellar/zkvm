use bulletproofs::r1cs;
use bulletproofs::r1cs::R1CSProof;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use spacesuit;
use std::iter::FromIterator;

use crate::encoding;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::*;
use crate::transcript::TranscriptProtocol;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;

use crate::signature::VerificationKey;
use crate::vm;


pub struct Verifier<'tx, 'transcript, 'gens> {
    state: vm::State<Item<'tx>, &'tx [u8], VerificationKey, vm::VariableCommitment, r1cs::Verifier>,
    deferred_operations: Vec<PointOp>,
}
