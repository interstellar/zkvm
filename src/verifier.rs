use curve25519_dalek::ristretto::{CompressedRistretto};
use bulletproofs::r1cs;

use crate::point_ops::PointOp;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;

use crate::signature::VerificationKey;
use crate::vm;

pub struct Verifier<'tx, 'transcript, 'gens> {
    state: vm::State<
    	Item<'tx>, &'tx [u8],
    	VerificationKey,
    	CompressedRistretto,
    	r1cs::Verifier<'transcript, 'gens>
    >,
    deferred_operations: Vec<PointOp>,
}
