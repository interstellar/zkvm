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

impl<'tx, 'transcript, 'gens> vm::VM for Verifier<'tx, 'transcript, 'gens> {
    // Unimplemented functions
    fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
        let state = self.state();
        // This subscript never fails because the variable is created only via `make_variable`.
        match state.variable_commitments[var.index] {
            vm::VariableCommitment::Detached(p) => p,
            vm::VariableCommitment::Attached(p, _) => p,
        }
    }
}
