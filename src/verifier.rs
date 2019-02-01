use curve25519_dalek::ristretto::{CompressedRistretto};
use bulletproofs::r1cs;

use crate::point_ops::PointOp;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;

use crate::vm::{VM,State,VariableCommitment};

pub struct Verifier<'t, 'g> {
    txprogram: Vec<u8>,
    state: State<r1cs::Verifier<'t, 'g>>,
    deferred_operations: Vec<PointOp>,
}

impl<'t, 'g> VM for Verifier<'t, 'g> {
    type CS = r1cs::Verifier<'t, 'g>;


    // Unimplemented functions
    fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
        let state = self.state();
        // This subscript never fails because the variable is created only via `make_variable`.
        match state.variable_commitments[var.index] {
            VariableCommitment::Detached(p) => p,
            VariableCommitment::Attached(p, _) => p,
        }
    }
}
