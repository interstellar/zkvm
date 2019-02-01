use core::ops::Range;
use crate::signature::VerificationKey;
use bulletproofs::{PedersenGens,BulletproofGens};
use curve25519_dalek::ristretto::{CompressedRistretto};
use bulletproofs::r1cs;
use merlin::Transcript;

use crate::transcript::TranscriptProtocol;
use crate::point_ops::PointOp;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;
use crate::errors::VMError;

use crate::vm::{VM,VMInternal,Tx,VerifiedTx,State,VariableCommitment};

pub struct Verifier<'t, 'g> {
    tx: Tx,
    state: State<r1cs::Verifier<'t, 'g>>,
    signtx_keys: Vec<VerificationKey>,
    deferred_operations: Vec<PointOp>,
}

impl<'t, 'g> Verifier<'t, 'g> {

    /// Instantiate a verifying VM
    pub fn new(tx: Tx, bp_gens: &BulletproofGens) -> Self {
        
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(&bp_gens, &pc_gens, &mut r1cs_transcript);

        Verifier {
            tx,
            state: State::new(
                tx.version,
                tx.mintime,
                tx.maxtime,
                0..tx.program.len(),
                cs,
            ),
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
        }
    }

    pub fn verify_tx(self) -> Result<VerifiedTx, VMError> {

        let txid = self.run()?;
        let vmstate = self.state();

        // Verify the signatures over txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);
        let signtx_point_op = self.tx
            .signature
            .verify_aggregated(&mut signtx_transcript, &self.signtx_keys[..]);
        self.deferred_operations.push(signtx_point_op);

        // Verify all deferred crypto operations.
        PointOp::verify_batch(&self.deferred_operations[..])?;

        // Verify the R1CS proof
        vmstate.cs.verify(&self.tx.proof).map_err(|_| VMError::InvalidR1CSProof)?;

        Ok(VerifiedTx {
            version: self.tx.version,
            mintime: self.tx.mintime,
            maxtime: self.tx.maxtime,
            id: txid,
            log: vmstate.txlog,
        })
    }
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
