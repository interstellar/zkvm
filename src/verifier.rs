use crate::signature::VerificationKey;
use bulletproofs::r1cs;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use crate::encoding::*;
use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::signature::*;
use crate::types::*;

use crate::vm::{Delegate, RunTrait, Tx, VerifiedTx, VM};

pub struct Verifier {
    signtx_keys: Vec<VerificationKey>,
    deferred_operations: Vec<PointOp>,
}

pub struct Run {
    program: Vec<u8>,
    offset: usize,
}

impl<'a, 'b> Delegate<r1cs::Verifier<'a, 'b>> for Verifier {
    type RunType = Run;

    fn commit_variable(
        &mut self,
        cs: &mut r1cs::Verifier,
        com: &Commitment,
    ) -> (CompressedRistretto, r1cs::Variable) {
        let point = com.to_point();
        let var = cs.commit(point);
        (point, var)
    }

    fn verify_point_op<F>(&mut self, point_op_fn: F)
    where
        F: FnOnce() -> PointOp,
    {
        self.deferred_operations.push(point_op_fn());
    }

    fn sign_tx(&mut self, key: Key) -> Result<(), VMError> {
        match key {
            Key::Verification(k) => Ok(self.signtx_keys.push(k)),
            Key::Signing(_) => Err(VMError::FormatError),
        }
    }
}

impl Verifier {
    pub fn verify_tx<'g>(tx: Tx, bp_gens: &'g BulletproofGens) -> Result<VerifiedTx, VMError> {
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(bp_gens, &pc_gens, &mut r1cs_transcript);

        let verifier = Verifier {
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
        };

        let vm = VM::new(
            tx.version,
            tx.mintime,
            tx.maxtime,
            Run::new(tx.program),
            verifier,
            cs,
        );

        let (txid, mut verifier, txlog, cs) = vm.run()?;

        // Verify the signatures over txid
        let mut signtx_transcript = Transcript::new(b"ZkVM.signtx");
        signtx_transcript.commit_bytes(b"txid", &txid.0);

        let signtx_point_op = tx
            .signature
            .verify_aggregated(&mut signtx_transcript, &verifier.signtx_keys);
        verifier.deferred_operations.push(signtx_point_op);
        // Verify all deferred crypto operations.
        PointOp::verify_batch(&verifier.deferred_operations[..])?;

        // Verify the R1CS proof
        cs.verify(&tx.proof)
            .map_err(|_| VMError::InvalidR1CSProof)?;

        Ok(VerifiedTx {
            version: tx.version,
            mintime: tx.mintime,
            maxtime: tx.maxtime,
            id: txid,
            log: txlog,
        })
    }
}

// impl<'t, 'g> VM for Verifier<'t, 'g> {
//     type CS = r1cs::Verifier<'t, 'g>;

//     // // Unimplemented functions
//     // fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
//     //     let state = self.state();
//     //     // This subscript never fails because the variable is created only via `make_variable`.
//     //     match state.variable_commitments[var.index] {
//     //         VariableCommitment::Detached(p) => p,
//     //         VariableCommitment::Attached(p, _) => p,
//     //     }
//     // }
// }

impl Run {
    fn new(program: Vec<u8>) -> Self {
        Run { program, offset: 0 }
    }
}

impl RunTrait for Run {
    fn next_instruction(&mut self) -> Result<Option<Instruction>, VMError> {
        let mut program = Subslice::new_with_range(&self.program, self.offset..self.program.len())?;

        // Reached the end of the program - no more instructions to execute.
        if program.len() == 0 {
            return Ok(None);
        }
        let instr = Instruction::parse(&mut program)?;
        self.offset = program.range().start;
        Ok(Some(instr))
    }
}
