use bulletproofs::r1cs;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;
use crate::ops::Instruction;
use crate::point_ops::PointOp;
use crate::types::*;
use crate::vm::{Delegate, RunTrait};

pub struct Prover {
    signtx_keys: Vec<Scalar>,
}

pub struct RunProver {}

impl<'a, 'b> Delegate<r1cs::Prover<'a, 'b>> for Prover {
    type RunType = RunProver;

    fn commit_variable(
        &mut self,
        cs: &mut r1cs::Prover,
        com: &Commitment,
    ) -> (CompressedRistretto, r1cs::Variable) {
        unimplemented!()
    }

    fn verify_point_op<F>(&mut self, point_op_fn: F)
    where
        F: FnOnce() -> PointOp,
    {
        return;
    }

    fn process_tx_signature(&mut self, pred: Predicate) -> Result<(), VMError> {
        match pred {
            Predicate::Opaque(_) => Err(VMError::WitnessMissing),
            Predicate::Witness(w) => match *w {
                PredicateWitness::Key(s) => Ok(self.signtx_keys.push(s)),
                _ => Err(VMError::TypeNotKeyValue),
            },
        }
    }
}

impl RunTrait for RunProver {
    fn next_instruction(&mut self) -> Result<Option<Instruction>, VMError> {
        unimplemented!()
    }
}
