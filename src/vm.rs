use bulletproofs::r1cs::R1CSProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::predicate::Predicate;
use crate::signature::Signature;

pub const CURRENT_TX_VERSION: u64 = 1;

/// The instance of ZkVM that validates a transaction.
pub struct ZkVM<'tx> {
    version: u64,
    mintime: u64,
    maxtime: u64,
    program: &'tx [u8],
    tx_signature: Signature,
    cs_proof: R1CSProof,

    extension: bool,
    unique: bool,
    stack: Vec<Item<'tx>>,

    current_program: Run<'tx>,
    program_stack: Vec<Run<'tx>>,
    txlog: Vec<[u8; 32]>,
    signtx_keys: Vec<CompressedRistretto>,
    deferred_operations: Vec<PointOp>,
    variables: Vec<VariableCommitment>,
    // cs: (need to figure out who owns transcript and CS)
}

impl<'tx> ZkVM<'tx> {
    /// Creates a new instance of ZkVM with the appropriate parameters
    pub fn new(
        version: u64,
        mintime: u64,
        maxtime: u64,
        program: &'tx [u8],
        tx_signature: Signature,
        cs_proof: R1CSProof,
    ) -> Self {
        Self {
            version,
            mintime,
            maxtime,
            program,
            tx_signature,
            cs_proof,

            extension: version > CURRENT_TX_VERSION,
            unique: false,
            stack: Vec::new(),

            current_program: Run {
                program: program,
                offset: 0,
            },
            program_stack: Vec::new(),
            txlog: Vec::new(),
            signtx_keys: Vec::new(),
            deferred_operations: Vec::new(),
            variables: Vec::new(),
        }
    }

    /// Executes the transaction and returns the txid upon success.
    /// TBD: add hooks to get proof-of-inclusion for various txlog items
    pub fn verify(self) -> Result<[u8; 32], VMError> {
        unimplemented!()
    }
}

enum Item<'tx> {
    Data(Data<'tx>),
    Contract(Contract<'tx>),
    Value(Value<'tx>),
}

struct Data<'tx> {
    bytes: &'tx [u8],
}

struct Contract<'tx> {
    payload: Vec<Item<'tx>>,
    predicate: Predicate,
}

struct Value<'tx> {
    payload: Vec<Item<'tx>>,
    predicate: Predicate,
}

struct Run<'tx> {
    program: &'tx [u8],
    offset: usize,
}

enum VariableCommitment {
    /// Variable is not attached to the CS yet,
    /// so its commitment is replaceable via `reblind`.
    Detached(CompressedRistretto),

    /// Variable is attached to the CS yet and has index in CS,
    /// so its commitment is no longer replaceable via `reblind`.
    Attached(CompressedRistretto, usize),
}
