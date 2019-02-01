use core::ops::Range;
use crate::signature::VerificationKey;
use bulletproofs::{PedersenGens,BulletproofGens};
use curve25519_dalek::ristretto::{CompressedRistretto};
use bulletproofs::r1cs;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::transcript::TranscriptProtocol;
use crate::point_ops::PointOp;
use crate::txlog::{Entry, TxID, UTXO};
use crate::types::*;
use crate::errors::VMError;
use crate::encoding;

use crate::vm::{VM,VMInternal,Tx,VerifiedTx,State,VariableCommitment};
use crate::predicate::Predicate;

pub struct Verifier<'t, 'g> {
    tx: Tx,
    state: State<r1cs::Verifier<'t, 'g>>,
    signtx_keys: Vec<VerificationKey>,
    deferred_operations: Vec<PointOp>,
}

impl<'t, 'g> Verifier<'t, 'g> {

    /// Instantiate a verifying VM
    pub fn new(tx: Tx, bp_gens: &'g BulletproofGens) -> Self {
        
        let mut r1cs_transcript = Transcript::new(b"ZkVM.r1cs");
        let pc_gens = PedersenGens::default();
        let cs = r1cs::Verifier::new(bp_gens, &pc_gens, &mut r1cs_transcript);

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

    fn decode_input(&mut self, input: Data) -> Result<(Contract, TxID, UTXO), VMError> {
//        Input  =  PreviousTxID || PreviousOutput
        // PreviousTxID  =  <32 bytes>

        let input_bytes = match input {
            Data::Opaque(_) => input.to_u8x32(&self.tx.program)?,
            // Data::Opaque(range) => self.tx.program.get(range).ok_or(VMError::FormatError)?,
            Data::Witness(_) => return Err(VMError::DataNotOpaque)
        };
        let (txid, output) = encoding::read_u8x32(&input_bytes)?;
        let txid = TxID(txid);
        let contract = self.decode_output(output)?;
        let utxo = UTXO::from_output(output, &txid);
        Ok((contract, txid, utxo))
    }

    /// Parses the output and returns an instantiated contract.
    fn decode_output(&mut self, output: &[u8]) -> Result<(Contract), VMError> {
        //    Output  =  Predicate  ||  LE32(k)  ||  Item[0]  || ... ||  Item[k-1]
        // Predicate  =  <32 bytes>
        //      Item  =  enum { Data, Value }
        //      Data  =  0x00  ||  LE32(len)  ||  <bytes>
        //     Value  =  0x01  ||  <32 bytes> ||  <32 bytes>

        let (predicate, payload) = encoding::read_point(output)?;
        let predicate = Predicate(predicate);

        let (k, mut items) = encoding::read_usize(payload)?;

        // sanity check: avoid allocating unreasonably more memory
        // just because an untrusted length prefix says so.
        if k > items.len() {
            return Err(VMError::FormatError);
        }

        // TODO: replace the slices themselves with a tracking of the indices.

        let mut payload: Vec<PortableItem> = Vec::with_capacity(k);
        for _ in 0..k {
            let (item_type, rest) = encoding::read_u8(items)?;
            let item = match item_type {
                DATA_TYPE => {
                    let (len, rest) = encoding::read_usize(rest)?;
                    let (bytes, rest) = encoding::read_bytes(len, rest)?;
                    items = rest;
                    PortableItem::Data(Data { bytes })
                }
                VALUE_TYPE => {
                    let (qty, rest) = encoding::read_point(rest)?;
                    let (flv, rest) = encoding::read_point(rest)?;

                    let qty = self.make_variable(qty);
                    let flv = self.make_variable(flv);

                    items = rest;
                    PortableItem::Value(Value { qty, flv })
                }
                _ => return Err(VMError::FormatError),
            };
            payload.push(item);
        }

        Ok(Contract { predicate, payload })
    }
}


impl<'t, 'g> VM for Verifier<'t, 'g> {
    type CS = r1cs::Verifier<'t, 'g>;

    fn state(&mut self) -> &mut State<Self::CS> {
        &mut self.state
    }

    fn issue(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let predicate = Predicate(state.pop_item()?.to_data()?.to_point(&self.tx.program)?);
        let flv = state.pop_item()?.to_variable()?;
        let qty = state.pop_item()?.to_variable()?;

        let (flv_point, _) = self.attach_variable(flv);
        let (qty_point, _) = self.attach_variable(qty);

        let value = Value { qty, flv };

        let flv_scalar = Value::issue_flavor(&predicate);
        // flv_point == flavor·B    ->   0 == -flv_point + flv_scalar·B
        self.deferred_operations.push(PointOp {
            primary: Some(flv_scalar),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), flv_point)],
        });

        let qty_expr = self.variable_to_expression(qty);
        self.add_range_proof(64, qty_expr)?;

        state.txlog.push(Entry::Issue(qty_point, flv_point));

        let contract = Contract {
            predicate,
            payload: vec![PortableItem::Value(value)],
        };

        state.push_item(contract);
        Ok(())
    }

    /// _input_ **input** → _contract_
    fn input(&mut self) -> Result<(), VMError> {
        let state = self.state();
        let serialized_input = state.pop_item()?.to_data()?;
        let (contract, _, utxo) = self.decode_input(serialized_input.bytes)?;
        state.push_item(contract);
        state.txlog.push(Entry::Input(utxo));
        state.unique = true;
        Ok(())
    }

    fn attach_variable(&mut self, var: Variable) -> (CompressedRistretto, r1cs::Variable) {
        let state = self.state();
        let variable_commitment = state.variable_commitments[var.index];
        if let Some(var) = variable_commitment.variable {
            (variable_commitment.commitment, var)
        } else {
            let r1cs_var = state.cs.commit(variable_commitment.commitment);
            state.variable_commitments[var.index].variable = Some(r1cs_var);
            (variable_commitment.commitment, r1cs_var)
        }
    }

    // // Unimplemented functions
    // fn get_variable_commitment(&self, var: Variable) -> CompressedRistretto {
    //     let state = self.state();
    //     // This subscript never fails because the variable is created only via `make_variable`.
    //     match state.variable_commitments[var.index] {
    //         VariableCommitment::Detached(p) => p,
    //         VariableCommitment::Attached(p, _) => p,
    //     }
    // }
}
