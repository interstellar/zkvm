//! Transaction data structures and encoding
//! - txid
//! - utxo id
//! - inputs
//! - outputs

use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::r1cs::R1CSProof;
use merlin::Transcript;

use crate::signature::Signature;
use crate::errors::VMError;
use crate::types::{Contract, Data, Value, PortableItem};
use crate::predicate::Predicate;
use crate::encoding;

/// Current tx version determines which extension opcodes are treated as noops (see VM.extension flag).
pub const CURRENT_VERSION: u64 = 1;

/// Prefix for the data type in the Output Structure
pub const DATA_TYPE: u8 = 0x00;

/// Prefix for the value type in the Output Structure
pub const VALUE_TYPE: u8 = 0x01;

/// Instance of a transaction that contains all necessary data to validate it.
pub struct Tx {
    /// Version of the transaction
    pub version: u64,

    /// Timestamp before which tx is invalid (sec)
    pub mintime: u64,

    /// Timestamp after which tx is invalid (sec)
    pub maxtime: u64,

    /// Program representing the transaction
    pub program: Vec<u8>,

    /// Aggregated signature of the txid
    pub signature: Signature,

    /// Constraint system proof for all the constraints
    pub proof: R1CSProof,
}

/// Represents a verified transaction: a txid and a list of state updates.
pub struct VerifiedTx {
    /// Transaction ID
    pub txid: [u8; 32],
    // TBD: list of txlog inputs, outputs and nonces to be inserted/deleted in the blockchain state.
}

/// Entry in a transaction log
pub enum LogEntry<'tx> {
    Issue(CompressedRistretto, CompressedRistretto),
    Retire(CompressedRistretto, CompressedRistretto),
    Input(UTXO),
    Nonce(Predicate, u64),
    Output(Contract<'tx>),
    Data(Data<'tx>),
    Import, // TBD: parameters
    Export // TBD: parameters
}


/// Transaction ID is a unique 32-byte identifier of a transaction
pub struct TxID([u8;32]);

/// UTXO is a unique 32-byte identifier of a transaction output
pub struct UTXO([u8;32]);

/// Parses the input and returns the instantiated contract, txid and UTXO identifier
pub fn parse_input<'tx>(input: &'tx [u8]) -> Result<(Contract<'tx>, TxID, UTXO), VMError> {
    // !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!!  
    // TBD: change the spec - we are moving txid in the front
    // !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 

    //        Input  =  PreviousTxID || PreviousOutput
    // PreviousTxID  =  <32 bytes>
    if input.len() < 32 {
        return Err(VMError::FormatError);
    }

    let (txid, output) = encoding::read_u8x32(input)?;
    let txid = TxID(txid);
    let contract = parse_output(output)?;
    let utxo = UTXO::from_output(output, &txid);
    Ok((
        contract,
        txid,
        utxo
    ))
}

pub fn parse_output<'tx>(output: &'tx [u8]) -> Result<(Contract<'tx>), VMError> {
   
    // !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 
    // TBD: change the spec - we are moving predicate up front
    // !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! !!! 

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
    
    let buf: Vec<PortableItem<'tx>> = Vec::with_capacity(k);
    for _ in 0..k {
        let (item_type, rest) = encoding::read_u8(items)?;
        let item = match item_type {
            DATA_TYPE => {
                let (len, rest) = encoding::read_usize(rest)?;
                let (bytes, rest) = encoding::read_bytes(len, rest)?;
                PortableItem::Data(Data{bytes})
            },
            VALUE_TYPE => {
                let (qty, rest) = encoding::read_point(rest)?;
                let (flv, rest) = encoding::read_point(rest)?;

                // XXX: we want value to have a pointer to the commitment,
                // so it can be replaced. This means, the commitment must be stored inside VM,
                // not inside the value. OR be lazily moved into VM when a qty/flavor variable is queried.

                PortableItem::Value(Value{})
            },
            _ => return Err(VMError::FormatError)
        };

        items = rest;

        buf.push(item);
    }
    
    unimplemented!()
}

impl<'tx> Contract<'tx> {
    /// Encodes the contract into an output structure
    pub fn to_output(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.output_size());
        encoding::write_point(&self.predicate.0, &mut output);
        encoding::write_u32(self.payload.len() as u32, &mut output);

        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => {
                    encoding::write_u8(DATA_TYPE, &mut output);
                    encoding::write_u32(d.bytes.len() as u32, &mut output);
                    encoding::write_bytes(d.bytes, &mut output);
                },
                PortableItem::Value(v) => {
                    encoding::write_u8(VALUE_TYPE, &mut output);

                    // XXX: we need to get the commitments from the VM
                    // TBD: encoding::write_point(&qty, &mut output);
                    // TBD: encoding::write_point(&flavor, &mut output);
                },
            }
        }

        output
    }

    fn output_size(&self) -> usize {
        let mut size = 32 + 4;
        for item in self.payload.iter() {
            match item {
                PortableItem::Data(d) => { size += 1 + 4 + d.bytes.len() },
                PortableItem::Value(d) => { size += 1 + 64 },
            }
        }
        size
    }
}

impl UTXO {
    /// Computes UTXO identifier from an output and transaction id.
    pub fn from_output(output: &[u8], txid: &TxID) -> Self {
        let t = Transcript::new(b"ZkVM.utxo");
        t.commit_bytes(b"txid", &txid.0);
        t.commit_bytes(b"output", &output);
        let mut utxo = UTXO([0u8;32]);
        t.challenge_bytes(b"id", &mut utxo.0);
        utxo
    }
}

