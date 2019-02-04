//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use stdlib::Range;
use std::ops::Deref;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;

#[derive(Copy,Clone,Debug)]
pub struct SliceView<'a> {
    whole: &'a [u8],
    start: usize,
    end: usize,
}

impl<'a> SliceView<'a> {
    fn new(data: &'a [u8]) -> Self {
        SliceView{
            start: 0,
            end: data.len(),
            whole: data,
        }
    }

     fn len(&self) -> usize {
        self.end - self.start
    }

    // read_bytes returns a SliceView of the first num_bytes of self and advances
    // the internal range.
    fn read_bytes(&mut self, num_bytes: usize) -> Result<SliceView, VMError> {
        if num_bytes > self.len() {
            return Err(VMError::FormatError);
        }
        let prefix = SliceView{
            start: self.start,
            end: self.start+num_bytes,
            whole: self.whole,
        };
        self.start = self.start+num_bytes;
        Ok(prefix)
    }

    pub fn read_u8(&mut self) -> Result<u8, VMError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, VMError> {
        let bytes = self.read_bytes(4)?;
        let x = LittleEndian::read_u32(&bytes);
        Ok(x)
    }

    pub fn read_usize(&mut self) -> Result<usize, VMError> {
        let n = self.read_u32()?;
        Ok(n as usize)
    }

    pub fn read_u8x32(&mut self) -> Result<[u8; 32], VMError> {
        let mut buf = [0u8; 32];
        let bytes = self.read_bytes(32)?;
        buf[..].copy_from_slice(&bytes);
        Ok(buf)
    }

    pub fn read_point(&mut self) -> Result<CompressedRistretto, VMError> {
        let buf  = self.read_u8x32()?;
        Ok(CompressedRistretto(buf))
    }

    pub fn read_scalar(&mut self) -> Result<Scalar, VMError> {
        let buf = self.read_u8x32()?;
        Ok(Scalar::from_canonical_bytes(buf).ok_or(VMError::FormatError)?)
    }
}

impl<'a> Deref for SliceView<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.whole[self.start..self.end]
    }
}

// Writing API
// This currently writes into the Vec, but later can be changed to support Arenas to minimize allocations

// Writes a single byte
pub fn write_u8<'a>(x: u8, target: &mut Vec<u8>) {
    target.push(x);
}

// Writes a LE32-encoded integer
pub fn write_u32<'a>(x: u32, target: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, x);
    target.extend_from_slice(&buf);
}

/// Reads a 32-byte array and returns the subsequent slice
pub fn write_bytes(x: &[u8], target: &mut Vec<u8>) {
    target.extend_from_slice(&x);
}

/// Reads a compressed point
pub fn write_point(x: &CompressedRistretto, target: &mut Vec<u8>) {
    write_bytes(x.as_bytes(), target);
}

/// Reads a scalar
pub fn write_scalar(x: &Scalar, target: &mut Vec<u8>) {
    write_bytes(x.as_bytes(), target);
}
