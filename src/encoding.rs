//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use core::ops::Range;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;

pub struct SliceView<'a,T> {
    whole: &'a [T],
    range: Range<usize>
}

impl<'a, T> SliceView<'a,T> {
    // get returns the slice from the given range, advancing the
    // internal range
    fn get(mut self, offset: usize) -> Result<&'a [T], VMError> {
        let result = self.whole.get(self.range.start..self.range.start+offset).ok_or(VMError::FormatError);
        self.range.start = self.range.start+offset;
        result
    }
}

pub fn read_next_u8<'a>(slice: &mut SliceView<'a, u8>) -> Result<u8, VMError> {
        let bytes = slice.get(1)?;
        Ok(bytes[0])
    }

pub fn read_next_u32<'a>(slice: &mut SliceView<'a, u8>) -> Result<u32, VMError> {
    let bytes = slice.get(4)?;
    let x = LittleEndian::read_u32(bytes);
    Ok(x)
}

pub fn read_next_usize<'a>(slice: &mut SliceView<'a, u8>) -> Result<usize, VMError> {
    let n = read_next_u32(slice)?;
    Ok(n as usize)
}

pub fn read_next_u8x32<'a>(slice: &mut SliceView<'a, u8>) -> Result<[u8; 32], VMError> {
    let mut buf = [0u8; 32];
    let bytes = slice.get(32)?;
    buf[..].copy_from_slice(bytes);
    Ok(buf)
}

pub fn read_next_bytes<'a>(slice: &mut SliceView<'a, u8>, n: usize) -> Result<&'a [u8], VMError> {
    Ok(slice.get(n)?)
}

pub fn read_next_point<'a>(slice: &mut SliceView<'a, u8>) -> Result<CompressedRistretto, VMError> {
    let buf = read_next_u8x32(slice)?;
    Ok(CompressedRistretto(buf))
}

pub fn read_next_scalar<'a>(slice: &mut SliceView<'a, u8>) -> Result<Scalar, VMError> {
    let buf = read_next_u8x32(slice)?;
    Ok(Scalar::from_canonical_bytes(buf).ok_or(VMError::FormatError)?)
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
