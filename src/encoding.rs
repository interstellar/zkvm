//! Encoding utils for ZkVM
//! All methods err using VMError::FormatError for convenience.

use byteorder::{ByteOrder, LittleEndian};
use core::ops::Range;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::errors::VMError;

#[derive(Copy,Clone,Debug)]
pub struct SliceView<'a> {
    whole: &'a [u8],
    index: usize,
}

impl<'a> SliceView<'a> {
    // next advances the internal range and returns the 
    // updated SliceView
    fn next(self, offset: usize) -> Result<Self, VMError> {
        self.index = self.index+offset;
        Ok(self)
    }

    fn slice(self, offset: usize) -> Result<&'a [u8], VMError> {
        self.whole.get(self.index..self.index+offset).ok_or(VMError::FormatError)
    }
}

pub fn read_next_u8<'a>(slice: SliceView<'a>) -> Result<(u8, SliceView<'a>), VMError> {
        let bytes = slice.slice(1)?;
        Ok((bytes[0], slice.next(1)?))
    }

pub fn read_next_u32<'a>(slice: SliceView<'a>) -> Result<(u32, SliceView<'a>), VMError> {
    let bytes = slice.slice(4)?;
    let x = LittleEndian::read_u32(bytes);
    Ok((x, slice.next(4)?))
}

pub fn read_next_usize<'a>(slice: SliceView<'a>) -> Result<(usize, SliceView<'a>), VMError> {
    let (n, next_slice) = read_next_u32(slice)?;
    Ok((n as usize, next_slice))
}

pub fn read_next_u8x32<'a>(slice: SliceView<'a>) -> Result<([u8; 32], SliceView<'a>), VMError> {
    let mut buf = [0u8; 32];
    let bytes = slice.slice(32)?;
    buf[..].copy_from_slice(bytes);
    Ok((buf, slice.next(32)?))
}

pub fn read_next_bytes<'a>(slice: SliceView<'a>, n: usize) -> Result<(&'a [u8], SliceView<'a>), VMError> {
    let bytes = slice.slice(n)?;
    Ok((bytes, slice.next(n)?))
}

pub fn read_next_point<'a>(slice: SliceView<'a>) -> Result<(CompressedRistretto, SliceView<'a>), VMError> {
    let (buf, next_slice) = read_next_u8x32(slice)?;
    Ok((CompressedRistretto(buf), next_slice))
}

pub fn read_next_scalar<'a>(slice: SliceView<'a>) -> Result<(Scalar, SliceView<'a>), VMError> {
    let (buf, next_slice) = read_next_u8x32(slice)?;
    Ok((Scalar::from_canonical_bytes(buf).ok_or(VMError::FormatError)?, next_slice))
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
