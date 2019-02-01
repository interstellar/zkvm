use core::ops::Range;
use byteorder::{ByteOrder, LittleEndian};
use core::mem;

use crate::types::Data;
use crate::errors::VMError;

#[derive(Debug)]
pub enum Instruction {
    Push(Data), // size of the string
    Drop,
    Dup(usize),  // index of the item
    Roll(usize), // index of the item
    Const,
    Var,
    Alloc,
    Mintime,
    Maxtime,
    Neg,
    Add,
    Mul,
    Eq,
    Range(u8), // bitwidth (1..64)
    And,
    Or,
    Verify,
    Blind,
    Reblind,
    Unblind,
    Issue,
    Borrow,
    Retire,
    Qty,
    Flavor,
    Cloak(usize, usize), // M inputs, N outputs
    Import,
    Export,
    Input,
    Output(usize),   // payload count
    Contract(usize), // payload count
    Nonce,
    Log,
    Signtx,
    Call,
    Left,
    Right,
    Delegate,
    Ext(u8),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Push = 0x00,
    Drop = 0x01,
    Dup = 0x02,
    Roll = 0x03,
    Const = 0x04,
    Var = 0x05,
    Alloc = 0x06,
    Mintime = 0x07,
    Maxtime = 0x08,
    Neg = 0x09,
    Add = 0x0a,
    Mul = 0x0b,
    Eq = 0x0c,
    Range = 0x0d,
    And = 0x0e,
    Or = 0x0f,
    Verify = 0x10,
    Blind = 0x11,
    Reblind = 0x12,
    Unblind = 0x13,
    Issue = 0x14,
    Borrow = 0x15,
    Retire = 0x16,
    Qty = 0x17,
    Flavor = 0x18,
    Cloak = 0x19,
    Import = 0x1a,
    Export = 0x1b,
    Input = 0x1c,
    Output = 0x1d,
    Contract = 0x1e,
    Nonce = 0x1f,
    Log = 0x20,
    Signtx = 0x21,
    Call = 0x22,
    Left = 0x23,
    Right = 0x24,
    Delegate = MAX_OPCODE,
}

const MAX_OPCODE: u8 = 0x25;

impl Opcode {
    pub fn to_u8(self) -> u8 {
        unsafe { mem::transmute(self) }
    }

    pub fn from_u8(code: u8) -> Option<Opcode> {
        if code > MAX_OPCODE {
            None
        } else {
            unsafe { mem::transmute(code) }
        }
    }
}

impl Instruction {
    /// Returns a parsed instruction with a size that it occupies in the program string.
    /// E.g. a push instruction with 5-byte string occupies 1+4+5=10 bytes
    /// (4 for the LE32 length prefix).
    ///
    /// Return `VMError::FormatError` if there is not enough bytes to parse an instruction.
    pub fn parse(txprogram: &[u8], range: Range<usize>) -> Result<(Self, usize), VMError> {
        // nothing to parse from an empty slice
        if range.len() == 0 {
            return Err(VMError::FormatError);
        }

        // TBD: .get is a nightly-only :-(
        let prog = txprogram.get(range).ok_or(VMError::FormatError)?;
        let byte = prog[0];
        let immdata = &prog[1..];

        // Interpret the opcode. Unknown opcodes are extension opcodes.
        let opcode = match Opcode::from_u8(byte) {
            None => {
                return Ok((Instruction::Ext(byte), 1));
            }
            Some(op) => op,
        };

        match opcode {
            Opcode::Push => {
                if immdata.len() < 4 {
                    return Err(VMError::FormatError);
                }
                let strlen = LittleEndian::read_u32(immdata) as usize;
                let data_range = 4..4+strlen;
                let global_range = Range {
                    start: range.start + data_range.start,
                    end: range.start + data_range.end
                };
                Ok((Instruction::Push(Data::Opaque(global_range)), 1 + 4 + strlen))
            }
            Opcode::Drop => Ok((Instruction::Drop, 1)),
            Opcode::Dup => {
                if immdata.len() < 4 {
                    return Err(VMError::FormatError);
                }
                let idx = LittleEndian::read_u32(immdata) as usize;
                Ok((Instruction::Dup(idx), 1 + 4))
            }
            Opcode::Roll => {
                if immdata.len() < 4 {
                    return Err(VMError::FormatError);
                }
                let idx = LittleEndian::read_u32(immdata) as usize;
                Ok((Instruction::Roll(idx), 1 + 4))
            }
            Opcode::Const => Ok((Instruction::Const, 1)),
            Opcode::Var => Ok((Instruction::Var, 1)),
            Opcode::Alloc => Ok((Instruction::Alloc, 1)),
            Opcode::Mintime => Ok((Instruction::Mintime, 1)),
            Opcode::Maxtime => Ok((Instruction::Maxtime, 1)),
            Opcode::Neg => Ok((Instruction::Neg, 1)),
            Opcode::Add => Ok((Instruction::Add, 1)),
            Opcode::Mul => Ok((Instruction::Mul, 1)),
            Opcode::Eq => Ok((Instruction::Eq, 1)),
            Opcode::Range => {
                if immdata.len() < 1 {
                    return Err(VMError::FormatError);
                }
                Ok((Instruction::Range(immdata[0]), 1 + 1))
            }
            Opcode::And => Ok((Instruction::And, 1)),
            Opcode::Or => Ok((Instruction::Or, 1)),
            Opcode::Verify => Ok((Instruction::Verify, 1)),
            Opcode::Blind => Ok((Instruction::Blind, 1)),
            Opcode::Reblind => Ok((Instruction::Reblind, 1)),
            Opcode::Unblind => Ok((Instruction::Unblind, 1)),
            Opcode::Issue => Ok((Instruction::Issue, 1)),
            Opcode::Borrow => Ok((Instruction::Borrow, 1)),
            Opcode::Retire => Ok((Instruction::Retire, 1)),
            Opcode::Qty => Ok((Instruction::Qty, 1)),
            Opcode::Flavor => Ok((Instruction::Flavor, 1)),
            Opcode::Cloak => {
                if immdata.len() < 8 {
                    return Err(VMError::FormatError);
                }
                let m = LittleEndian::read_u32(immdata) as usize;
                let n = LittleEndian::read_u32(&immdata[4..]) as usize;
                Ok((Instruction::Cloak(m, n), 1 + 8))
            }
            Opcode::Import => Ok((Instruction::Import, 1)),
            Opcode::Export => Ok((Instruction::Export, 1)),
            Opcode::Input => Ok((Instruction::Input, 1)),
            Opcode::Output => {
                if immdata.len() < 4 {
                    return Err(VMError::FormatError);
                }
                let k = LittleEndian::read_u32(immdata) as usize;
                Ok((Instruction::Output(k), 1 + 4))
            }
            Opcode::Contract => {
                if immdata.len() < 4 {
                    return Err(VMError::FormatError);
                }
                let k = LittleEndian::read_u32(immdata) as usize;
                Ok((Instruction::Contract(k), 1 + 4))
            }
            Opcode::Nonce => Ok((Instruction::Nonce, 1)),
            Opcode::Log => Ok((Instruction::Log, 1)),
            Opcode::Signtx => Ok((Instruction::Signtx, 1)),
            Opcode::Call => Ok((Instruction::Call, 1)),
            Opcode::Left => Ok((Instruction::Left, 1)),
            Opcode::Right => Ok((Instruction::Right, 1)),
            Opcode::Delegate => Ok((Instruction::Delegate, 1)),
        }
    }
}
