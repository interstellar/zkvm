use byteorder::{ByteOrder, LittleEndian};
use core::mem;

const MAX_OPCODE: u8 = 0x25;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Represents a data string with a specified length
    Push(usize),

    /// Represents a dup of an item at a given index from the top of the stack
    Dup(usize),

    /// Represents a roll of an item from a given index from the top of the stack.
    Roll(usize),

    /// Represents a range proof with a given width (1..64)
    Range(u8),

    /// Represents a cloak operation between M inputs and N outputs
    Cloak(usize, usize),

    /// Represents an output with N payload items
    Output(usize),

    /// Represents a contract with N payload items
    Contract(usize),

    /// Represents all other supported instructions without any immediate data (plain opcodes)
    Other(Op),

    /// Unsupported instruction code
    Unsupported(u8),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
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

impl Op {
    pub fn to_u8(self) -> u8 {
        unsafe { mem::transmute(self) }
    }

    unsafe fn from_u8_unchecked(code: u8) -> Op {
        mem::transmute(code)
    }
}

impl Instruction {
    /// Returns a parsed instruction with a size that it occupies in the program string.
    /// E.g. a push instruction with 5-byte string occupies 1+4+5=10 bytes
    /// (4 for the LE32 length prefix).
    ///
    /// Return `None` if there is not enough bytes to parse an instruction.
    pub fn parse(program: &[u8]) -> Option<(Instruction, usize)> {
        if program.len() == 0 {
            return None;
        }

        let opcode = program[0];
        let immdata = &program[1..];

        if opcode > MAX_OPCODE {
            return Some((Instruction::Unsupported(opcode), 1));
        }

        // opcode is checked to be in a valid range above.
        let op = unsafe { Op::from_u8_unchecked(opcode) };

        match op {
            Op::Push => {
                if immdata.len() < 4 {
                    return None;
                }
                let strlen = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Push(strlen), 1 + 4 + strlen))
            }
            Op::Dup => {
                if immdata.len() < 4 {
                    return None;
                }
                let idx = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Dup(idx), 1 + 4))
            }
            Op::Roll => {
                if immdata.len() < 4 {
                    return None;
                }
                let idx = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Roll(idx), 1 + 4))
            }
            Op::Range => {
                if immdata.len() < 1 {
                    return None;
                }
                Some((Instruction::Range(immdata[0]), 1 + 1))
            }
            Op::Cloak => {
                if immdata.len() < 8 {
                    return None;
                }
                let m = LittleEndian::read_u32(immdata) as usize;
                let n = LittleEndian::read_u32(&immdata[4..]) as usize;
                Some((Instruction::Cloak(m, n), 1 + 8))
            }
            Op::Output => {
                if immdata.len() < 4 {
                    return None;
                }
                let k = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Output(k), 1 + 4))
            }
            Op::Contract => {
                if immdata.len() < 4 {
                    return None;
                }
                let k = LittleEndian::read_u32(immdata) as usize;
                Some((Instruction::Contract(k), 1 + 4))
            }
            _ => Some((Instruction::Other(op), 1)),
        }
    }
}
