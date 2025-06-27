#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opcode {
    OpPushdata1,
    OpChecksig,
}

impl Opcode {
    pub fn to_u8(&self) -> u8 {
        match self {
            Opcode::OpPushdata1 => 0x4c, // Example value, adjust as per actual protocol
            Opcode::OpChecksig => 0xac, // Example value, adjust as per actual protocol
        }
    }
}