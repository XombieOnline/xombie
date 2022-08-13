use std::convert::From;

/// Enum with the different tag types
/// * Primitive: Object which are not composed by other objects. For example, basic types like Integer, Boolean, ...
/// * Constructed: Object composed by other objects, such as Sequences.
/// 
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TagType {
    Primitive = 0b0,
    Constructed = 0b1
}

impl From<u8> for TagType {
    fn from(u: u8) -> TagType {
        match u & 0x01 {
            0 => TagType::Primitive,
            1 => TagType::Constructed,
            _ => unreachable!()
        }
    }
}


impl Default for TagType {
    fn default() -> Self {
        return Self::Primitive;
    }
}
