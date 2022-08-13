use std::fmt;

/// Enum with the different tag classes
/// * Universal: basic common types that are the same in all applications, defined in X.208 (all defined in this library are of this type)
/// * Application: types specific to an application (custom types)
/// * Context: types which depends on context, as sequence fields
/// * Private: types specific to an enterprise
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TagClass {
    Universal = 0b00,
    Application = 0b01,
    Context = 0b10,
    Private = 0b11
}


impl From<u8> for TagClass {
    fn from(u: u8) -> TagClass {
        match u & 0x03 {
            0b00 => TagClass::Universal,
            0b01 => TagClass::Application,
            0b10 => TagClass::Context,
            0b11 => TagClass::Private,
            _ => unreachable!()
        }
    }
}

impl fmt::Display for TagClass {

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TagClass::Universal => {
                write!(f, "universal")
            }
            TagClass::Application => {
                write!(f, "application")
            }
            TagClass::Context => {
                write!(f, "context")
            }
            TagClass::Private => {
                write!(f, "private")
            }
        }
        
    }

}

impl Default for TagClass {
    fn default() -> Self {
        return Self::Universal;
    }
}
