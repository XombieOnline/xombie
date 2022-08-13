use std::fmt;

pub type ParseResult<T> = Result<T, ParseError>;


#[derive(Clone, Debug)]
pub enum ParseError {

    /// The field has not attribute tag seq_field
    NotFoundAttributeTag,
    InvalidTagNumberValue,

    AttributeInvalidFormat(String),
    AttributeUnknown(String),
    /// The data type with [derive(Sequence)] it is not an struct
    NotStruct
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}
