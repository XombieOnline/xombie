use syn::{Ident, PathSegment};
use proc_macro2::TokenStream;

pub struct SequenceDefinition {
    pub name: Ident,
    pub application_tag_number: Option<u8>,
    pub fields: Vec<FieldDefinition>
}

pub struct FieldDefinition {
    pub id: Ident,
    pub kind: Ident,
    pub sub_kinds: Option<PathSegment>,
    pub optional: bool,
    pub context_tag_number: Option<u8>
}


impl FieldDefinition {
    pub fn parser_name(&self) -> Ident {
        let concatenated = format!("parse_{}", self.id);
        return Ident::new(&concatenated, self.id.span());
    }

    pub fn builder_name(&self) -> Ident {
        let concatenated = format!("build_{}", self.id);
        return Ident::new(&concatenated, self.id.span());
    }

}

pub struct FieldCode {
    pub builder: TokenStream,
    pub parser: TokenStream
}


pub struct SequenceInnerCallsCode {
    pub build_calls: TokenStream,
    pub parse_calls: TokenStream,
    pub components_unit_functions: TokenStream
}


