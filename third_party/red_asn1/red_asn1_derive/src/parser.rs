use super::parse_definitions::{FieldDefinition, SequenceDefinition};
use super::parse_error::{ParseError, ParseResult};
use syn::{
    Attribute, Data, DataStruct, DeriveInput, Field, Fields, FieldsNamed,
    GenericArgument, Ident, Meta, PathArguments, PathSegment, Type,
};

static OPTIONAL_TYPE: &str = "Optional";
static OPTION_TYPE: &str = "Option";
static ASN1_SEQ_ATTR: &str = "seq";
static ASN1_SEQ_FIELD_ATTR: &str = "seq_field";
static TAG_NUMBER_ATTR: &str = "context_tag";
static APPLICATION_TAG_ATTR: &str = "application_tag";

/// Public method to parse thre definition of an struct which
/// derives Sequence
pub fn parse_sequence(ast: DeriveInput) -> ParseResult<SequenceDefinition> {
    if let Data::Struct(data_struct) = ast.data {
        return parse_sequence_struct(ast.ident, &ast.attrs, data_struct);
    } else {
        return Err(ParseError::NotStruct);
    }
}

/// Method to parse a sequence definition when it is confirmed that
/// it is an struct.
fn parse_sequence_struct(
    seq_name: Ident,
    seq_attrs: &Vec<Attribute>,
    data_struct: DataStruct,
) -> ParseResult<SequenceDefinition> {
    let fields = parse_sequence_fields(data_struct)?;
    let mut application_tag_number: Option<u8> = None;

    match parse_sequence_attrs(seq_attrs) {
        Ok(tag_number) => {
            application_tag_number = tag_number;
        }
        Err(parse_error) => match parse_error {
            ParseError::NotFoundAttributeTag => {}
            _ => {
                return Err(parse_error);
            }
        },
    }

    return Ok(SequenceDefinition {
        name: seq_name,
        application_tag_number: application_tag_number,
        fields,
    });
}

fn parse_sequence_fields(
    data_struct: DataStruct,
) -> ParseResult<Vec<FieldDefinition>> {
    if let Fields::Named(fields_named) = data_struct.fields {
        return parse_structure_fields(fields_named);
    }

    // all fields of an struct are named
    unreachable!()
}

fn parse_structure_fields(
    fields: FieldsNamed,
) -> ParseResult<Vec<FieldDefinition>> {
    let mut fields_defs: Vec<FieldDefinition> = Vec::new();

    for field in fields.named {
        fields_defs.push(parse_structure_field(field)?);
    }

    return Ok(fields_defs);
}

fn parse_structure_field(field: Field) -> ParseResult<FieldDefinition> {
    let field_name;
    if let Some(name) = field.ident {
        field_name = name;
    } else {
        // fields of an struct are named
        unreachable!();
    }

    let (field_type, field_sub_types) = parse_field_type(&field.ty);
    let mut context_tag_number = None;
    let optional = is_field_optional(&field_type);

    match parse_field_attrs(&field.attrs) {
        Ok(tag_number) => {
            context_tag_number = tag_number;
        }
        Err(parse_error) => match parse_error {
            ParseError::NotFoundAttributeTag => {}
            _ => {
                return Err(parse_error);
            }
        },
    }

    return Ok(FieldDefinition {
        id: field_name,
        kind: field_type,
        sub_kinds: field_sub_types,
        optional,
        context_tag_number,
    });
}

fn parse_field_type(field_type: &Type) -> (Ident, Option<PathSegment>) {
    if let Type::Path(path) = &field_type {
        let field_kind = path.path.segments[0].ident.clone();
        let field_sub_kinds =
            parse_field_sub_types(&path.path.segments[0].arguments);
        return (field_kind, field_sub_kinds);
    }
    unreachable!();
}

fn parse_field_sub_types(arguments: &PathArguments) -> Option<PathSegment> {
    if let PathArguments::AngleBracketed(brack_argument) = arguments {
        if let GenericArgument::Type(ty) = &brack_argument.args[0] {
            if let Type::Path(path) = ty {
                return Some(path.path.segments[0].clone());
            }
        }
    }

    return None;
}

/// Check if a sequence field is optional based on its type.
/// If type is "Option" or "Optional", then the field is optional.
fn is_field_optional(field_type: &Ident) -> bool {
    if field_type == OPTION_TYPE {
        return true;
    }

    if field_type == OPTIONAL_TYPE {
        return true;
    }

    return false;
}

fn parse_field_attrs(attrs: &Vec<Attribute>) -> ParseResult<Option<u8>> {
    for attr in attrs {
        if attr.path.segments.len() > 0
            && attr.path.segments[0].ident == ASN1_SEQ_FIELD_ATTR
        {
            return parse_field_attr(attr);
        }
    }
    return Err(ParseError::NotFoundAttributeTag);
}

fn parse_field_attr(attr: &Attribute) -> ParseResult<Option<u8>> {
    let mut tag_number = None;

    if let Ok(Meta::List(ref meta)) = attr.parse_meta() {
        let subattrs: Vec<syn::NestedMeta> =
            meta.nested.iter().cloned().collect();

        for subattr in subattrs {
            if let syn::NestedMeta::Meta(ref a) = subattr {
                match a {
                    Meta::NameValue(name_value) => {
                        if name_value.ident == TAG_NUMBER_ATTR {
                            match name_value.lit {
                                syn::Lit::Int(ref value) => {
                                    let int_value = value.value();
                                    if int_value >= 256 {
                                        return Err(
                                            ParseError::InvalidTagNumberValue,
                                        );
                                    }
                                    tag_number = Some(int_value as u8);
                                }
                                _ => {
                                    return Err(
                                        ParseError::InvalidTagNumberValue,
                                    );
                                }
                            }
                        } else {
                            return Err(ParseError::AttributeUnknown(
                                name_value.ident.to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(ParseError::AttributeInvalidFormat(
                            attr.tts.to_string()
                        ));
                    }
                };
            }
        }
    }

    return Ok(tag_number);
}

fn parse_sequence_attrs(attrs: &Vec<Attribute>) -> ParseResult<Option<u8>> {
    for attr in attrs {
        if attr.path.segments.len() > 0
            && attr.path.segments[0].ident == ASN1_SEQ_ATTR
        {
            return parse_seq_attr(attr);
        }
    }
    return Err(ParseError::NotFoundAttributeTag);
}

fn parse_seq_attr(attr: &Attribute) -> ParseResult<Option<u8>> {
    let mut tag_number = None;

    if let Ok(Meta::List(ref meta)) = attr.parse_meta() {
        let subattrs: Vec<syn::NestedMeta> =
            meta.nested.iter().cloned().collect();
        for subattr in subattrs {
            if let syn::NestedMeta::Meta(ref a) = subattr {
                match a {
                    Meta::NameValue(name_value) => {
                        if name_value.ident == APPLICATION_TAG_ATTR {
                            match name_value.lit {
                                syn::Lit::Int(ref value) => {
                                    let int_value = value.value();
                                    if int_value >= 256 {
                                        return Err(
                                            ParseError::InvalidTagNumberValue,
                                        );
                                    }
                                    tag_number = Some(int_value as u8);
                                }
                                _ => {
                                    return Err(
                                        ParseError::InvalidTagNumberValue,
                                    );
                                }
                            }
                        } else {
                            return Err(ParseError::AttributeUnknown(
                                name_value.ident.to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(ParseError::AttributeInvalidFormat(
                            attr.tts.to_string()
                        ));
                    }
                };
            }
        }
    }

    return Ok(tag_number);
}
