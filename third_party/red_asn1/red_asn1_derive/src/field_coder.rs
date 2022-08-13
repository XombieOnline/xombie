use crate::parse_definitions::{FieldCode, FieldDefinition};
use proc_macro2::TokenStream;
use syn::{Ident, PathSegment};

/// Method to create the code for the build/parse methods
/// for a field of the structure
pub fn code_field(field: &FieldDefinition) -> FieldCode {
    return FieldCode {
        builder: code_field_builder(field),
        parser: code_field_parser(field),
    };
}

/// Method to create the code for the parse method of a
/// structure field
fn code_field_parser(field: &FieldDefinition) -> TokenStream {
    match field.context_tag_number {
        Some(ctx_tag) => match field.optional {
            true => code_optional_field_parser_with_context_tag(field, ctx_tag),
            false => {
                code_required_field_parser_with_context_tag(field, ctx_tag)
            }
        },

        None => code_field_parser_without_context_tag(field),
    }
}

fn code_required_field_parser_with_context_tag(
    field: &FieldDefinition,
    context_tag_number: u8,
) -> TokenStream {
    let parser_name = field.parser_name();
    let field_name = &field.id;
    let field_type = compose_field_type(&field.kind, &field.sub_kinds);

    return quote! {
        fn #parser_name<'a>(
            &mut self,
            raw: &'a [u8]
        ) -> red_asn1::Result<&'a [u8]> {
            let parsed_tag;
            let mut raw = raw;

            match red_asn1::Tag::parse(raw) {
                Ok((raw_tmp, tag)) => {
                    raw = raw_tmp;
                    parsed_tag = tag;
                },
                Err(error) => {
                    match error.clone() {
                        red_asn1::Error::NotEnoughTagOctets(_) => {
                            return Err(
                                red_asn1::Error::NotEnoughTagOctets(
                                    red_asn1::TagClass::Context
                                )
                            )?;
                        }
                        red_asn1::Error::EmptyTag(_) => {
                            return Err(
                                red_asn1::Error::EmptyTag(
                                    red_asn1::TagClass::Context
                                )
                            )?;
                        }
                        _ => {
                            return Err(error);
                        }
                    }
                }
            }

            if parsed_tag != red_asn1::Tag::new(
                #context_tag_number,
                red_asn1::TagType::Constructed,
                red_asn1::TagClass::Context
            ) {
                return Err(
                    red_asn1::Error::UnmatchedTag(
                        red_asn1::TagClass::Context
                    )
                )?;
            }

            let (raw, length) = red_asn1::parse_length(raw)?;
            if length > raw.len() {
                return Err(red_asn1::Error::NoDataForLength)?;
            }

            let (raw_value, raw) = raw.split_at(length);

            let (_, field) = #field_type::parse(raw_value)?;
            self.#field_name = field;

            return Ok(raw);
        }
    };
}

/// Write the code for parse a field in case of having a context tag
/// and being optional. In this case the parse fails in case the
/// context tag matchs but the type tag is incorrect, or the type
/// data is invalid. However is context tag doesn't match, then,
/// the field is set to None.
fn code_optional_field_parser_with_context_tag(
    field: &FieldDefinition,
    context_tag_number: u8,
) -> TokenStream {
    let parser_name = field.parser_name();
    let field_name = &field.id;
    let field_type = compose_field_type(&field.kind, &field.sub_kinds);

    return quote! {
        fn #parser_name<'a>(
            &mut self,
            raw: &'a [u8]
        ) -> red_asn1::Result<&'a [u8]> {
            let parsed_tag;
            let mut raw_local = raw;

            match red_asn1::Tag::parse(raw) {
                Ok((raw_tmp, tag)) => {
                    raw_local = raw_tmp;
                    parsed_tag = tag;
                },
                Err(error) => {
                    self.#field_name = None;
                    return Ok(raw);
                }
            }

            if parsed_tag != red_asn1::Tag::new(
                #context_tag_number,
                red_asn1::TagType::Constructed,
                red_asn1::TagClass::Context
            ) {
                self.#field_name = None;
                return Ok(raw);
            }

            let (raw_local, length) = red_asn1::parse_length(raw_local)?;
            if length > raw.len() {
                return Err(red_asn1::Error::NoDataForLength)?;
            }

            let (raw_value, raw_local) = raw_local.split_at(length);

            let (_, type_tag) = red_asn1::Tag::parse(raw_value)?;
            if type_tag != #field_type::tag() {
                return Err(
                    red_asn1::Error::UnmatchedTag(
                        red_asn1::TagClass::Universal
                    )
                );
            }

            let (_, field) = #field_type::parse(raw_value)?;
            self.#field_name = field;

            return Ok(raw_local);
        }
    };
}

fn code_field_parser_without_context_tag(
    field: &FieldDefinition,
) -> TokenStream {
    let parser_name = field.parser_name();
    let field_name = &field.id;
    let field_type = compose_field_type(&field.kind, &field.sub_kinds);
    return quote! {
        fn #parser_name<'a>(
            &mut self,
            raw: &'a [u8]
        ) -> red_asn1::Result<&'a [u8]> {
            let (raw, field) = #field_type::parse(raw)?;
            self.#field_name = field;
            return Ok(raw);
        }
    };
}

/// Method to create the code of the build method of a
/// structure field
fn code_field_builder(field: &FieldDefinition) -> TokenStream {
    match field.context_tag_number {
        Some(context_tag_number) => {
            code_field_builder_with_context_tag(field, context_tag_number)
        }
        None => code_field_builder_without_context_tag(field),
    }
}

fn code_field_builder_with_context_tag(
    field: &FieldDefinition,
    ctx_tag: u8,
) -> TokenStream {
    let builder_name = field.builder_name();
    let field_name = &field.id;

    return quote! {
        fn #builder_name (&self) -> Vec<u8> {
            let mut built_value = self.#field_name.build();
            if built_value.len() == 0 {
                return built_value;
            }

            let tag = red_asn1::Tag::new(
                #ctx_tag,
                red_asn1::TagType::Constructed,
                red_asn1::TagClass::Context
            );
            let mut built = tag.build();
            let mut built_length = red_asn1::build_length(built_value.len());

            built.append(&mut built_length);
            built.append(&mut built_value);

            return built;
        }
    };
}

fn code_field_builder_without_context_tag(
    field: &FieldDefinition,
) -> TokenStream {
    let builder_name = field.builder_name();
    let field_name = &field.id;

    return quote! {
        fn #builder_name (&self) -> Vec<u8> {
            return self.#field_name.build();
        }
    };
}

/// Function to compose the path to call Self functions. Simple types
/// call this functions with Type::function(), but other types, like
/// Option, required to call Self functions in the way
/// Option::<SubType>::function().
fn compose_field_type(
    field_kind: &Ident,
    field_sub_kinds: &Option<PathSegment>,
) -> TokenStream {
    match field_sub_kinds {
        Some(field_sub_types) => {
            quote! {#field_kind::<#field_sub_types>}
        }
        None => {
            quote! {#field_kind}
        }
    }
}
