use super::parse_definitions::{SequenceDefinition, SequenceInnerCallsCode};
use crate::field_coder::code_field;
use proc_macro2::TokenStream;
use syn::Ident;

/// Function to write the code of the methods to build/parse a Sequence
/// used by Asn1Object.
pub fn code_sequence(sequence: &SequenceDefinition) -> TokenStream {
    let seq_name = &sequence.name;

    let seq_inner_calls = code_sequence_inner_calls(sequence);
    let build_calls = &seq_inner_calls.build_calls;
    let parse_calls = &seq_inner_calls.parse_calls;
    let components_unit_functions = &seq_inner_calls.components_unit_functions;

    let build_value = code_build_value(build_calls);
    let parse_value = code_parse_value(parse_calls, seq_name);
    let inner_build = code_inner_build();
    let mut inner_parse = code_inner_parse(seq_name);

    let build;
    let parse;

    if let Some(app_tag_number) = sequence.application_tag_number {
        build = code_build_with_application_tag(app_tag_number);
        inner_parse = quote! {
            #inner_parse

            fn _parse_application_tag<'a>(
                &self,
                raw: &'a [u8]
            ) -> red_asn1::Result<&'a [u8]> {
                let (raw, parsed_tag) = red_asn1::Tag::parse(raw)?;

                if parsed_tag != red_asn1::Tag::new(
                    #app_tag_number,
                    red_asn1::TagType::Constructed,
                    red_asn1::TagClass::Application
                ) {
                    return Err(red_asn1::Error::UnmatchedTag(
                        red_asn1::TagClass::Application
                    ))?;
                }

                return Ok(raw);
            }
        };

        parse = code_parse_with_application_tag(seq_name);
    } else {
        build = quote! {
            fn build(&self) -> Vec<u8> {
                return self._inner_build();
            }
        };

        parse = quote! {
            fn parse(raw: &[u8]) -> red_asn1::Result<(&[u8], Self)> {
                let mut sequence = Self::default();
                let raw = sequence._inner_parse(raw)?;
                return Ok((raw, sequence));
            }
        }
    }

    let total_exp = quote! {
        impl red_asn1::Asn1Object for #seq_name {
            fn tag() -> red_asn1::Tag {
                return red_asn1::Tag::new_constructed_universal(
                    red_asn1::SEQUENCE_TAG_NUMBER
                );
            }

            #build
            #parse

            #build_value
            #parse_value
        }

        impl #seq_name {
            #components_unit_functions
            #inner_build
            #inner_parse
        }
    };

    return total_exp;
}

fn code_build_value(build_calls: &TokenStream) -> TokenStream {
    return quote! {
        fn build_value(&self) -> Vec<u8> {
            let mut value: Vec<u8> = Vec::new();
            #build_calls
            return value;
        }
    };
}

/// To write the `parse_value` function of Asn1Object for Sequence.
/// In `parse_value` all the parse functions of the members of
/// the Sequence are called.
fn code_parse_value(
    parse_calls: &TokenStream,
    seq_name: &Ident,
) -> TokenStream {
    return quote! {
        fn parse_value(&mut self, raw: &[u8]) -> red_asn1::Result<()> {
            #parse_calls

            if raw.len() > 0 {
                return Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(red_asn1::Error::from(
                        red_asn1::Error::NoAllDataConsumed
                    ))
                ))?;
            }

            return Ok(());
        }
    };
}

fn code_inner_build() -> TokenStream {
    return quote! {
        fn _inner_build(&self) -> Vec<u8> {
            let mut built = Self::tag().build();
            let mut built_value = self.build_value();
            let mut built_length = red_asn1::build_length(built_value.len());

            built.append(&mut built_length);
            built.append(&mut built_value);

            return built;
        }
    };
}

/// Function to write the `_inner_parse` function (called from `parse`) of
/// the structure, which parses the structure tag and length, and calls
/// parse_value. In case of an application tag in the structure, this
/// is parsed in the `parse` function
fn code_inner_parse(seq_name: &Ident) -> TokenStream {
    return quote! {
        fn _inner_parse<'a>(
            &mut self,
            raw: &'a [u8]
        ) -> red_asn1::Result<&'a [u8]> {
            let (raw, parsed_tag) = red_asn1::Tag::parse(raw).or_else( |error|
                Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(error.clone())
                ))
            )?;

            if parsed_tag != Self::tag() {
                return Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(
                        red_asn1::Error::UnmatchedTag(
                            red_asn1::TagClass::Universal
                        )
                    )
                ))
            }

            let (raw, length) = red_asn1::parse_length(raw).or_else( |error|
                Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(error.clone())
                ))
            )?;

            if length > raw.len() {
                return Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(red_asn1::Error::from(red_asn1::Error::NoDataForLength))
                ))?;
            }

            let (raw_value, raw) = raw.split_at(length);
            self.parse_value(raw_value)?;

            return Ok(raw);
        }
    };
}

/// Function to write the code of the Asn1Object `build` function for Sequence
/// in case of having an application tag defined by the seq tag
fn code_build_with_application_tag(app_tag_number: u8) -> TokenStream {
    return quote! {
        fn build(&self) -> Vec<u8> {
            let mut built = red_asn1::Tag::new(
                #app_tag_number,
                red_asn1::TagType::Constructed,
                red_asn1::TagClass::Application
            ).build();

            let mut built_value = self._inner_build();
            let mut built_length = red_asn1::build_length(built_value.len());

            built.append(&mut built_length);
            built.append(&mut built_value);

            return built;
        }
    };
}

/// Function to write the code of the Asn1Object parse function for Sequence
/// in case of having an application tag defined by the seq tag
fn code_parse_with_application_tag(seq_name: &Ident) -> TokenStream {
    return quote! {
        fn parse(raw: &[u8]) -> red_asn1::Result<(&[u8], Self)> {
            let mut sequence = Self::default();
            let raw = sequence._parse_application_tag(raw).or_else(
                |error|
                Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(error.clone())
                ))
            )?;

            let (raw, length) = red_asn1::parse_length(raw).or_else(
                |error|
                Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(error.clone())
                ))
            )?;

            if length > raw.len() {
                return Err(red_asn1::Error::SequenceError(
                    stringify!(#seq_name).to_string(),
                    Box::new(red_asn1::Error::from(red_asn1::Error::NoDataForLength))
                ))?;
            }

            let (raw_value, raw) = raw.split_at(length);
            sequence._inner_parse(raw_value)?;
            return Ok((raw, sequence));
        }
    };
}

pub fn code_sequence_inner_calls(
    sequence: &SequenceDefinition,
) -> SequenceInnerCallsCode {
    let mut components_unit_functions = quote! {};
    let mut build_calls = quote! {};
    let mut parse_calls = quote! {};
    let seq_name = &sequence.name;

    for field in &sequence.fields {
        let builder_name = field.builder_name();
        let parser_name = field.parser_name();
        let field_name = &field.id;

        build_calls = quote! {
            #build_calls
            value.append(&mut self.#builder_name());
        };

        parse_calls = quote! {
            #parse_calls
            let raw = self.#parser_name(raw).or_else(
                |error| Err(red_asn1::Error::SequenceFieldError(
                    stringify!(#seq_name).to_string(),
                    stringify!(#field_name).to_string(),
                    Box::new(error.clone())
                )))?;
        };

        let field_code = code_field(field);
        let builder = &field_code.builder;
        let parser = &field_code.parser;

        components_unit_functions = quote! {
            #components_unit_functions

            #builder
            #parser
        };
    }

    return SequenceInnerCallsCode {
        build_calls,
        parse_calls,
        components_unit_functions,
    };
}
