use serde::{Deserialize, Serialize};
use std::{fmt, path::Path};

use crate::MAX_POSEIDON_INPUTS as MAX_PUBLIC_HASH_INPUTS;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicFieldKind {
    Integer {
        bits: usize,
    },
    Bool,
    Hash,
    Array {
        len: usize,
        item: Box<PublicFieldKind>,
    },
}

pub trait PublicField {
    fn kind() -> PublicFieldKind;
}
pub trait PublicInputLayout {
    fn layout() -> Vec<(&'static str, PublicFieldKind)>;
}

macro_rules! integer {
    ($($t:ty => $bits:literal),*) => {$(impl PublicField for $t {
        fn kind() -> PublicFieldKind { PublicFieldKind::Integer { bits: $bits } }
    })*};
}
integer!(u8 => 8, u16 => 16, u32 => 32, u64 => 64, u128 => 128);
impl PublicField for bool {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Bool
    }
}
impl PublicField for crate::Field {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}
impl PublicField for crate::UtxoOwner {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}
impl PublicField for crate::ShieldedAddress {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Hash
    }
}
/// `[u8; N]` lays out as an array of bytes, which [`ProgramMetadata::validate`]
/// rejects: the circuit hashes byte arrays with `hash_bytes`, which no
/// generated verifier reproduces.
impl<T: PublicField, const N: usize> PublicField for [T; N] {
    fn kind() -> PublicFieldKind {
        PublicFieldKind::Array {
            len: N,
            item: Box::new(T::kind()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramMetadata {
    pub name: String,
    pub rust_type: String,
    pub fields: Vec<(String, PublicFieldKind)>,
}

/// Why a program's exported metadata cannot produce a verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataError {
    /// The program name is used in file names, crate names and generated code.
    InvalidProgramName {
        name: String,
    },
    InvalidRustType {
        program: String,
        rust_type: String,
    },
    InvalidFieldName {
        program: String,
        field: String,
    },
    TooManyPublicFields {
        program: String,
        count: usize,
    },
    ByteArrayField {
        program: String,
        field: String,
    },
    ArrayLength {
        program: String,
        field: String,
        len: usize,
    },
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgramName { name } => write!(
                f,
                "program name {name:?} is not a plain Rust identifier (ASCII letters, digits and `_`, not starting with a digit)"
            ),
            Self::InvalidRustType { program, rust_type } => write!(
                f,
                "program `{program}` has rust type {rust_type:?}, which is not a `::`-separated Rust path"
            ),
            Self::InvalidFieldName { program, field } => write!(
                f,
                "program `{program}` has public field {field:?}, which is not a plain Rust identifier"
            ),
            Self::TooManyPublicFields { program, count } => write!(
                f,
                "program `{program}` has {count} public fields; the public hash also covers the transaction hash and takes at most {MAX_PUBLIC_HASH_INPUTS} inputs, so a program has at most {} public fields",
                MAX_PUBLIC_HASH_INPUTS - 1
            ),
            Self::ByteArrayField { program, field } => write!(
                f,
                "program `{program}` public field `{field}` is a byte array; the circuit hashes byte arrays in a way the on-chain verifier does not reproduce, so declare it as `Field` (or a u64 or bool)"
            ),
            Self::ArrayLength {
                program,
                field,
                len,
            } => write!(
                f,
                "program `{program}` public field `{field}` has an array of length {len}; arrays hash as one Poseidon input of 1 to {MAX_PUBLIC_HASH_INPUTS} items"
            ),
        }
    }
}

impl std::error::Error for MetadataError {}

/// Plain Rust identifier: ASCII letters, digits and `_`, not starting with a
/// digit, and usable as a raw identifier.
pub fn is_plain_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    let starts_well = bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_');
    starts_well
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !matches!(name, "_" | "crate" | "self" | "super" | "Self")
}

impl ProgramMetadata {
    /// Rejects metadata the CLI cannot turn into a sound verifier or safe
    /// generated file and crate names.
    pub fn validate(&self) -> Result<(), MetadataError> {
        let program = &self.name;
        if !is_plain_identifier(program) {
            return Err(MetadataError::InvalidProgramName {
                name: program.clone(),
            });
        }
        if !self.rust_type.split("::").all(is_plain_identifier) {
            return Err(MetadataError::InvalidRustType {
                program: program.clone(),
                rust_type: self.rust_type.clone(),
            });
        }
        if self.fields.len() >= MAX_PUBLIC_HASH_INPUTS {
            return Err(MetadataError::TooManyPublicFields {
                program: program.clone(),
                count: self.fields.len(),
            });
        }
        for (field, kind) in &self.fields {
            if !is_plain_identifier(field) {
                return Err(MetadataError::InvalidFieldName {
                    program: program.clone(),
                    field: field.clone(),
                });
            }
            validate_kind(program, field, kind)?;
        }
        Ok(())
    }
}

fn validate_kind(program: &str, field: &str, kind: &PublicFieldKind) -> Result<(), MetadataError> {
    let PublicFieldKind::Array { len, item } = kind else {
        return Ok(());
    };
    if matches!(**item, PublicFieldKind::Integer { bits: 8 }) {
        return Err(MetadataError::ByteArrayField {
            program: program.into(),
            field: field.into(),
        });
    }
    if *len == 0 || *len > MAX_PUBLIC_HASH_INPUTS {
        return Err(MetadataError::ArrayLength {
            program: program.into(),
            field: field.into(),
            len: *len,
        });
    }
    validate_kind(program, field, item)
}

pub fn export_program(name: &str, rust_type: &str, layout: Vec<(&str, PublicFieldKind)>) {
    let Some(directory) = std::env::var_os("ZOLANA_PROGRAM_EXPORT_DIR") else {
        return;
    };
    let metadata = ProgramMetadata {
        name: name.into(),
        rust_type: rust_type.into(),
        fields: layout
            .into_iter()
            .map(|(name, kind)| (name.to_string(), kind))
            .collect(),
    };
    let output = Path::new(&directory).join(format!("{name}.json"));
    std::fs::write(
        output,
        serde_json::to_vec_pretty(&metadata).expect("serialize program metadata"),
    )
    .expect("write program metadata");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(fields: Vec<(&str, PublicFieldKind)>) -> ProgramMetadata {
        ProgramMetadata {
            name: "escrow".into(),
            rust_type: "circuits::Escrow".into(),
            fields: fields
                .into_iter()
                .map(|(name, kind)| (name.into(), kind))
                .collect(),
        }
    }

    #[test]
    fn byte_arrays_lay_out_as_arrays_of_bytes_and_are_rejected() {
        assert_eq!(
            <[u8; 32]>::kind(),
            PublicFieldKind::Array {
                len: 32,
                item: Box::new(PublicFieldKind::Integer { bits: 8 })
            }
        );
        for kind in [
            <[u8; 32]>::kind(),
            <[u8; 7]>::kind(),
            <[[u8; 4]; 2]>::kind(),
        ] {
            assert_eq!(
                program(vec![("destination", kind)]).validate(),
                Err(MetadataError::ByteArrayField {
                    program: "escrow".into(),
                    field: "destination".into(),
                })
            );
        }
        assert_eq!(program(vec![("count", u8::kind())]).validate(), Ok(()));
    }

    #[test]
    fn the_public_hash_input_limit_is_enforced() {
        let fields = |count: usize| {
            (0..count)
                .map(|_| ("amount", u64::kind()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            program(fields(MAX_PUBLIC_HASH_INPUTS - 1)).validate(),
            Ok(())
        );
        assert_eq!(
            program(fields(MAX_PUBLIC_HASH_INPUTS)).validate(),
            Err(MetadataError::TooManyPublicFields {
                program: "escrow".into(),
                count: MAX_PUBLIC_HASH_INPUTS,
            })
        );
        for len in [0, MAX_PUBLIC_HASH_INPUTS + 1] {
            let array = PublicFieldKind::Array {
                len,
                item: Box::new(PublicFieldKind::Bool),
            };
            assert_eq!(
                program(vec![("flags", array)]).validate(),
                Err(MetadataError::ArrayLength {
                    program: "escrow".into(),
                    field: "flags".into(),
                    len,
                })
            );
        }
        assert_eq!(
            program(vec![("flags", <[[bool; 3]; 12]>::kind())]).validate(),
            Ok(())
        );
    }

    #[test]
    fn names_used_in_generated_code_must_be_plain_identifiers() {
        for name in [
            "",
            "1escrow",
            "../escrow",
            "es-crow",
            "escrow\"",
            "r#type",
            "self",
            "_",
        ] {
            let mut metadata = program(Vec::new());
            metadata.name = name.into();
            assert_eq!(
                metadata.validate(),
                Err(MetadataError::InvalidProgramName { name: name.into() })
            );
        }
        let mut metadata = program(Vec::new());
        metadata.rust_type = "circuits::Escrow<T>".into();
        assert!(matches!(
            metadata.validate(),
            Err(MetadataError::InvalidRustType { .. })
        ));
        assert!(matches!(
            program(vec![("a b", u64::kind())]).validate(),
            Err(MetadataError::InvalidFieldName { .. })
        ));
        for name in ["escrow", "_escrow", "type", "Escrow2"] {
            let mut metadata = program(Vec::new());
            metadata.name = name.into();
            assert_eq!(metadata.validate(), Ok(()), "{name}");
        }
    }
}
