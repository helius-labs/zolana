//! Renders the verifier module of a circuit with regular public inputs: a
//! `PublicInputs` struct with the on-chain types of the public fields, their
//! encoding into the proof's public inputs, and `verify` over the zk DSL's
//! on-chain verifier.

use zolana_hasher::primitives::pack_be_chunks;

use crate::PublicFieldKind;

pub fn render_verifier(name: &str, layout: &[(&str, PublicFieldKind)]) -> String {
    let count: usize = layout.iter().map(|(_, kind)| kind.public_inputs()).sum();
    let mut encoding = Encoding::default();
    for (field, kind) in layout {
        encoding.next = 0;
        encoding.field(&Value::Field(field), binding_base(field), kind);
    }
    let imports = encoding.imports();
    let mut text = format!(
        "use zolana_program::{{verifier::{{{imports}groth16_solana, verify_groth16, VerifyError}}, CompressedProof}};\n"
    );
    text.push_str(&format!("\ninclude!(\"{name}.vk.rs\");\n\n"));
    if layout.is_empty() {
        text.push_str("pub struct PublicInputs {}\n");
    } else {
        text.push_str("pub struct PublicInputs {\n");
        for (field, kind) in layout {
            text.push_str(&format!("    pub {field}: {},\n", rust_type(kind)));
        }
        text.push_str("}\n");
    }
    text.push_str(&format!(
        "\nimpl PublicInputs {{\n    pub fn public_inputs(&self) -> [[u8; 32]; {count}] {{\n"
    ));
    for statement in &encoding.statements {
        text.push_str(&format!("        {statement}\n"));
    }
    text.push_str(&format!(
        "        [{}]\n    }}\n}}\n\n",
        encoding.inputs.join(", ")
    ));
    text.push_str(
        "pub fn verify(proof: &CompressedProof, public_inputs: &PublicInputs) -> Result<(), VerifyError> {
    verify_groth16(proof, &public_inputs.public_inputs(), &VERIFYINGKEY)
}
",
    );
    text
}

/// The on-chain Rust type of a public field.
pub fn rust_type(kind: &PublicFieldKind) -> String {
    match kind {
        PublicFieldKind::Integer { bits } => format!("u{bits}"),
        PublicFieldKind::Bool => "bool".to_string(),
        PublicFieldKind::Hash => "[u8; 32]".to_string(),
        PublicFieldKind::Bytes { len } => format!("[u8; {len}]"),
        PublicFieldKind::Array { len, item } => format!("[{}; {len}]", rust_type(item)),
    }
}

/// The name element bindings of a field start with: a raw identifier without
/// its `r#` prefix.
pub fn binding_base(field: &str) -> &str {
    field.strip_prefix("r#").unwrap_or(field)
}

/// A value the encoding reads: a field of `self` or an array element binding,
/// which destructuring a reference makes a reference itself.
enum Value<'a> {
    Field(&'a str),
    Element(String),
}

impl Value<'_> {
    fn owned(&self) -> String {
        match self {
            Self::Field(field) => format!("self.{field}"),
            Self::Element(binding) => format!("*{binding}"),
        }
    }

    fn reference(&self) -> String {
        match self {
            Self::Field(field) => format!("&self.{field}"),
            Self::Element(binding) => binding.clone(),
        }
    }
}

/// The statements and public input expressions that encode the public fields,
/// in public input order.
#[derive(Default)]
struct Encoding {
    statements: Vec<String>,
    inputs: Vec<String>,
    next: usize,
    integer: bool,
    boolean: bool,
    bytes: bool,
}

impl Encoding {
    fn field(&mut self, value: &Value, base: &str, kind: &PublicFieldKind) {
        match kind {
            PublicFieldKind::Integer { .. } => {
                self.integer = true;
                self.inputs
                    .push(format!("integer(u128::from({}))", value.owned()));
            }
            PublicFieldKind::Bool => {
                self.boolean = true;
                self.inputs.push(format!("boolean({})", value.owned()));
            }
            PublicFieldKind::Hash => self.inputs.push(value.owned()),
            PublicFieldKind::Bytes { len } => {
                self.bytes = true;
                let chunks = pack_be_chunks(*len);
                let names = self.bindings(base, chunks);
                self.statements.push(format!(
                    "let [{}] = pack_be::<{len}, {chunks}>({});",
                    names.join(", "),
                    value.reference()
                ));
                self.inputs.extend(names);
            }
            PublicFieldKind::Array { len, item } => {
                let names = self.bindings(base, *len);
                self.statements.push(format!(
                    "let [{}] = {};",
                    names.join(", "),
                    value.reference()
                ));
                for name in names {
                    self.field(&Value::Element(name), base, item);
                }
            }
        }
    }

    fn bindings(&mut self, base: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|_| {
                let name = format!("{base}_{}", self.next);
                self.next += 1;
                name
            })
            .collect()
    }

    fn imports(&self) -> String {
        [
            (self.boolean, "boolean, "),
            (self.integer, "integer, "),
            (self.bytes, "pack_be, "),
        ]
        .iter()
        .filter(|(used, _)| *used)
        .map(|(_, import)| *import)
        .collect()
    }
}
