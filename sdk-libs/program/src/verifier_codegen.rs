use zolana_zk_dsl::__private::{binding_base, rust_type};

use crate::PublicFieldKind;

const HASH_SIGNATURE: &str = "impl PublicInputs {
    pub fn hash(&self, transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
";

const VERIFY: &str = "pub struct Verifier<'a> {
    pub proof: &'a CompressedProof,
    pub public_inputs: PublicInputs,
    pub private_tx_hash: &'a [u8; 32],
    pub transfers: &'a [PublicTransfer],
}

impl Verifier<'_> {
    pub fn verify(&self) -> Result<(), VerifyError> {
        let transaction_hash = transaction_hash(self.private_tx_hash, self.transfers)
            .map_err(|_| VerifyError::PublicInputs)?;
        verify_groth16(self.proof, self.public_inputs.hash(&transaction_hash)?, &VERIFYINGKEY)
    }
}
";

pub fn render_verifier(name: &str, layout: &[(&str, PublicFieldKind)]) -> String {
    let field_import = if layout.is_empty() { "" } else { "Field, " };
    let mut text = format!(
        "use zolana_program::{{verifier::{{groth16_solana, public_hash, verify_groth16, {field_import}VerifyError}}, transaction_hash, CompressedProof, PublicTransfer}};\n"
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
    text.push('\n');
    text.push_str(HASH_SIGNATURE);
    let mut fields = Vec::with_capacity(layout.len());
    for (field, kind) in layout {
        let expression = match kind {
            PublicFieldKind::Integer { .. } => integer(&format!("self.{field}")),
            PublicFieldKind::Bool => boolean(&format!("self.{field}")),
            PublicFieldKind::Hash => hash(&format!("&self.{field}")),
            PublicFieldKind::Bytes { .. } => unsupported_bytes(),
            PublicFieldKind::Array { len, item } => {
                let base = binding_base(field);
                let mut next = 0usize;
                let (pattern, expression) = array_binding(*len, item, base, &mut next);
                text.push_str(&format!("        let {pattern} = &self.{field};\n"));
                expression
            }
        };
        fields.push(expression);
    }
    text.push_str(&format!(
        "        public_hash(&[{}], transaction_hash)\n    }}\n}}\n\n",
        fields.join(", ")
    ));
    text.push_str(VERIFY);
    text
}

fn array_binding(
    len: usize,
    item: &PublicFieldKind,
    base: &str,
    next: &mut usize,
) -> (String, String) {
    let (patterns, items): (Vec<String>, Vec<String>) = (0..len)
        .map(|_| match item {
            PublicFieldKind::Array { len, item } => array_binding(*len, item, base, next),
            PublicFieldKind::Integer { .. } => {
                let binding = element_binding(base, next);
                let expression = integer(&format!("*{binding}"));
                (binding, expression)
            }
            PublicFieldKind::Bool => {
                let binding = element_binding(base, next);
                let expression = boolean(&format!("*{binding}"));
                (binding, expression)
            }
            PublicFieldKind::Hash => {
                let binding = element_binding(base, next);
                let expression = hash(&binding);
                (binding, expression)
            }
            PublicFieldKind::Bytes { .. } => (element_binding(base, next), unsupported_bytes()),
        })
        .unzip();
    (
        format!("[{}]", patterns.join(", ")),
        format!("Field::Array(&[{}])", items.join(", ")),
    )
}

fn element_binding(base: &str, next: &mut usize) -> String {
    let binding = format!("{base}_{next}");
    *next += 1;
    binding
}

fn integer(value: &str) -> String {
    format!("Field::Integer(u128::from({value}))")
}

fn boolean(value: &str) -> String {
    format!("Field::Bool({value})")
}

fn hash(value: &str) -> String {
    format!("Field::Hash({value})")
}

/// A program's public inputs hash into one value on-chain, and that hash has no
/// encoding for packed bytes. The derive keeps them out through
/// `PublicHashField`; a layout that has them anyway renders a module that
/// refuses to compile.
fn unsupported_bytes() -> String {
    "compile_error!(\"a ZK program public input cannot be packed bytes; use [u8; 32] or a hash\")"
        .to_string()
}
