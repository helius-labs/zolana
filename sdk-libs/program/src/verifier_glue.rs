use crate::PublicFieldKind;

const HASH_SIGNATURE: &str = "impl PublicInputs {
    pub fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
";

const VERIFY: &str = "pub fn verify(proof: &CompressedProof, public_inputs: &PublicInputs, private_tx_hash: &[u8; 32]) -> Result<(), VerifyError> {
    verify_groth16(proof, public_inputs.hash(private_tx_hash)?, &VERIFYINGKEY)
}
";

pub fn render_verifier(name: &str, layout: &[(&str, PublicFieldKind)]) -> String {
    let field_import = if layout.is_empty() { "" } else { "Field, " };
    let mut text = format!(
        "use zolana_program::{{verifier::{{groth16_solana, public_hash, verify_groth16, {field_import}VerifyError}}, CompressedProof}};\n"
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
            PublicFieldKind::Array { len, item } => {
                let base = field.strip_prefix("r#").unwrap_or(field);
                let mut next = 0usize;
                let (pattern, expression) = array_binding(*len, item, base, &mut next);
                text.push_str(&format!("        let {pattern} = &self.{field};\n"));
                expression
            }
        };
        fields.push(expression);
    }
    text.push_str(&format!(
        "        public_hash(&[{}], private_tx_hash)\n    }}\n}}\n\n",
        fields.join(", ")
    ));
    text.push_str(VERIFY);
    text
}

fn rust_type(kind: &PublicFieldKind) -> String {
    match kind {
        PublicFieldKind::Integer { bits } => format!("u{bits}"),
        PublicFieldKind::Bool => "bool".to_string(),
        PublicFieldKind::Hash => "[u8; 32]".to_string(),
        PublicFieldKind::Array { len, item } => format!("[{}; {len}]", rust_type(item)),
    }
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
