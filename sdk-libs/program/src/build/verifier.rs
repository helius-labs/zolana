use super::{PublicFieldKind, Package, ProgramMetadata, Result, error};
use std::{fs, path::Path};
use sha2::{Digest, Sha256};

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
                let (pattern, expression) = array_binding(*len, item, &base, &mut next);
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

fn binding_base(name: &str) -> String { format!("__{name}") }
fn rust_type(kind: &PublicFieldKind) -> String {
    match kind {
        PublicFieldKind::Integer { bits } => format!("u{bits}"),
        PublicFieldKind::Bool => "bool".into(),
        PublicFieldKind::Hash => "[u8; 32]".into(),
        PublicFieldKind::Bytes { len } => format!("[u8; {len}]"),
        PublicFieldKind::Array { len, item } => format!("[{}; {len}]", rust_type(item)),
    }
}

pub(super) fn export(package: &Package, artifact: &Path, program: &ProgramMetadata, check: bool) -> Result<()> {
    let directory = package.manifest.parent().unwrap().join("src/verifier");
    export_to(artifact, program, &directory, check)
}

pub(super) fn export_to(artifact: &Path, program: &ProgramMetadata, directory: &Path, check: bool) -> Result<()> {
    let source = key_source(artifact)?;
    let layout: Vec<_> = program.fields.iter().map(|(name, kind)| (name.as_str(), kind.clone())).collect();
    let verifier = render_verifier(&program.name, &layout);
    let files = [(format!("{}.vk.rs", program.name), source), (format!("{}.rs", program.name), verifier)];
    if !check { fs::create_dir_all(directory)?; }
    for (name, contents) in files {
        let path = directory.join(name);
        if check {
            if fs::read_to_string(&path).ok().as_deref() != Some(&contents) { return Err(error(format!("{} is stale; rebuild without --check", path.display()))); }
        } else { super::write_if_changed(&path, contents)?; }
    }
    Ok(())
}

fn key_source(artifact: &Path) -> Result<String> {
    let key_bytes = fs::read(artifact.join("vk.bin"))?;
    let metadata: serde_json::Value = serde_json::from_slice(&fs::read(artifact.join("metadata.json"))?)?;
    let hash = format!("{:x}", Sha256::digest(&key_bytes));
    if metadata["verifying_key_sha256"].as_str() != Some(&hash) { return Err(error("verifying key differs from its setup metadata")); }
    let circuit_digest = fs::read_to_string(artifact.join("digest"))?;
    if metadata["digest"].as_str() != Some(circuit_digest.trim()) { return Err(error("verifying key belongs to a different circuit")); }
    let key = crate::proof::SolanaVerifyingKey::from_xark(&key_bytes).map_err(error)?;
    let key = key.as_key();
    let production = metadata["production_safe"].as_bool() == Some(true);
    let mut source = String::new();
    if !production {
        source.push_str("#[cfg(not(feature = \"insecure-test-setup\"))]\ncompile_error!(\"this verifying key is for testing only; enable insecure-test-setup\");\n\n");
    }
    source.push_str(&format!("pub const VERIFYINGKEY: groth16_solana::groth16::Groth16Verifyingkey<'static> = groth16_solana::groth16::Groth16Verifyingkey {{\n    nr_pubinputs: {},\n    vk_alpha_g1: {:?},\n    vk_beta_g2: {:?},\n    vk_gamma_g2: {:?},\n    vk_delta_g2: {:?},\n    vk_ic: &{:?},\n    vk_commitment: None,\n}};\n", key.nr_pubinputs, key.vk_alpha_g1, key.vk_beta_g2, key.vk_gamma_g2, key.vk_delta_g2, key.vk_ic));
    source.push_str(&format!("pub const ZOLANA_VK_SHA256: &str = \"{hash}\";\npub const ZOLANA_CIRCUIT_DIGEST: &str = \"{}\";\n", circuit_digest.trim()));
    Ok(source)
}

pub(super) fn export_plain(package: &Package, artifact: &Path, name: &str, check: bool) -> Result<()> {
    let directory = package.manifest.parent().unwrap().join("src/verifier");
    if !directory.is_dir() { return Ok(()); }
    let source = key_source(artifact)?;
    let path = directory.join(format!("{name}.vk.rs"));
    if check {
        if fs::read_to_string(&path).ok().as_deref() != Some(&source) { return Err(error(format!("{} is stale", path.display()))); }
    } else { super::write_if_changed(&path, source)?; }
    Ok(())
}
