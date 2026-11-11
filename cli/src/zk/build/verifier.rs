use super::{error, read, BuildError, ProgramMetadata, PublicFieldKind, Result};
use groth16_solana::vk::{
    circom::parse_vk_json_to_rust_string,
    setup::{proving_key_sha256, SetupKind},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const HASH_SIGNATURE: &str = "#[rustfmt::skip]
impl PublicInputs {
    pub fn hash(&self, transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
";

const VERIFY: &str = "pub struct Verifier<'a> {
    pub proof: &'a CompressedProof,
    pub public_inputs: PublicInputs,
    pub private_tx_hash: &'a [u8; 32],
    pub transfers: &'a [PublicTransfer],
}

#[rustfmt::skip]
impl Verifier<'_> {
    pub fn verify(&self) -> Result<(), VerifyError> {
        let transaction_hash = transaction_hash(self.private_tx_hash, self.transfers)
            .map_err(|_| VerifyError::PublicInputs)?;
        verify_groth16(self.proof, self.public_inputs.hash(&transaction_hash)?, &VERIFYINGKEY)
    }
}
";

/// The suffix of every verifying key module this tool writes.
const KEY_MODULE_SUFFIX: &str = ".vk.rs";

pub fn render_verifier(name: &str, layout: &[(&str, PublicFieldKind)]) -> String {
    let field_import = if layout.is_empty() { "" } else { "Field, " };
    // Generated items skip rustfmt, as the `.vk.rs` constants do, so `--check`
    // compares exact bytes that `cargo fmt` leaves alone.
    let mut text = format!(
        "#[rustfmt::skip]\nuse spr_program::{{verifier::{{groth16_solana, public_hash, verify_groth16, {field_import}VerifyError}}, transaction_hash, CompressedProof, PublicTransfer}};\n"
    );
    text.push_str(&format!("\ninclude!(\"{name}{KEY_MODULE_SUFFIX}\");\n\n"));
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

fn binding_base(name: &str) -> String {
    format!("__{name}")
}
fn rust_type(kind: &PublicFieldKind) -> String {
    match kind {
        PublicFieldKind::Integer { bits } => format!("u{bits}"),
        PublicFieldKind::Bool => "bool".into(),
        PublicFieldKind::Hash => "[u8; 32]".into(),
        PublicFieldKind::Array { len, item } => format!("[{}; {len}]", rust_type(item)),
    }
}

/// A module the build writes into the crate's `src/verifier` directory.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct GeneratedFile {
    pub name: String,
    pub contents: String,
}

/// The verifying key module and the verifier of a ZK program.
pub(super) fn program_files(
    program: &ProgramMetadata,
    keys: &KeyArtifacts,
) -> Result<[GeneratedFile; 2]> {
    let (source, _) = render_key_source(keys)?;
    let layout: Vec<_> = program
        .fields
        .iter()
        .map(|(name, kind)| (name.as_str(), kind.clone()))
        .collect();
    Ok([
        GeneratedFile {
            name: format!("{}{KEY_MODULE_SUFFIX}", program.name),
            contents: source,
        },
        GeneratedFile {
            name: format!("{}.rs", program.name),
            contents: render_verifier(&program.name, &layout),
        },
    ])
}

/// The verifying key module of a plain circuit, whose verifier is hand-written.
pub(super) fn plain_file(name: &str, keys: &KeyArtifacts) -> Result<GeneratedFile> {
    let (source, _) = render_key_source(keys)?;
    Ok(GeneratedFile {
        name: format!("{name}{KEY_MODULE_SUFFIX}"),
        contents: source,
    })
}

/// Writes the generated modules, or with `check` compares them with the
/// committed ones without writing. A check reports every stale, missing and
/// orphaned (a verifying key module no circuit generates) file at once.
pub(super) fn sync(directory: &Path, files: &[GeneratedFile], check: bool) -> Result<()> {
    if !check {
        fs::create_dir_all(directory)?;
        for file in files {
            super::write_if_changed(&directory.join(&file.name), &file.contents)?;
        }
        return Ok(());
    }
    let mut problems = Vec::new();
    for file in files {
        let path = directory.join(&file.name);
        match fs::read(&path) {
            Ok(committed) if committed == file.contents.as_bytes() => {}
            Ok(_) => problems.push(format!("stale: {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                problems.push(format!("missing: {}", path.display()))
            }
            Err(source) => return Err(BuildError::Io { path, source }),
        }
    }
    let expected: BTreeSet<&str> = files.iter().map(|file| file.name.as_str()).collect();
    for path in orphaned_key_modules(directory, &expected)? {
        problems.push(format!("orphan: {}", path.display()));
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(error(format!(
        "verifier modules differ from the build; rebuild without --check:\n  {}",
        problems.join("\n  ")
    )))
}

fn orphaned_key_modules(directory: &Path, expected: &BTreeSet<&str>) -> Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(BuildError::Io {
                path: directory.to_path_buf(),
                source,
            });
        }
    };
    let mut orphans = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.ends_with(KEY_MODULE_SUFFIX) && !expected.contains(name) {
            orphans.push(directory.join(name));
        }
    }
    orphans.sort();
    Ok(orphans)
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct KeySetupMetadata {
    pub proving_key_sha256: [u8; 32],
    pub insecure_test_setup: bool,
}

/// The setup outputs a verifier is generated from, read once so the bytes that
/// were checked are the bytes that are exported.
pub(super) struct KeyArtifacts {
    pub verifying_key: Vec<u8>,
    pub metadata: Vec<u8>,
    pub circuit_digest: String,
    pub proving_key_sha256: [u8; 32],
}

impl KeyArtifacts {
    pub(super) fn read(artifact: &Path) -> Result<Self> {
        let proving_key = artifact.join("pk.bin");
        Ok(Self {
            verifying_key: read(&artifact.join("vk.bin"))?,
            metadata: read(&artifact.join("metadata.json"))?,
            circuit_digest: read_circuit_digest(artifact)?,
            proving_key_sha256: proving_key_sha256(&proving_key).map_err(|source| {
                BuildError::Io {
                    path: proving_key,
                    source,
                }
            })?,
        })
    }
}

pub(super) fn read_circuit_digest(artifact: &Path) -> Result<String> {
    let path = artifact.join("digest");
    let bytes = read(&path)?;
    String::from_utf8(bytes)
        .map(|digest| digest.trim().to_string())
        .map_err(|_| error(format!("{} is not UTF-8", path.display())))
}

pub(super) fn key_setup_metadata(artifact: &Path) -> Result<KeySetupMetadata> {
    render_key_source(&KeyArtifacts::read(artifact)?).map(|(_, metadata)| metadata)
}

#[cfg(test)]
fn key_source(artifact: &Path) -> Result<String> {
    render_key_source(&KeyArtifacts::read(artifact)?).map(|(source, _)| source)
}

fn render_key_source(keys: &KeyArtifacts) -> Result<(String, KeySetupMetadata)> {
    let metadata: serde_json::Value = serde_json::from_slice(&keys.metadata)?;
    let hash = format!("{:x}", Sha256::digest(&keys.verifying_key));
    if metadata["verifying_key_sha256"].as_str() != Some(&hash) {
        return Err(error("verifying key differs from its setup metadata"));
    }
    if metadata["digest"].as_str() != Some(keys.circuit_digest.as_str()) {
        return Err(error("verifying key belongs to a different circuit"));
    }
    let key = spr_program::proof::snarkjs_verifying_key(&keys.verifying_key).map_err(error)?;
    let insecure_test_setup = !super::key_cache::production_metadata(&metadata)?;
    let setup = if insecure_test_setup {
        SetupKind::InsecureTest
    } else {
        SetupKind::Production
    };
    let mut source =
        parse_vk_json_to_rust_string(&key.to_string(), setup, &keys.proving_key_sha256)
            .map_err(error)?;
    source.push_str(&format!(
        "pub const ZOLANA_VK_SHA256: &str = \"{hash}\";\npub const ZOLANA_CIRCUIT_DIGEST: &str = {:?};\n",
        keys.circuit_digest
    ));
    Ok((
        source,
        KeySetupMetadata {
            proving_key_sha256: keys.proving_key_sha256,
            insecure_test_setup,
        },
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/verifier.rs"]
mod tests;
