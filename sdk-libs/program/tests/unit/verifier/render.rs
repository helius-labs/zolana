use std::{
    io::Write,
    process::{Command, Stdio},
};

use zolana_program::{__private::render_verifier, PublicInputLayout};

use super::{Settlement, Unconditional};

const UNCONDITIONAL: &str = "use zolana_program::{
    verifier::{groth16_solana, public_hash, verify_groth16, VerifyError},
    CompressedProof,
};

include!(\"unconditional.vk.rs\");

pub struct PublicInputs {}

impl PublicInputs {
    pub fn hash(&self, private_tx_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError> {
        public_hash(&[], private_tx_hash)
    }
}

pub fn verify(
    proof: &CompressedProof,
    public_inputs: &PublicInputs,
    private_tx_hash: &[u8; 32],
) -> Result<(), VerifyError> {
    verify_groth16(proof, public_inputs.hash(private_tx_hash)?, &VERIFYINGKEY)
}
";

fn rustfmt(source: &str) -> String {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run rustfmt");
    child
        .stdin
        .take()
        .expect("rustfmt stdin")
        .write_all(source.as_bytes())
        .expect("write to rustfmt");
    let output = child.wait_with_output().expect("wait for rustfmt");
    assert!(
        output.status.success(),
        "rustfmt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("rustfmt writes UTF-8")
}

#[test]
fn the_verifier_renders_every_field_kind() {
    assert_eq!(
        rustfmt(&render_verifier("settlement", &Settlement::layout())),
        include_str!("settlement.rs")
    );
}

#[test]
fn a_verifier_without_public_inputs_imports_no_field() {
    assert_eq!(
        rustfmt(&render_verifier("unconditional", &Unconditional::layout())),
        UNCONDITIONAL
    );
}

#[test]
fn a_raw_field_name_binds_its_elements_without_the_prefix() {
    let rendered = rustfmt(&render_verifier(
        "raw",
        &[(
            "r#type",
            zolana_program::PublicFieldKind::Array {
                len: 2,
                item: Box::new(zolana_program::PublicFieldKind::Bool),
            },
        )],
    ));
    assert!(rendered.contains("    pub r#type: [bool; 2],\n"));
    assert!(rendered.contains("        let [type_0, type_1] = &self.r#type;\n"));
    assert!(rendered.contains("Field::Array(&[Field::Bool(*type_0), Field::Bool(*type_1)])"));
}
