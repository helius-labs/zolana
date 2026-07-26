//! Records which smart-account builder inputs Rust refuses.
//!
//! The TypeScript port rejects oversized signer, instruction, and account
//! counts with structured `SmartAccountClientError` codes. Rust's builders are
//! infallible by signature and refuse the same overflows by panicking inside
//! `checked_u8`. Hand-written TypeScript tests prove the port refuses
//! something; this binary calls the production builders over the boundary
//! matrix and records each accept/reject so the suite replays Rust's decision.
//!
//! ```text
//! cargo run -p xtask --bin smart-account-rejects            # write the fixture
//! cargo run -p xtask --bin smart-account-rejects -- --check # fail on any drift
//! ```

use std::{
    env, fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_smart_account_client::{
    create_smart_account_ix, execute_sync_ix, settings_pda, treasury_pda, Permissions,
    SmartAccountSigner, SMART_ACCOUNT_PROGRAM_ID,
};

const FIXTURE: &str = "sdk-libs/ts/vectors/smart-account-rejects-v1.json";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("smart-account-rejects failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut check = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "Generate smart-account-client Rust rejection vectors.\n\nusage: cargo run -p xtask --bin smart-account-rejects -- [--check]"
                );
                return Ok(());
            }
            other => bail!("unexpected argument {other:?}"),
        }
    }

    let path = workspace_root()?.join(FIXTURE);
    let fixture = canonicalize(&fixture()?);
    let mut bytes = serde_json::to_vec_pretty(&fixture)?;
    bytes.push(b'\n');

    if check {
        let current = fs::read(&path)
            .with_context(|| format!("{FIXTURE} is missing; run the generator without --check"))?;
        if current != bytes {
            bail!("{FIXTURE} differs from Rust smart-account builders; regenerate it");
        }
        println!("verified {FIXTURE}");
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    println!("wrote {FIXTURE}");
    Ok(())
}

fn fixture() -> Result<Value> {
    let creator = Pubkey::new_from_array([1u8; 32]);
    let treasury = treasury_pda();
    let (settings, _) = settings_pda(1);
    let program = Pubkey::new_from_array([9u8; 32]);

    let accepts = vec![
        accept("create-empty-signers", || {
            create_smart_account_ix(&creator, &treasury, 1, None, &[], 1, 0);
        }),
        accept("create-duplicate-signers", || {
            let signer = SmartAccountSigner {
                key: Pubkey::new_from_array([7u8; 32]),
                permissions: Permissions { mask: 1 },
            };
            create_smart_account_ix(
                &creator,
                &treasury,
                1,
                None,
                &[
                    signer.clone(),
                    SmartAccountSigner {
                        key: signer.key,
                        permissions: Permissions { mask: 2 },
                    },
                ],
                1,
                0,
            );
        }),
        accept("create-zero-threshold", || {
            let signer = SmartAccountSigner {
                key: Pubkey::new_from_array([7u8; 32]),
                permissions: Permissions::all(),
            };
            create_smart_account_ix(&creator, &treasury, 1, None, &[signer], 0, 0);
        }),
        accept("execute-255-signers", || {
            let signers: Vec<Pubkey> = (0..255).map(|index| unique(index + 10)).collect();
            execute_sync_ix(&settings, 0, &signers, &[]);
        }),
        accept("execute-255-inner-instructions", || {
            let inners: Vec<Instruction> = (0..255).map(|_| inner(program, vec![])).collect();
            execute_sync_ix(&settings, 0, &[], &inners);
        }),
        accept("execute-255-accounts-per-instruction", || {
            // Same key repeated: the bound is on the per-instruction length, not
            // unique compiled accounts. Distinct keys hit the compiled-list cap first.
            let repeated = unique(300);
            let accounts = vec![repeated; 255];
            execute_sync_ix(&settings, 0, &[], &[inner(program, accounts)]);
        }),
        accept("execute-256-compiled-accounts", || {
            // Vault + program id are compiled first; 254 unique metas fill the u8 range.
            let accounts: Vec<Pubkey> = (0..254).map(|index| unique(index + 1000)).collect();
            let instruction = execute_sync_ix(&settings, 0, &[], &[inner(program, accounts)]);
            assert_eq!(instruction.accounts.len(), 258);
        }),
        accept("execute-duplicate-signer-keys", || {
            let member = unique(42);
            execute_sync_ix(&settings, 0, &[member, member], &[]);
        }),
    ];

    let rejects = vec![
        refuse(
            "execute-256-signers",
            "tooManySigners",
            "signer count exceeds u8",
            || {
                let signers: Vec<Pubkey> = (0..256).map(|index| unique(index + 10)).collect();
                execute_sync_ix(&settings, 0, &signers, &[]);
            },
        ),
        refuse(
            "execute-256-inner-instructions",
            "tooManyInstructions",
            "inner instruction count exceeds u8",
            || {
                let inners: Vec<Instruction> = (0..256).map(|_| inner(program, vec![])).collect();
                execute_sync_ix(&settings, 0, &[], &inners);
            },
        ),
        refuse(
            "execute-256-accounts-per-instruction",
            "tooManyAccounts",
            "inner instruction account count exceeds u8",
            || {
                let repeated = unique(300);
                let accounts = vec![repeated; 256];
                execute_sync_ix(&settings, 0, &[], &[inner(program, accounts)]);
            },
        ),
        refuse(
            "execute-257-compiled-accounts",
            "tooManyCompiledAccounts",
            "compiled account count exceeds u8",
            || {
                let accounts: Vec<Pubkey> = (0..255).map(|index| unique(index + 1000)).collect();
                execute_sync_ix(&settings, 0, &[], &[inner(program, accounts)]);
            },
        ),
        // Distinct keys: vault + program + 255 uniques = 257 compiled slots.
        // TypeScript's per-instruction length check still accepts 255 metas here
        // and only fails later if the compiled list grows past 256, so this case
        // is recorded separately from the repeated-key length refusal above.
        refuse(
            "execute-255-distinct-accounts-compiled-overflow",
            "tooManyCompiledAccounts",
            "compiled account count exceeds u8",
            || {
                let accounts: Vec<Pubkey> = (0..255).map(|index| unique(index + 2000)).collect();
                execute_sync_ix(&settings, 0, &[], &[inner(program, accounts)]);
            },
        ),
    ];

    // Tamper: rebuild a known-good create instruction, flip one payload byte,
    // and record that regenerating from the same inputs restores the canonical
    // bytes. The TypeScript suite must keep matching the canonical form.
    let signer = SmartAccountSigner {
        key: Pubkey::new_from_array([0x1b; 32]),
        permissions: Permissions::all(),
    };
    let canonical = create_smart_account_ix(&creator, &treasury, 1, None, &[signer], 1, 0);
    let mut tampered = canonical.data.clone();
    if tampered.is_empty() {
        bail!("create instruction data is empty");
    }
    tampered[0] ^= 0xff;
    let regenerated = create_smart_account_ix(
        &creator,
        &treasury,
        1,
        None,
        &[SmartAccountSigner {
            key: Pubkey::new_from_array([0x1b; 32]),
            permissions: Permissions::all(),
        }],
        1,
        0,
    );

    let tampers = vec![json!({
        "id": "tamper-create-discriminator-byte",
        "kind": "tamper",
        "mutation": "xorFirstDataByte",
        "canonicalDataBytes": hex(&canonical.data),
        "tamperedDataBytes": hex(&tampered),
        "regeneratedMatchesCanonical": regenerated.data == canonical.data,
        "programId": SMART_ACCOUNT_PROGRAM_ID.to_string(),
    })];

    Ok(json!({
        "accepts": accepts,
        "generatorCommand": "cargo run -p xtask --bin smart-account-rejects",
        "id": "smart-account-rejects-v1",
        "rejects": rejects,
        "responsibility": concat!(
            "Rust oracle for @zolana/smart-account-client builder rejection and ",
            "tamper cases: checked_u8 overflows on signer/instruction/account ",
            "counts, acceptance of shapes the create builder does not refuse, ",
            "and a create-payload byte flip that regeneration must not follow."
        ),
        "rustPath": "sdk-libs/smart-account-client/src/lib.rs",
        "rustSymbol": "checked_u8; create_smart_account_ix; execute_sync_ix",
        "schema": "zolana-ts-fixtures-v1",
        "tampers": tampers,
        "version": "1",
    }))
}

fn accept(id: &str, action: impl FnOnce() + std::panic::UnwindSafe) -> Value {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(()) => json!({
            "accepted": true,
            "id": id,
        }),
        Err(payload) => panic!(
            "acceptance case {id} panicked: {}",
            panic_message(payload.as_ref())
        ),
    }
}

fn refuse(
    id: &str,
    kind: &str,
    expected_message: &str,
    action: impl FnOnce() + std::panic::UnwindSafe,
) -> Value {
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(()) => panic!("rejection case {id} was accepted by Rust"),
        Err(payload) => {
            let message = panic_message(payload.as_ref());
            if !message.contains(expected_message) {
                panic!(
                    "rejection case {id} panicked with unexpected message {message:?}; expected substring {expected_message:?}"
                );
            }
            json!({
                "accepted": false,
                "id": id,
                "kind": kind,
                "rustPanic": message,
            })
        }
    }
}

fn inner(program_id: Pubkey, accounts: Vec<Pubkey>) -> Instruction {
    Instruction {
        program_id,
        accounts: accounts
            .into_iter()
            .map(|key| AccountMeta::new_readonly(key, false))
            .collect(),
        data: Vec::new(),
    }
}

fn unique(value: u32) -> Pubkey {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    bytes[31] = 1;
    Pubkey::new_from_array(bytes)
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "non-string panic payload".to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect::<Map<_, _>>(),
        ),
        _ => value.clone(),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}
