use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("create-verifying-keys") => {
            let options = CreateVerifyingKeysOptions::parse(args.collect());
            create_verifying_keys(options);
        }
        Some("bsb22-vk") => {
            let vk_bin = args
                .next()
                .unwrap_or_else(|| usage_and_exit("usage: bsb22-vk <vk_bin> <out_dir> <filename>"));
            let out_dir = args
                .next()
                .unwrap_or_else(|| usage_and_exit("bsb22-vk missing <out_dir>"));
            let filename = args
                .next()
                .unwrap_or_else(|| usage_and_exit("bsb22-vk missing <filename>"));
            groth16_solana::gnark_vk_parser::generate_bsb22_vk_file(
                &vk_bin,
                Path::new(&out_dir),
                &filename,
                "VERIFYINGKEY",
            )
            .unwrap_or_else(|e| panic!("failed to emit {filename}: {e:?}"));
            println!("wrote {out_dir}/{filename}");
        }
        Some("program-ids") => print_program_ids(),
        Some("tx-size") => tx_size(args.collect()),
        Some("--help") | Some("-h") | None => print_help(),
        Some(command) => {
            eprintln!("unknown xtask command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_program_ids() {
    println!(
        "SHIELDED_POOL_PROGRAM_ID={}",
        bs58::encode(zolana_interface::SHIELDED_POOL_PROGRAM_ID).into_string()
    );
    println!(
        "USER_REGISTRY_PROGRAM_ID={}",
        bs58::encode(zolana_user_registry_interface::USER_REGISTRY_PROGRAM_ID).into_string()
    );
    println!(
        "ZONE_TEST_PROGRAM_ID={}",
        bs58::encode(zolana_program_test::ZONE_TEST_PROGRAM_ID).into_string()
    );
}

#[derive(Debug)]
struct CreateVerifyingKeysOptions {
    keys_dir: PathBuf,
    out_dir: PathBuf,
    limit: Option<usize>,
}

impl CreateVerifyingKeysOptions {
    fn parse(args: Vec<String>) -> Self {
        let mut keys_dir = PathBuf::from("prover/server/proving-keys");
        let mut out_dir = env::var("ZOLANA_VERIFYING_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target/verifying-keys"));
        let mut limit = env::var("ZOLANA_VERIFYING_KEYS_LIMIT")
            .ok()
            .map(|value| parse_limit(&value));

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--keys-dir" => {
                    keys_dir = args
                        .next()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| usage_and_exit("--keys-dir missing value"));
                }
                "--out-dir" => {
                    out_dir = args
                        .next()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| usage_and_exit("--out-dir missing value"));
                }
                "--limit" => {
                    let value = args
                        .next()
                        .unwrap_or_else(|| usage_and_exit("--limit missing value"));
                    limit = Some(parse_limit(&value));
                }
                "--help" | "-h" => {
                    print_create_verifying_keys_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        Self {
            keys_dir,
            out_dir,
            limit,
        }
    }
}

fn create_verifying_keys(options: CreateVerifyingKeysOptions) {
    let workspace_root = env::current_dir().expect("failed to resolve current directory");
    let keys_dir = absolute_path(&workspace_root, &options.keys_dir);
    let out_dir = absolute_path(&workspace_root, &options.out_dir);
    let prover_server_dir = workspace_root.join("prover/server");

    if !keys_dir.is_dir() {
        eprintln!(
            "proving key directory does not exist: {}",
            keys_dir.display()
        );
        std::process::exit(1);
    }
    if !prover_server_dir.is_dir() {
        eprintln!(
            "prover server directory does not exist: {}",
            prover_server_dir.display()
        );
        std::process::exit(1);
    }

    fs::create_dir_all(&out_dir).expect("failed to create verifying key output directory");

    let mut proving_keys = read_proving_keys(&keys_dir);
    if let Some(limit) = options.limit {
        proving_keys.truncate(limit);
    }
    if proving_keys.is_empty() {
        eprintln!("no proving keys found in {}", keys_dir.display());
        std::process::exit(1);
    }

    let mut manifest = String::from("# Generated verifying keys\n# sha256  bytes  filename\n");
    for key_path in proving_keys {
        let stem = key_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("proving key filename is not valid UTF-8");
        let output_path = out_dir.join(format!("{stem}.vkey"));

        println!(
            "exporting verifying key {} -> {}",
            key_path.display(),
            output_path.display()
        );
        export_verifying_key(&prover_server_dir, &key_path, &output_path);

        let metadata = fs::metadata(&output_path).unwrap_or_else(|error| {
            panic!(
                "failed to read generated verifying key {}: {error}",
                output_path.display()
            )
        });
        if metadata.len() == 0 {
            panic!(
                "generated verifying key is empty: {}",
                output_path.display()
            );
        }

        let hash = sha256_file(&output_path);
        manifest.push_str(&format!(
            "{hash}  {}  {}\n",
            metadata.len(),
            output_path
                .file_name()
                .expect("output filename missing")
                .to_string_lossy()
        ));
    }

    fs::write(out_dir.join("MANIFEST.txt"), manifest)
        .expect("failed to write verifying key manifest");
}

fn read_proving_keys(keys_dir: &Path) -> Vec<PathBuf> {
    let mut keys = fs::read_dir(keys_dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", keys_dir.display()))
        .map(|entry| {
            entry
                .expect("failed to read proving key directory entry")
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("key"))
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn export_verifying_key(prover_server_dir: &Path, key_path: &Path, output_path: &Path) {
    let status = Command::new("go")
        .current_dir(prover_server_dir)
        .args(["run", ".", "export-vk", "--keys-file"])
        .arg(key_path)
        .arg("--output")
        .arg(output_path)
        .status()
        .unwrap_or_else(|error| panic!("failed to run go export-vk: {error}"));

    if !status.success() {
        panic!("go export-vk failed with status {status}");
    }
}

fn sha256_file(path: &Path) -> String {
    let mut file = fs::File::open(path)
        .unwrap_or_else(|error| panic!("failed to open {}: {error}", path.display()));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    format!("{:x}", hasher.finalize())
}

fn absolute_path(workspace_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

fn parse_limit(value: &str) -> usize {
    value
        .parse::<usize>()
        .unwrap_or_else(|_| usage_and_exit("--limit must be a positive integer"))
}

fn usage_and_exit(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_create_verifying_keys_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask <command>");
    println!();
    println!("Commands:");
    println!("  create-verifying-keys    Export prover-server verifying key artifacts");
    println!("  bsb22-vk                 Export one binary verifying key as Rust source");
    println!("  program-ids              Print local validator program ids as shell assignments");
    println!("  tx-size [N:M ...]        Compute serialized transaction sizes per circuit shape");
}

fn print_create_verifying_keys_help() {
    println!("xtask create-verifying-keys [--keys-dir <dir>] [--out-dir <dir>] [--limit <n>]");
    println!();
    println!("Defaults:");
    println!("  --keys-dir prover/server/proving-keys");
    println!("  --out-dir  $ZOLANA_VERIFYING_KEYS_DIR or target/verifying-keys");
}

fn tx_size(args: Vec<String>) {
    use bincode;
    use solana_hash::Hash;
    use solana_instruction::Instruction;
    use solana_keypair::Keypair;
    use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
    use solana_pubkey::Pubkey;
    use solana_signer::Signer;
    use solana_transaction::{versioned::VersionedTransaction, Transaction};
    use zolana_interface::{
        instruction::{tag, InputUtxo, OutputCiphertext, TransactIxData},
        SHIELDED_POOL_PROGRAM_ID,
    };
    use zolana_transaction::transfer::SENDER_SLOT_COUNT;

    // Pre-spec sender: owner_pk(34)+amounts(24)+blinding(31)+viewing_pks(1+33R)+data(2) = 92+33R
    // sender_slot_data(R) = type_prefix(1) + plaintext + GCM-tag(16) = 109 + 33R
    let current_sender_data_len = |r: usize| -> usize { 109 + 33 * r };
    // Pre-spec recipient: owner_pk(34)+sender_pk(33)+asset(8)+amount(8)+blinding(31)+data(1) = 115 B + 16 B GCM tag
    let current_recipient_data_len = 131_usize;

    // Spec-target: AES-256-CTR (no tag), owner_pubkey and sender_pubkey dropped from ciphertexts.
    const OPT_SENDER_DATA_LEN: usize = 58; // type_prefix(1) + 57 B plaintext
    const OPT_RECIPIENT_DATA_LEN: usize = 48; // 48 B plaintext

    let shapes: Vec<(usize, usize)> = if args.is_empty() {
        vec![(2, 2), (1, 2), (3, 3), (5, 3), (1, 8)]
    } else {
        args.iter()
            .map(|s| {
                let (ns, ms) = s.split_once(':').unwrap_or_else(|| {
                    eprintln!("error: expected N:M shape, got {s:?}");
                    std::process::exit(2);
                });
                let n = ns.parse::<usize>().unwrap_or_else(|_| {
                    eprintln!("error: bad N in {s:?}");
                    std::process::exit(2);
                });
                let m = ms.parse::<usize>().unwrap_or_else(|_| {
                    eprintln!("error: bad M in {s:?}");
                    std::process::exit(2);
                });
                (n, m)
            })
            .collect()
    };

    let payer = Keypair::new();
    let payer_pk = payer.pubkey();
    let tree_pk = Pubkey::from([2u8; 32]);
    let spp_pk = Pubkey::from(SHIELDED_POOL_PROGRAM_ID);

    // SPL shield/unshield extra accounts. vault and recipient are in the ALT;
    // user_token_pk and token_program_pk are inline (user-specific / program).
    let vault_pk = Pubkey::from([3u8; 32]);
    let recipient_pk = Pubkey::from([4u8; 32]);
    let user_token_pk = Pubkey::from([5u8; 32]);
    let token_program_pk = Pubkey::from([6u8; 32]);

    // ALT for a pure transfer: tree (writable) + program (readonly).
    let alt_transfer = AddressLookupTableAccount {
        key: Pubkey::from([10u8; 32]),
        addresses: vec![tree_pk, spp_pk],
    };
    // ALT for SPL shield: tree + vault + recipient (writable) + program (readonly).
    let alt_shield = AddressLookupTableAccount {
        key: Pubkey::from([11u8; 32]),
        addresses: vec![tree_pk, vault_pk, recipient_pk, spp_pk],
    };

    let build_ix_data = |public_spl: Option<i64>,
                         r: usize,
                         m: usize,
                         n: usize,
                         sender_len: usize,
                         recipient_len: usize|
     -> TransactIxData {
        let inputs = (0..n)
            .map(|_| InputUtxo {
                nullifier_hash: [0u8; 32],
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
                tree_index: 0,
                eddsa_signer_index: 255,
            })
            .collect();
        let mut output_ciphertexts = vec![OutputCiphertext {
            view_tag: [0u8; 32],
            data: vec![0u8; sender_len],
        }];
        for _ in 0..r {
            output_ciphertexts.push(OutputCiphertext {
                view_tag: [0u8; 32],
                data: vec![0u8; recipient_len],
            });
        }
        TransactIxData {
            proof: [0u8; 192],
            expiry_unix_ts: 0,
            relayer_fee: 0,
            private_tx_hash: [0u8; 32],
            inputs,
            public_sol_amount: None,
            public_spl_amount: public_spl,
            cpi_signer: None,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            output_utxo_hashes: vec![[0u8; 32]; m],
            output_ciphertexts,
        }
    };

    let make_ix_bytes = |data: &TransactIxData| -> Vec<u8> {
        let mut d = vec![tag::TRANSACT];
        d.extend_from_slice(&data.serialize().unwrap());
        d
    };

    let legacy_tx_len = |ix: Instruction| -> usize {
        let msg = Message::new(&[ix], Some(&payer_pk));
        let tx = Transaction::new(&[&payer], msg, Hash::default());
        bincode::serialize(&tx).unwrap().len()
    };

    let v0_tx_len = |ix: Instruction, alts: &[AddressLookupTableAccount]| -> usize {
        let msg = v0::Message::try_compile(&payer_pk, &[ix], alts, Hash::default()).unwrap();
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&payer]).unwrap();
        bincode::serialize(&tx).unwrap().len()
    };

    // TransactIxData.proof is [u8; 192] in the struct, but EdDSA (Solana rail)
    // vanilla Groth16 proofs are 128 B. P256 rail adds 32 B proof_commitment +
    // 32 B proof_commitment_pok for a total of 192 B.
    const STRUCT_PROOF_LEN: usize = 192;
    const EDDSA_PROOF_LEN: usize = 128;

    let make_tx_sizes = |n: usize,
                         m: usize,
                         r: usize,
                         sender_len: usize,
                         recipient_len: usize,
                         proof_len: usize|
     -> (usize, usize, usize, usize, usize) {
        let transfer_data = build_ix_data(None, r, m, n, sender_len, recipient_len);
        let shield_data = build_ix_data(Some(1000), r, m, n, sender_len, recipient_len);

        let adj = proof_len as isize - STRUCT_PROOF_LEN as isize;
        let adjust = |v: usize| (v as isize + adj) as usize;

        let ix_len = adjust(make_ix_bytes(&transfer_data).len());

        let ta = transfer_accounts(payer_pk, tree_pk, spp_pk);
        let sa = shield_accounts(payer_pk, tree_pk, vault_pk, recipient_pk, user_token_pk, token_program_pk, spp_pk);

        let t_legacy = adjust(legacy_tx_len(Instruction { program_id: spp_pk, accounts: ta.clone(), data: make_ix_bytes(&transfer_data) }));
        let t_v0 = adjust(v0_tx_len(Instruction { program_id: spp_pk, accounts: ta, data: make_ix_bytes(&transfer_data) }, &[alt_transfer.clone()]));
        let s_legacy = adjust(legacy_tx_len(Instruction { program_id: spp_pk, accounts: sa.clone(), data: make_ix_bytes(&shield_data) }));
        let s_v0 = adjust(v0_tx_len(Instruction { program_id: spp_pk, accounts: sa, data: make_ix_bytes(&shield_data) }, &[alt_shield.clone()]));

        (ix_len, t_legacy, t_v0, s_legacy, s_v0)
    };

    println!("Current code (AES-GCM, redundant pubkeys in ciphertexts, 192 B proof):");
    println!(
        "| {:<14} | N | M | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
        "Circuit", "ix data (B)", "transfer, no ALT", "transfer, ALT", "shield, no ALT", "shield, ALT",
    );
    println!("|{:-<16}|---|---|{:-<13}|{:-<23}|{:-<20}|{:-<21}|{:-<18}|", "", "", "", "", "", "");

    for &(n, m) in &shapes {
        let r = m.saturating_sub(SENDER_SLOT_COUNT);
        let (ix, tl, tv, sl, sv) = make_tx_sizes(n, m, r, current_sender_data_len(r), current_recipient_data_len, STRUCT_PROOF_LEN);
        let fmt = |v: usize, show: bool| if show { v.to_string() } else { "—".to_string() };
        println!(
            "| {:<14} | {} | {} | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
            format!("{n} in {m} out"), n, m, ix,
            fmt(tl, r > 0), fmt(tv, r > 0), sl, sv,
        );
    }

    println!();
    println!("Spec-target EdDSA (AES-256-CTR, no redundant pubkeys, 128 B proof):");
    println!("  P256 rail adds 64 B (proof_commitment 32 B + proof_commitment_pok 32 B).");
    println!(
        "| {:<14} | N | M | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
        "Circuit", "ix data (B)", "transfer, no ALT", "transfer, ALT", "shield, no ALT", "shield, ALT",
    );
    println!("|{:-<16}|---|---|{:-<13}|{:-<23}|{:-<20}|{:-<21}|{:-<18}|", "", "", "", "", "", "");

    for &(n, m) in &shapes {
        let r = m.saturating_sub(SENDER_SLOT_COUNT);
        let (ix, tl, tv, sl, sv) = make_tx_sizes(n, m, r, OPT_SENDER_DATA_LEN, OPT_RECIPIENT_DATA_LEN, EDDSA_PROOF_LEN);
        let fmt = |v: usize, show: bool| if show { v.to_string() } else { "—".to_string() };
        println!(
            "| {:<14} | {} | {} | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
            format!("{n} in {m} out"), n, m, ix,
            fmt(tl, r > 0), fmt(tv, r > 0), sl, sv,
        );
    }
}

fn transfer_accounts(payer: solana_pubkey::Pubkey, tree: solana_pubkey::Pubkey, spp: solana_pubkey::Pubkey) -> Vec<solana_instruction::AccountMeta> {
    use solana_instruction::AccountMeta;
    vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(spp, false),
    ]
}

#[allow(clippy::too_many_arguments)]
fn shield_accounts(
    payer: solana_pubkey::Pubkey,
    tree: solana_pubkey::Pubkey,
    vault: solana_pubkey::Pubkey,
    recipient: solana_pubkey::Pubkey,
    user_token: solana_pubkey::Pubkey,
    token_program: solana_pubkey::Pubkey,
    spp: solana_pubkey::Pubkey,
) -> Vec<solana_instruction::AccountMeta> {
    use solana_instruction::AccountMeta;
    vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(tree, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(recipient, false),
        AccountMeta::new(user_token, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(spp, false),
    ]
}
