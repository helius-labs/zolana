use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

mod create_release;
mod find_smart_accounts;
mod init_protocol;
mod loadtest;
mod set_tree_fees;
mod tree_fees;
mod update_protocol_config;

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
            groth16_solana::vk::gnark::generate_bsb22_vk_file(
                &vk_bin,
                Path::new(&out_dir),
                &filename,
                "VERIFYINGKEY",
            )
            .unwrap_or_else(|e| panic!("failed to emit {filename}: {e:?}"));
            println!("wrote {out_dir}/{filename}");
        }
        Some("vk-json") => {
            let vk_json = args
                .next()
                .unwrap_or_else(|| usage_and_exit("usage: vk-json <vk_json> <out_dir> <filename>"));
            let out_dir = args
                .next()
                .unwrap_or_else(|| usage_and_exit("vk-json missing <out_dir>"));
            let filename = args
                .next()
                .unwrap_or_else(|| usage_and_exit("vk-json missing <filename>"));
            groth16_solana::vk::circom::generate_vk_file(&vk_json, &out_dir, &filename)
                .unwrap_or_else(|e| panic!("failed to emit {filename}: {e:?}"));
            println!("wrote {out_dir}/{filename}");
        }
        Some("loadtest") => {
            let options = match loadtest::Options::parse(args.collect()) {
                Ok(options) => options,
                Err(error) => usage_and_exit(&format!("loadtest: {error:#}")),
            };
            if let Err(error) = loadtest::run(options) {
                eprintln!("loadtest failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("program-ids") => print_program_ids(),
        Some("init-protocol") => {
            if let Err(error) = init_protocol::run(init_protocol::Options::parse(args.collect())) {
                eprintln!("init-protocol failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("find-smart-accounts") => {
            if let Err(error) =
                find_smart_accounts::run(find_smart_accounts::Options::parse(args.collect()))
            {
                eprintln!("find-smart-accounts failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("update-protocol-config") => {
            if let Err(error) =
                update_protocol_config::run(update_protocol_config::Options::parse(args.collect()))
            {
                eprintln!("update-protocol-config failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("set-tree-fees") => {
            if let Err(error) = set_tree_fees::run(set_tree_fees::Options::parse(args.collect())) {
                eprintln!("set-tree-fees failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("create-release") => {
            if let Err(error) = create_release::run(create_release::Options::parse(args.collect()))
            {
                eprintln!("create-release failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("generate-account-snapshots") => {
            let (deploy_dir, accounts_dir) = parse_account_snapshot_options(args.collect());
            if let Err(error) =
                create_release::generate_account_snapshots(&deploy_dir, &accounts_dir)
            {
                eprintln!("generate-account-snapshots failed: {error:?}");
                std::process::exit(1);
            }
        }
        Some("tx-size") => tx_size(args.collect()),
        Some("max-shape") => max_shape(args.collect()),
        Some("max-merge-shape") => max_merge_shape(),
        Some("--help") | Some("-h") | None => print_help(),
        Some(command) => {
            eprintln!("unknown xtask command: {command}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn parse_account_snapshot_options(args: Vec<String>) -> (PathBuf, PathBuf) {
    let mut deploy_dir = PathBuf::from("target/deploy");
    let mut accounts_dir = PathBuf::from("target/localnet-accounts");
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--deploy-dir" => {
                deploy_dir = args
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| usage_and_exit("--deploy-dir missing value"));
            }
            "--accounts-dir" => {
                accounts_dir = args
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| usage_and_exit("--accounts-dir missing value"));
            }
            other => usage_and_exit(&format!(
                "generate-account-snapshots: unexpected arg {other:?} \
                 (options: --deploy-dir <dir>, --accounts-dir <dir>)"
            )),
        }
    }
    (deploy_dir, accounts_dir)
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
        "RING_TEST_PROGRAM_ID={}",
        bs58::encode(zolana_program_test::RING_TEST_PROGRAM_ID).into_string()
    );
    println!(
        "SWAP_PROGRAM_ID={}",
        bs58::encode(swap_program::ID).into_string()
    );
    println!(
        "CUSTOM_RING_PROGRAM_ID={}",
        zolana_test_utils::localnet::CUSTOM_RING_PROGRAM_ADDRESS
    );
    println!("DEFAULT_TREE_ADDRESS={}", zolana_interface::pda::tree(0));
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
    println!("  vk-json                  Export one JSON verifying key as Rust source");
    println!("  program-ids              Print local validator program ids as shell assignments");
    println!("  init-protocol            Initialize the protocol on a cluster (see --help)");
    println!(
        "  find-smart-accounts      Recover an existing deployment's authority smart accounts"
    );
    println!("  update-protocol-config   Update protocol config flags on a cluster (see --help)");
    println!("  set-tree-fees            Set a pool tree's forester fee schedule (see --help)");
    println!(
        "  create-release           Build the localnet release artifacts + lockfile (see --help)"
    );
    println!(
        "  generate-account-snapshots  Generate canonical protocol accounts from the local build"
    );
    println!("  tx-size [N:M ...]        Compute serialized transaction sizes per circuit shape");
    println!(
        "  max-shape [DATA_LEN]     Largest transact shape that fits a v1 transaction, per rail"
    );
    println!(
        "  max-merge-shape          Largest merge input count that fits a v1 transaction, per rail"
    );
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
    use zolana_interface::instruction::instruction_data::MERGE_DEFAULT_INPUT_COUNT;
    use zolana_interface::{
        instruction::{
            tag, CircuitId, InputUtxo, InterfaceTransfer, OwnerTag, TransactIxData, TransactOutput,
            TransactProof,
        },
        N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
    };
    use zolana_transaction::instructions::transact::SENDER_SLOT_COUNT;

    // Pre-spec sender: owner_pk(34)+amounts(24)+blinding(31)+viewing_pks(1+33R)+data(2) = 92+33R
    // sender_slot_data(R) = type_prefix(1) + plaintext + GCM-tag(16) = 109 + 33R
    let current_sender_data_len = |r: usize| -> usize { 109 + 33 * r };
    // Pre-spec recipient: owner_pk(34)+sender_pk(33)+asset(8)+amount(8)+blinding(31)+data(1) = 115 B + 16 B GCM tag
    let current_recipient_data_len = 131_usize;

    // Spec-target ciphertext lengths (the per-output `data` slot). AES-256-CTR (no
    // tag), owner_pubkey and sender_pubkey dropped from ciphertexts. Unchanged by
    // the TransactOutput regrouping: the sender bundle is still one ciphertext
    // covering both change positions, so isolating this constant makes the size
    // delta below purely structural (owner tag vs the old 32-byte view_tag).
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

    // Each output is described by its owner tag and its optional ciphertext
    // length (`None` = a covered position carrying `data: None`). Since outputs
    // now fold the utxo hash, owner tag, and ciphertext into one `TransactOutput`,
    // this descriptor is all a shape needs.
    let build_ix_data = |interface_transfers: Vec<InterfaceTransfer>,
                         n: usize,
                         proof: TransactProof,
                         outputs_spec: &[(OwnerTag, Option<usize>)]|
     -> TransactIxData {
        let inputs = (0..n)
            .map(|_| InputUtxo {
                nullifier_hash: [0u8; 32],
                nullifier_tree_root_index: 0,
                utxo_tree_root_index: 0,
            })
            .collect();
        let outputs: Vec<TransactOutput> = outputs_spec
            .iter()
            .map(|(owner_tag, data_len)| TransactOutput {
                utxo_hash: [0u8; 32],
                owner_tag: *owner_tag,
                data: data_len.map(|len| vec![0u8; len]),
            })
            .collect();
        // Captured before `outputs` moves into the external-data fields.
        let n_outputs = outputs.len() as u8;
        TransactIxData {
            expiry_unix_ts: 0,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            interface_transfers,
            outputs,
            messages: vec![],
            data_hash: None,
            ring_data_hash: None,
            circuit: CircuitId::ConfidentialEddsa(n as u8, n_outputs, N_PUBLIC_SLOTS as u8),
            proof,
            private_tx_hash: [0u8; 32],
            inputs,
        }
    };

    // Transfer layout: the sender bundle covers the leading SENDER_SLOT_COUNT
    // change positions (position 0 carries the ciphertext under the sender's tag,
    // the rest carry `None`), then R recipient positions each carry their own
    // Inline-tagged ciphertext. The sender tag is Account(0) when the owner is
    // the payer and Inline(..) for a relayed Ed25519 transfer.
    let transfer_layout = |m: usize,
                           sender_tag: OwnerTag,
                           sender_len: usize,
                           recipient_len: usize|
     -> Vec<(OwnerTag, Option<usize>)> {
        (0..m)
            .map(|position| {
                if position == 0 {
                    (sender_tag, Some(sender_len))
                } else if position < SENDER_SLOT_COUNT {
                    (sender_tag, None)
                } else {
                    (OwnerTag::Inline([0u8; 32]), Some(recipient_len))
                }
            })
            .collect()
    };

    // Split layout: one bundle at position 0 covers every output, so all M
    // positions share the Account(0) sender tag and only position 0 carries a
    // ciphertext. Expressible only now that coverage is data-placement, not a
    // vec-length convention.
    let split_layout = |m: usize, sender_len: usize| -> Vec<(OwnerTag, Option<usize>)> {
        (0..m)
            .map(|position| {
                let data = if position == 0 {
                    Some(sender_len)
                } else {
                    None
                };
                (OwnerTag::Account(0), data)
            })
            .collect()
    };

    let repeated_spl_withdraw_accounts = |leg_count: usize| {
        use solana_instruction::AccountMeta;
        use zolana_interface::SHIELDED_POOL_CPI_AUTHORITY_PUBKEY;

        let mut accounts = vec![
            AccountMeta::new(payer_pk, true),
            AccountMeta::new(tree_pk, false),
            AccountMeta::new(tree_pk, false),
        ];
        for index in 0..leg_count {
            let recipient = Pubkey::from([20 + index as u8; 32]);
            let user_token = Pubkey::from([40 + index as u8; 32]);
            accounts.push(AccountMeta::new_readonly(
                SHIELDED_POOL_CPI_AUTHORITY_PUBKEY,
                false,
            ));
            accounts.push(AccountMeta::new(vault_pk, false));
            accounts.push(AccountMeta::new(recipient, false));
            accounts.push(AccountMeta::new(user_token, false));
            accounts.push(AccountMeta::new_readonly(token_program_pk, false));
        }
        accounts.push(AccountMeta::new_readonly(spp_pk, false));
        accounts
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

    // TransactIxData.proof carries the compressed Groth16 points.
    const TRANSACT_PROOF_LEN: usize = 128;
    // Legacy flat proof (pre-enum, always 192 B, no tag) for the baseline table.
    const LEGACY_PROOF_LEN: usize = 192;

    let make_tx_sizes = |outputs_spec: &[(OwnerTag, Option<usize>)],
                         n: usize,
                         proof: TransactProof,
                         serialized_proof_len: usize|
     -> (usize, usize, usize, usize, usize) {
        let transfer_data = build_ix_data(Vec::new(), n, proof, outputs_spec);
        let shield_data = build_ix_data(
            vec![InterfaceTransfer::SplDeposit {
                amount: 1000,
                spl_interface_bump: 0,
            }],
            n,
            proof,
            outputs_spec,
        );

        let adj = serialized_proof_len as isize - TRANSACT_PROOF_LEN as isize;
        let adjust = |v: usize| (v as isize + adj) as usize;

        let ix_len = adjust(make_ix_bytes(&transfer_data).len());

        let ta = transfer_accounts(payer_pk, tree_pk, spp_pk);
        let sa = shield_accounts(
            payer_pk,
            tree_pk,
            vault_pk,
            recipient_pk,
            user_token_pk,
            token_program_pk,
            spp_pk,
        );

        let t_legacy = adjust(legacy_tx_len(Instruction {
            program_id: spp_pk,
            accounts: ta.clone(),
            data: make_ix_bytes(&transfer_data),
        }));
        let t_v0 = adjust(v0_tx_len(
            Instruction {
                program_id: spp_pk,
                accounts: ta,
                data: make_ix_bytes(&transfer_data),
            },
            std::slice::from_ref(&alt_transfer),
        ));
        let s_legacy = adjust(legacy_tx_len(Instruction {
            program_id: spp_pk,
            accounts: sa.clone(),
            data: make_ix_bytes(&shield_data),
        }));
        let s_v0 = adjust(v0_tx_len(
            Instruction {
                program_id: spp_pk,
                accounts: sa,
                data: make_ix_bytes(&shield_data),
            },
            std::slice::from_ref(&alt_shield),
        ));

        (ix_len, t_legacy, t_v0, s_legacy, s_v0)
    };

    println!("Legacy baseline (AES-GCM, redundant pubkeys in ciphertexts, 192 B proof):");
    println!(
        "| {:<14} | N | M | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
        "Circuit",
        "ix data (B)",
        "transfer, no ALT",
        "transfer, ALT",
        "shield, no ALT",
        "shield, ALT",
    );
    println!(
        "|{:-<16}|---|---|{:-<13}|{:-<23}|{:-<20}|{:-<21}|{:-<18}|",
        "", "", "", "", "", ""
    );

    for &(n, m) in &shapes {
        let r = m.saturating_sub(SENDER_SLOT_COUNT);
        let spec = transfer_layout(
            m,
            OwnerTag::Account(0),
            current_sender_data_len(r),
            current_recipient_data_len,
        );
        let (ix, tl, tv, sl, sv) =
            make_tx_sizes(&spec, n, TransactProof::zeroed(), LEGACY_PROOF_LEN);
        let fmt = |v: usize, show: bool| {
            if show {
                v.to_string()
            } else {
                "—".to_string()
            }
        };
        println!(
            "| {:<14} | {} | {} | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
            format!("{n} in {m} out"),
            n,
            m,
            ix,
            fmt(tl, r > 0),
            fmt(tv, r > 0),
            sl,
            sv,
        );
    }

    println!();
    println!("Spec-target (AES-256-CTR, no redundant pubkeys, 128 B vanilla proof):");
    println!(
        "| {:<14} | N | M | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
        "Circuit",
        "ix data (B)",
        "transfer, no ALT",
        "transfer, ALT",
        "shield, no ALT",
        "shield, ALT",
    );
    println!(
        "|{:-<16}|---|---|{:-<13}|{:-<23}|{:-<20}|{:-<21}|{:-<18}|",
        "", "", "", "", "", ""
    );

    for &(n, m) in &shapes {
        let r = m.saturating_sub(SENDER_SLOT_COUNT);
        let spec = transfer_layout(
            m,
            OwnerTag::Account(0),
            OPT_SENDER_DATA_LEN,
            OPT_RECIPIENT_DATA_LEN,
        );
        let (ix, tl, tv, sl, sv) =
            make_tx_sizes(&spec, n, TransactProof::zeroed(), TRANSACT_PROOF_LEN);
        let fmt = |v: usize, show: bool| {
            if show {
                v.to_string()
            } else {
                "—".to_string()
            }
        };
        println!(
            "| {:<14} | {} | {} | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
            format!("{n} in {m} out"),
            n,
            m,
            ix,
            fmt(tl, r > 0),
            fmt(tv, r > 0),
            sl,
            sv,
        );
    }

    // Sender owner-tag sensitivity: Account(0) is compact when the owner is the
    // payer; Inline is the relayed-Ed25519 case.
    println!();
    println!("Sender owner-tag sensitivity (3 in 3 out, eddsa rail, 2 change positions):");
    println!(
        "| {:<16} | {:>13} | {:>11} | {:>16} | {:>13} |",
        "sender tag", "tag B/pos", "ix data (B)", "transfer, no ALT", "transfer, ALT",
    );
    println!(
        "|{:-<18}|{:-<15}|{:-<13}|{:-<18}|{:-<15}|",
        "", "", "", "", ""
    );
    let sender_tag_kinds = [
        ("Account(0)", OwnerTag::Account(0), 2usize),
        ("Inline([u8;32])", OwnerTag::Inline([0u8; 32]), 33),
    ];
    for &(label, tag, tag_bytes) in &sender_tag_kinds {
        let spec = transfer_layout(3, tag, OPT_SENDER_DATA_LEN, OPT_RECIPIENT_DATA_LEN);
        let (ix, tl, tv, _sl, _sv) =
            make_tx_sizes(&spec, 3, TransactProof::zeroed(), TRANSACT_PROOF_LEN);
        println!(
            "| {:<16} | {:>13} | {:>11} | {:>16} | {:>13} |",
            label, tag_bytes, ix, tl, tv,
        );
    }

    // UTXO Split: a single bundle at position 0 covers all M outputs, so every
    // position shares the Account(0) sender tag and only position 0 carries a
    // ciphertext. This layout is expressible only after the regrouping.
    println!();
    println!("UTXO Split (single bundle covering every output, Account(0), eddsa rail):");
    println!(
        "| {:<14} | N | M | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
        "Circuit",
        "ix data (B)",
        "transfer, no ALT",
        "transfer, ALT",
        "shield, no ALT",
        "shield, ALT",
    );
    println!(
        "|{:-<16}|---|---|{:-<13}|{:-<23}|{:-<20}|{:-<21}|{:-<18}|",
        "", "", "", "", "", ""
    );
    let (n, m) = (1usize, 8usize);
    let spec = split_layout(m, OPT_SENDER_DATA_LEN);
    let (ix, tl, tv, sl, sv) = make_tx_sizes(&spec, n, TransactProof::zeroed(), TRANSACT_PROOF_LEN);
    println!(
        "| {:<14} | {} | {} | {:>11} | {:>21} | {:>18} | {:>19} | {:>16} |",
        format!("{n} in {m} out"),
        n,
        m,
        ix,
        tl,
        tv,
        sl,
        sv,
    );

    println!();
    println!("Public-leg sensitivity (3 in 3 out, repeated same-asset SPL withdrawals):");
    println!(
        "| {:>11} | {:>17} | {:>16} |",
        "interface transfers", "EdDSA ix data (B)", "EdDSA tx (B)",
    );
    println!("|{:-<13}|{:-<19}|{:-<18}|", "", "", "");
    let spec = transfer_layout(
        3,
        OwnerTag::Account(0),
        OPT_SENDER_DATA_LEN,
        OPT_RECIPIENT_DATA_LEN,
    );
    for leg_count in [0usize, 1, 5] {
        let interface_transfers = (0..leg_count)
            .map(|_| InterfaceTransfer::SplWithdrawal {
                amount: 1,
                spl_interface_bump: 0,
            })
            .collect::<Vec<_>>();
        let eddsa_data = build_ix_data(
            interface_transfers.clone(),
            3,
            TransactProof::zeroed(),
            &spec,
        );
        let eddsa_ix = Instruction {
            program_id: spp_pk,
            accounts: repeated_spl_withdraw_accounts(leg_count),
            data: make_ix_bytes(&eddsa_data),
        };
        println!(
            "| {:>11} | {:>17} | {:>16} |",
            leg_count,
            eddsa_ix.data.len(),
            legacy_tx_len(eddsa_ix),
        );
    }

    println!();
    println!("Builder layouts with nullifier PDAs (one writable PDA per input):");
    println!(
        "| {:<34} | {:>8} | {:>11} | {:>12} |",
        "transaction", "accounts", "ix data (B)", "legacy tx (B)",
    );
    println!("|{:-<36}|{:-<10}|{:-<13}|{:-<14}|", "", "", "", "");
    let tree = Pubkey::new_unique();
    for n in [2usize, 3, 5] {
        let spec = transfer_layout(
            3,
            OwnerTag::Account(0),
            OPT_SENDER_DATA_LEN,
            OPT_RECIPIENT_DATA_LEN,
        );
        let mut data = build_ix_data(Vec::new(), n, TransactProof::zeroed(), &spec);
        for (index, input) in data.inputs.iter_mut().enumerate() {
            input.nullifier_hash = [index as u8 + 1; 32];
        }
        let ix = zolana_interface::instruction::Transact {
            payer: payer_pk,
            input_tree: tree,
            output_tree: tree,
            owner_signers: Vec::new(),
            interface_transfer_accounts: Vec::new(),
            data,
        }
        .instruction()
        .expect("valid transact builder input");
        println!(
            "| {:<34} | {:>8} | {:>11} | {:>12} |",
            format!("transact {n} in 3 out, transfer"),
            ix.accounts.len(),
            ix.data.len(),
            legacy_tx_len(ix),
        );
    }
    {
        use zolana_interface::instruction::{
            instruction_data::MergeProof, MergeTransact, MergeTransactIxData,
        };
        let nullifiers = (0..MERGE_DEFAULT_INPUT_COUNT)
            .map(|index| [index as u8 + 1; 32])
            .collect::<Vec<_>>();
        let data = MergeTransactIxData {
            expiry_unix_ts: 0,
            proof: MergeProof::zeroed(),
            output_utxo_hash: [0u8; 32],
            eddsa_owner: true,
            private_tx_hash: [0u8; 32],
            nullifiers,
            utxo_tree_root_index: vec![0; MERGE_DEFAULT_INPUT_COUNT],
            nullifier_tree_root_index: vec![0; MERGE_DEFAULT_INPUT_COUNT],
        };
        let settings = Pubkey::new_unique();
        let vault = zolana_smart_account_client::smart_account_pda(&settings, 0).0;
        let merge_ix = MergeTransact {
            input_tree: tree,
            output_tree: tree,
            payer: vault,
            user_record: Pubkey::new_unique(),
            data,
        }
        .instruction()
        .expect("the default merge shape is supported");
        let merge_ix_accounts = merge_ix.accounts.len();
        let merge_ix_data_len = merge_ix.data.len();
        let direct_len = bincode::serialize(&Transaction::new_unsigned(Message::new(
            std::slice::from_ref(&merge_ix),
            Some(&payer_pk),
        )))
        .unwrap()
        .len();
        let sync_ix =
            zolana_smart_account_client::execute_sync_ix(&settings, 0, &[payer_pk], &[merge_ix]);
        let compute_budget = Instruction {
            program_id: Pubkey::from_str_const("ComputeBudget111111111111111111111111111111"),
            accounts: Vec::new(),
            data: [vec![2u8], 1_400_000u32.to_le_bytes().to_vec()].concat(),
        };
        let msg = Message::new(&[compute_budget, sync_ix.clone()], Some(&payer_pk));
        let tx = Transaction::new_unsigned(msg);
        println!(
            "| {:<34} | {:>8} | {:>11} | {:>12} |",
            "merge 8 in 1 out, direct", merge_ix_accounts, merge_ix_data_len, direct_len,
        );
        println!(
            "| {:<34} | {:>8} | {:>11} | {:>12} |",
            "merge 8 in 1 out, execute_sync + cb",
            sync_ix.accounts.len(),
            sync_ix.data.len(),
            bincode::serialize(&tx).unwrap().len(),
        );
    }
}

fn transfer_accounts(
    payer: solana_pubkey::Pubkey,
    tree: solana_pubkey::Pubkey,
    spp: solana_pubkey::Pubkey,
) -> Vec<solana_instruction::AccountMeta> {
    use solana_instruction::AccountMeta;
    vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(tree, false),
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
        AccountMeta::new(tree, false),
        AccountMeta::new(vault, false),
        AccountMeta::new(recipient, false),
        AccountMeta::new(user_token, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(spp, false),
    ]
}

/// Largest shape that fits a transaction v1 message, per rail.
///
/// The binding constraint is not the plain `transact`: a shape must also work
/// through a custom ring, which adds a signing ring config, the ring program's
/// own id, and whatever accounts and data that ring carries. This searches
/// against real serialized messages rather than a hand-rolled byte model, so it
/// stays correct when the instruction layout changes.
fn max_shape(args: Vec<String>) {
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::v1;
    use solana_pubkey::Pubkey;
    use zolana_interface::{
        instruction::{
            tag, CircuitId, InputUtxo, OwnerTag, TransactIxData, TransactOutput, TransactProof,
        },
        N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
    };

    // Ciphertext bytes per output, if any. `0` means a data-less output, which
    // is what a consolidation shape carries.
    let output_data_len: usize = args
        .first()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);

    let ix_data = |n_in: usize, n_out: usize| -> Vec<u8> {
        let data = TransactIxData {
            expiry_unix_ts: u64::MAX,
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            interface_transfers: Vec::new(),
            outputs: (0..n_out)
                .map(|_| TransactOutput {
                    utxo_hash: [0u8; 32],
                    owner_tag: OwnerTag::Inline([0u8; 32]),
                    data: (output_data_len > 0).then(|| vec![0u8; output_data_len]),
                })
                .collect(),
            messages: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            circuit: CircuitId::ConfidentialEddsa(n_in as u8, n_out as u8, N_PUBLIC_SLOTS as u8),
            proof: TransactProof {
                a: [0u8; 32],
                b: [0u8; 64],
                c: [0u8; 32],
            },
            private_tx_hash: [0u8; 32],
            inputs: (0..n_in)
                .map(|_| InputUtxo {
                    nullifier_hash: [0u8; 32],
                    nullifier_tree_root_index: 0,
                    utxo_tree_root_index: 0,
                })
                .collect(),
        };
        let mut bytes = vec![tag::TRANSACT];
        bytes.extend_from_slice(&data.serialize().expect("serialize transact ix data"));
        bytes
    };

    // A v1 transaction is the message plus the version prefix byte and the
    // signature array (a compact count plus 64 bytes each).
    let tx_len = |message_len: usize, signatures: usize| message_len + 1 + 1 + 64 * signatures;

    let fits = |n_in: usize,
                n_out: usize,
                extra_accounts: usize,
                extra_data: usize,
                signatures: usize|
     -> Option<(usize, usize)> {
        let payer = Pubkey::new_unique();
        // payer, input tree, output tree, pool, system, then one nullifier PDA
        // per input, then whatever the rail adds.
        let mut metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::from(SHIELDED_POOL_PROGRAM_ID), false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ];
        for _ in 0..n_in + extra_accounts {
            metas.push(AccountMeta::new(Pubkey::new_unique(), false));
        }
        let mut data = ix_data(n_in, n_out);
        data.extend(std::iter::repeat_n(0u8, extra_data));
        let instruction = Instruction {
            program_id: Pubkey::from(SHIELDED_POOL_PROGRAM_ID),
            accounts: metas,
            data,
        };
        let message = v1::Message::try_compile(&payer, &[instruction], Hash::default()).ok()?;
        let addresses = message.account_keys.len();
        let total = tx_len(message.size(), signatures);
        (total <= v1::MAX_TRANSACTION_SIZE && addresses <= usize::from(v1::MAX_ADDRESSES))
            .then_some((total, addresses))
    };

    println!(
        "transaction v1: {} bytes, {} addresses, {} signatures; output data = {output_data_len} B",
        v1::MAX_TRANSACTION_SIZE,
        v1::MAX_ADDRESSES,
        v1::MAX_SIGNATURES,
    );
    println!();
    println!(
        "{:<34} {:>7} {:>8} {:>8} {:>7}",
        "rail (n_out=2)", "max in", "bytes", "spare", "addrs"
    );

    // Modelled rails, widening from a bare pool call to a custom ring that
    // brings its own accounts, data and a second signer.
    let rails: [(&str, usize, usize, usize); 4] = [
        ("plain transact", 0, 0, 1),
        ("ring transact", 2, 64, 1),
        ("custom ring", 6, 256, 1),
        ("custom ring, two signers", 6, 256, 2),
    ];
    for (name, extra_accounts, extra_data, signatures) in rails {
        let mut best = None;
        for n_in in 1..200 {
            match fits(n_in, 2, extra_accounts, extra_data, signatures) {
                Some(result) => best = Some((n_in, result)),
                None => break,
            }
        }
        match best {
            Some((n_in, (bytes, addresses))) => println!(
                "{name:<34} {n_in:>7} {bytes:>8} {:>8} {addresses:>7}",
                v1::MAX_TRANSACTION_SIZE - bytes
            ),
            None => println!("{name:<34} {:>7}", "none"),
        }
    }

    println!();
    println!(
        "{:<34} {:>8} {:>8}",
        "shape (custom ring, 2 signers)", "bytes", "fits"
    );
    for (n_in, n_out) in [(40, 2), (42, 2), (44, 2), (48, 2), (1, 40), (1, 48)] {
        let label = format!("{n_in} in x {n_out} out");
        match fits(n_in, n_out, 6, 256, 2) {
            Some((bytes, _)) => println!("{label:<34} {bytes:>8} {:>8}", "yes"),
            None => println!("{label:<34} {:>8} {:>8}", "-", "no"),
        }
    }
}

/// Largest merge input count that fits a transaction v1 message, per rail.
///
/// Merge has no output count to vary: it always produces one UTXO. The rails
/// widen the same way `max-shape` does for transact. The `merge_ring` rows use
/// the production account layout, so the extra `ring_config` account, the ring
/// program's own address, and the 32-byte `output_ring_data_hash` are counted.
/// This command intentionally serializes hypothetical unsupported counts so it
/// can identify a future circuit ceiling; production builders reject those
/// counts before constructing an instruction.
fn max_merge_shape() {
    use solana_hash::Hash;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::v1;
    use solana_pubkey::Pubkey;
    use zolana_interface::{
        instruction::{
            builders::nullifier_pda_accounts,
            instruction_data::{merge_transact::MergeProof, MergeRingIxData},
            tag, MergeTransactIxData,
        },
        pda, PROGRAM_ID_PUBKEY,
    };

    let ix_data = |n_in: usize| MergeTransactIxData {
        expiry_unix_ts: u64::MAX,
        proof: MergeProof::zeroed(),
        output_utxo_hash: [0u8; 32],
        eddsa_owner: false,
        private_tx_hash: [0u8; 32],
        nullifiers: (0..n_in).map(|i| [i as u8; 32]).collect(),
        utxo_tree_root_index: vec![0; n_in],
        nullifier_tree_root_index: vec![0; n_in],
    };

    // A v1 transaction is the message plus the version prefix byte and the
    // signature array (a compact count plus 64 bytes each).
    let tx_len = |message_len: usize, signatures: usize| message_len + 1 + 1 + 64 * signatures;

    let fits = |rail: Rail,
                n_in: usize,
                extra_accounts: usize,
                extra_data: usize,
                signatures: usize|
     -> Option<(usize, usize)> {
        let payer = Pubkey::new_unique();
        let input_tree = Pubkey::new_unique();
        let output_tree = Pubkey::new_unique();
        let merge_data = ix_data(n_in);
        let nullifiers = merge_data.nullifiers.clone();
        let (program_id, mut accounts, data) = match rail {
            Rail::Plain => {
                let accounts = vec![
                    AccountMeta::new(input_tree, false),
                    AccountMeta::new(output_tree, false),
                    AccountMeta::new(payer, true),
                    AccountMeta::new_readonly(Pubkey::new_unique(), false),
                    AccountMeta::new_readonly(Pubkey::default(), false),
                    AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                ];
                let mut data = vec![tag::MERGE_TRANSACT];
                data.extend(merge_data.serialize().ok()?);
                (PROGRAM_ID_PUBKEY, accounts, data)
            }
            Rail::Ring => {
                let ring_program_id = Pubkey::new_unique();
                let accounts = vec![
                    AccountMeta::new(input_tree, false),
                    AccountMeta::new(output_tree, false),
                    AccountMeta::new_readonly(pda::ring_auth(&ring_program_id).0, false),
                    AccountMeta::new(payer, true),
                    AccountMeta::new_readonly(Pubkey::default(), false),
                    AccountMeta::new_readonly(PROGRAM_ID_PUBKEY, false),
                ];
                let mut data = vec![tag::RING_MERGE_TRANSACT];
                data.extend(
                    MergeRingIxData {
                        output_ring_data_hash: [0u8; 32],
                        merge: merge_data,
                    }
                    .serialize()
                    .ok()?,
                );
                (ring_program_id, accounts, data)
            }
        };
        accounts.extend(nullifier_pda_accounts(&input_tree, nullifiers.iter()));
        let mut instruction = Instruction {
            program_id,
            accounts,
            data,
        };
        for _ in 0..extra_accounts {
            instruction
                .accounts
                .push(AccountMeta::new(Pubkey::new_unique(), false));
        }
        instruction
            .data
            .extend(std::iter::repeat_n(0u8, extra_data));
        // A compute budget instruction is mandatory at these input counts, so it
        // is part of the budget rather than an afterthought.
        let compute_budget = Instruction {
            program_id: Pubkey::from_str_const("ComputeBudget111111111111111111111111111111"),
            accounts: Vec::new(),
            data: [vec![2u8], 1_400_000u32.to_le_bytes().to_vec()].concat(),
        };
        let message =
            v1::Message::try_compile(&payer, &[compute_budget, instruction], Hash::default())
                .ok()?;
        let addresses = message.account_keys.len();
        let total = tx_len(message.size(), signatures);
        (total <= v1::MAX_TRANSACTION_SIZE && addresses <= usize::from(v1::MAX_ADDRESSES))
            .then_some((total, addresses))
    };

    println!(
        "transaction v1: {} bytes, {} addresses, {} signatures; merge is always 1 output",
        v1::MAX_TRANSACTION_SIZE,
        v1::MAX_ADDRESSES,
        v1::MAX_SIGNATURES,
    );
    println!();
    println!(
        "{:<34} {:>7} {:>8} {:>8} {:>7}",
        "rail", "max in", "bytes", "spare", "addrs"
    );

    let rails: [(&str, Rail, usize, usize, usize); 4] = [
        ("merge_transact", Rail::Plain, 0, 0, 1),
        ("merge_ring", Rail::Ring, 0, 0, 1),
        ("merge_ring, custom ring", Rail::Ring, 6, 256, 1),
        ("merge_ring, custom ring, 2 signers", Rail::Ring, 6, 256, 2),
    ];
    for (name, rail, extra_accounts, extra_data, signatures) in rails {
        let mut best = None;
        for n_in in 1..200 {
            match fits(rail, n_in, extra_accounts, extra_data, signatures) {
                Some(result) => best = Some((n_in, result)),
                None => break,
            }
        }
        match best {
            Some((n_in, (bytes, addresses))) => println!(
                "{name:<34} {n_in:>7} {bytes:>8} {:>8} {addresses:>7}",
                v1::MAX_TRANSACTION_SIZE - bytes
            ),
            None => println!("{name:<34} {:>7}", "none"),
        }
    }

    println!();
    println!(
        "{:<34} {:>8} {:>8} {:>7}",
        "shape (custom ring, 2 signers)", "bytes", "fits", "addrs"
    );
    for n_in in [8, 32, 36, 38, 40, 42] {
        let label = format!("{n_in} in x 1 out");
        match fits(Rail::Ring, n_in, 6, 256, 2) {
            Some((bytes, addresses)) => {
                println!("{label:<34} {bytes:>8} {:>8} {addresses:>7}", "yes")
            }
            None => println!("{label:<34} {:>8} {:>8}", "-", "no"),
        }
    }
}

/// Which merge instruction a `max-merge-shape` row measures.
#[derive(Clone, Copy)]
enum Rail {
    Plain,
    Ring,
}
