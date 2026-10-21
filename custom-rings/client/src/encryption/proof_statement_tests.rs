//! Rebuild the on-chain statement from actual encrypted fields before verifying Go proofs.

use super::*;
use custom_ring_interface::{CustomRingBasePublicInput, CustomRingPolicyPublicInput};
use serde_json::Value;
use zolana_client::{prover::verify_proof_inputs, Proof};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::tree_slot::TreeSlot;
use zolana_ring_policy::{EncodedRuleTable, PolicySource, SourceMap};

fn bytes<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

fn amount(value: &Value) -> u64 {
    u64::from_be_bytes(bytes::<32>(value)[24..].try_into().unwrap())
}

fn opening(value: &Value) -> ProofInputUtxo {
    ProofInputUtxo {
        domain: bytes(&value["domain"]),
        tree_id: bytes(&value["treeId"]),
        owner_hash: poseidon(&[
            &bytes::<32>(&value["ownerPkHash"]),
            &bytes::<32>(&value["nullifierPk"]),
        ])
        .unwrap(),
        asset: bytes(&value["asset"]),
        amount: bytes(&value["amount"]),
        blinding: bytes(&value["blinding"]),
        data_hash: bytes(&value["dataHash"]),
        ring_data_hash: bytes(&value["ringDataHash"]),
        ring_program_id: bytes(&value["ringProgramId"]),
    }
}

fn policy_hash(request: &Value) -> [u8; 32] {
    let sources = SourceMap::from_slots(core::array::from_fn(|i| PolicySource {
        list_id: request["sources"][i]["listId"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        registry: bytes(&request["sources"][i]["registry"]),
    }))
    .unwrap();
    EncodedRuleTable {
        rule_count: request["policyLen"].as_u64().unwrap().try_into().unwrap(),
        rules: core::array::from_fn(|i| bytes(&request["ruleEnc"][i])),
        inline_count: request["inlineCount"].as_u64().unwrap().try_into().unwrap(),
        inline_assets: core::array::from_fn(|i| bytes(&request["inlineAssets"][i])),
        inline_limits: core::array::from_fn(|i| amount(&request["inlineLimits"][i]).to_be_bytes()),
        limit_count: request["limitCount"].as_u64().unwrap().try_into().unwrap(),
        limit_assets: core::array::from_fn(|i| bytes(&request["limits"][i]["asset"])),
        limit_caps: core::array::from_fn(|i| amount(&request["limits"][i]["cap"]).to_be_bytes()),
        limit_cosign: core::array::from_fn(|i| {
            amount(&request["limits"][i]["cosignAbove"]).to_be_bytes()
        }),
    }
    .hash(&sources)
    .unwrap()
}

fn statement_hash(request: &Value) -> ([u8; 32], Value) {
    let tx = ViewingKey::from_canonical_bytes(&bytes::<32>(&request["txViewingSk"])).unwrap();
    let ephemeral = X25519Keypair::from_bytes(&bytes::<32>(&request["ephSk"]));
    let mut auditor_bytes = [4; 33];
    auditor_bytes[1..].copy_from_slice(&bytes::<32>(&request["auditorPk"]));
    let auditor = X25519Pubkey::from_bytes(auditor_bytes).unwrap();
    let salt = bytes(&request["salt"]);
    let n_in = request["nIn"].as_u64().unwrap() as usize;
    let n_out = request["nOut"].as_u64().unwrap() as usize;
    let anonymous = request["anonymous"].as_bool().unwrap();
    let outputs: Vec<_> = request["outputs"].as_array().unwrap()[..n_out]
        .iter()
        .map(opening)
        .collect();
    let message = if anonymous {
        let disclosure = AnonymousDisclosure {
            sender: bytes::<33>(&request["sender"])[1..].try_into().unwrap(),
            inputs: request["inputs"].as_array().unwrap()[..n_in]
                .iter()
                .map(|input| AuditInputOpening {
                    tree_id: amount(&input["treeId"]).try_into().unwrap(),
                    amount: amount(&input["amount"]),
                    asset: bytes(&input["asset"]),
                    blinding: bytes(&input["blinding"]),
                })
                .collect(),
            outputs: (0..n_out)
                .map(|i| {
                    let requested = &request["outputs"][i];
                    let identity = bytes::<33>(&request["recipients"][i]);
                    let owner = AnonymousOwner {
                        identity_tag: identity[0],
                        identity_key: identity[1..].try_into().unwrap(),
                        nullifier_pk: bytes(&requested["nullifierPk"]),
                    };
                    if outputs[i].domain != right_align(&UTXO_DOMAIN.to_be_bytes()) {
                        return AnonymousOutputOpening::Padding;
                    }
                    if outputs[i].ring_program_id == [0; 32] {
                        return AnonymousOutputOpening::Exit(AnonymousExit {
                            owner,
                            amount: amount(&requested["amount"]),
                            asset: bytes(&requested["asset"]),
                            blinding: bytes(&requested["blinding"]),
                        });
                    }
                    AnonymousOutputOpening::Ring(AnonymousRingOutput {
                        owner,
                        viewing_pk: bytes(&request["recipientViewingKeys"][i]),
                    })
                })
                .collect(),
        };
        AuditorEncryption::new_with_anonymous(&tx, &auditor, salt, &disclosure)
    } else {
        AuditorEncryption::new_with_outputs(&tx, &auditor, salt, &outputs)
    }
    .unwrap()
    .message;
    // The disclosure is deterministic. Reconstruct the fixture's separate ephemeral envelope.
    let mut ciphertext = tx.secret_bytes();
    seal_stream(&ephemeral, &auditor, AUDIT_ENC_INFO, &mut *ciphertext).unwrap();
    let trees: Vec<_> = request["treeSlots"]
        .as_array()
        .unwrap()
        .iter()
        .take_while(|tree| bytes::<32>(&tree["utxoRoot"]) != [0; 32])
        .map(|tree| {
            TreeSlot::new(
                amount(&tree["id"]).try_into().unwrap(),
                bytes(&tree["utxoRoot"]),
                bytes(&tree["nullifierRoot"]),
            )
        })
        .collect();
    let output_body_hashes: Vec<[u8; 32]> = outputs
        .iter()
        .enumerate()
        .map(|(i, output)| {
            if !anonymous || output.ring_program_id == [0; 32] {
                return [0; 32];
            }
            let ciphertext = bytes::<104>(&request["delivery"]["outputs"][i]["ciphertext"]);
            let mut body = [0x09u8; 105];
            body[1..].copy_from_slice(&ciphertext);
            hash_bytes(&body).unwrap()
        })
        .collect();
    let hash = CustomRingPolicyPublicInput {
        audit: CustomRingBasePublicInput {
            private_tx_hash: &bytes(&request["privateTxHash"]),
            tx_viewing_pk: tx.pubkey().as_bytes(),
            auditor_pk: auditor.as_bytes(),
            eph_pk: ephemeral.pubkey().as_bytes(),
            ciphertext: &ciphertext,
            output_body_hashes: &output_body_hashes,
            output_hashes: &outputs
                .iter()
                .map(|output| output.hash().unwrap())
                .collect::<Vec<_>>(),
            salt: &salt,
            disclosure: message.disclosure(),
            anonymous,
        },
        policy_hash: &policy_hash(request),
        tree_slots: &trees,
        address_tree_id: amount(&request["addressTreeId"]).try_into().unwrap(),
        ring_id: &bytes(&request["ringId"]),
        namespace_owner_hash: &bytes(&request["namespaceOwnerHash"]),
        approval_required: request["approvalRequired"].as_bool().unwrap(),
        key_escrow: request["keyEscrow"].as_bool().unwrap(),
        member_registry_root: &bytes(&request["memberRegistryRoot"]),
        foreign_root: &bytes(&request["foreignRoot"]),
    }
    .hash()
    .unwrap();
    let hex = |bytes: &[u8]| format!("0x{}", hex::encode(bytes));
    let transcript = serde_json::json!({
        "privateTxHash": request["privateTxHash"],
        "txViewingPk": hex(tx.pubkey().as_bytes()),
        "auditorPk": hex(auditor.as_bytes()),
        "ephPk": hex(ephemeral.pubkey().as_bytes()),
        "ciphertext": hex(&*ciphertext),
        "outputBodyHashes": output_body_hashes.iter().map(|body| hex(body)).collect::<Vec<_>>(),
        "outputHashes": outputs.iter().map(|output| hex(&output.hash().unwrap())).collect::<Vec<_>>(),
        "salt": hex(&salt),
        "disclosure": message.disclosure().iter().map(|field| hex(field)).collect::<Vec<_>>(),
        "anonymous": anonymous,
        "policyHash": hex(&policy_hash(request)),
        "treeSlots": request["treeSlots"],
        "addressTreeId": request["addressTreeId"],
        "ringId": request["ringId"],
        "namespaceOwnerHash": request["namespaceOwnerHash"],
        "approvalRequired": request["approvalRequired"],
        "keyEscrow": request["keyEscrow"],
        "memberRegistryRoot": request["memberRegistryRoot"],
        "foreignRoot": request["foreignRoot"],
        "publicInputHash": hex(&hash),
    });
    (hash, transcript)
}

#[test]
fn go_proofs_verify_against_reconstructed_encrypted_statements() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../sdk/tests/fixtures");
    let mut cases = vec![
        (
            fixtures.join("custom-ring-policy-2x3.json"),
            &custom_ring_interface::policy_2x3_verifying_key::VERIFYINGKEY,
        ),
        (
            fixtures.join("custom-ring-policy-2x3-anonymous.json"),
            &custom_ring_interface::policy_2x3_anonymous_verifying_key::VERIFYINGKEY,
        ),
        (
            fixtures.join("custom-ring-delegate-policy-2x3.json"),
            &custom_ring_interface::delegate_policy_2x3_verifying_key::VERIFYINGKEY,
        ),
    ];
    for (inputs, outputs, anonymous, delegate) in [
        (1, 2, false, false),
        (16, 2, false, false),
        (16, 4, false, false),
        (3, 4, true, false),
        (4, 4, false, true),
    ] {
        for subtree in [false, true] {
            let name = format!(
                "custom-ring-{}policy-{inputs}-{outputs}{}{}",
                if delegate { "delegate-" } else { "" },
                if anonymous { "-anonymous" } else { "" },
                if subtree { "-subtree" } else { "" }
            );
            cases.push((
                fixtures.join("shaped-proofs").join(format!("{name}.json")),
                custom_ring_interface::shaped_verifying_keys::policy_shape_key(
                    inputs, outputs, anonymous, delegate, subtree,
                )
                .unwrap(),
            ));
        }
    }
    for (path, key) in cases {
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let request = vector["request"]
            .get("policy")
            .unwrap_or(&vector["request"]);
        let mut public: [[u8; 32]; 78] = vector["publicInputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let (reconstructed, transcript) = statement_hash(request);
        if path.file_name().unwrap() == "custom-ring-policy-3-4-anonymous.json" {
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/anonymous-statement.json");
            if std::env::var_os("WRITE_RING_STATEMENT_FIXTURE").is_some() {
                std::fs::create_dir_all(fixture.parent().unwrap()).unwrap();
                std::fs::write(
                    &fixture,
                    serde_json::to_string_pretty(&transcript).unwrap() + "\n",
                )
                .unwrap();
            }
            let pinned: Value =
                serde_json::from_str(&std::fs::read_to_string(fixture).unwrap()).unwrap();
            assert_eq!(transcript, pinned);
        }
        assert_eq!(reconstructed, public[0], "{}", path.display());
        public[0] = reconstructed;
        let proof = Proof::from_gnark_json(&vector["proof"].to_string()).unwrap();
        verify_proof_inputs(&proof, &public, key).unwrap();
    }
}
