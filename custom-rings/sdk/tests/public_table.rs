use bytemuck::Zeroable;
use custom_ring_interface::{
    delegate_policy_2x3_verifying_key, policy_2x3_anonymous_verifying_key,
    policy_2x3_verifying_key, policy_table_inputs, PolicyTableInputs,
};
use serde_json::Value;
use solana_address::Address;
use zolana_client::{prover::verify_proof_inputs, Proof};
use zolana_interface::tree_slot::{populated_tree_slots_hash_chain, TreeSlot};
use zolana_ring_policy::{EncodedRuleTable, PolicySource, SourceMap};

fn field(value: &Value) -> [u8; 32] {
    let bytes = hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap();
    bytes.try_into().unwrap()
}

#[test]
fn full_policy_proofs_bind_every_public_field_in_rust() {
    let mut cases = vec![
        (
            include_str!("fixtures/custom-ring-policy-2x3.json").to_owned(),
            &policy_2x3_verifying_key::VERIFYINGKEY,
        ),
        (
            include_str!("fixtures/custom-ring-policy-2x3-anonymous.json").to_owned(),
            &policy_2x3_anonymous_verifying_key::VERIFYINGKEY,
        ),
        (
            include_str!("fixtures/custom-ring-delegate-policy-2x3.json").to_owned(),
            &delegate_policy_2x3_verifying_key::VERIFYINGKEY,
        ),
    ];
    for (inputs, outputs, anonymous, delegate) in [
        (1, 2, false, false),
        (16, 2, false, false),
        (16, 4, false, false),
        (24, 2, false, false),
        (3, 4, true, false),
        (3, 2, true, false),
        (12, 2, true, false),
        (4, 4, false, true),
    ] {
        for subtree in [false, true] {
            let name = format!(
                "custom-ring-{}policy-{inputs}-{outputs}{}{}",
                if delegate { "delegate-" } else { "" },
                if anonymous { "-anonymous" } else { "" },
                if subtree { "-subtree" } else { "" }
            );
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/shaped-proofs")
                .join(format!("{name}.json"));
            let data = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let key = custom_ring_interface::shaped_verifying_keys::policy_shape_key(
                inputs, outputs, anonymous, delegate, subtree,
            )
            .expect("shipped key");
            cases.push((data, key));
        }
    }
    for (data, key) in &cases {
        let vector: Value = serde_json::from_str(data).unwrap();
        let request = vector["request"]
            .get("policy")
            .unwrap_or(&vector["request"]);
        let public: PolicyTableInputs = vector["publicInputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(field)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let sources = SourceMap::from_slots(core::array::from_fn(|i| PolicySource {
            list_id: request["sources"][i]["listId"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            registry: field(&request["sources"][i]["registry"]),
        }))
        .unwrap();
        let short = |v: &Value| field(v)[24..].try_into().unwrap();
        let table = EncodedRuleTable {
            rule_count: request["policyLen"].as_u64().unwrap().try_into().unwrap(),
            rules: core::array::from_fn(|i| field(&request["ruleEnc"][i])),
            inline_count: request["inlineCount"].as_u64().unwrap().try_into().unwrap(),
            inline_assets: core::array::from_fn(|i| field(&request["inlineAssets"][i])),
            inline_limits: core::array::from_fn(|i| short(&request["inlineLimits"][i])),
            limit_count: request["limitCount"].as_u64().unwrap().try_into().unwrap(),
            limit_assets: core::array::from_fn(|i| field(&request["limits"][i]["asset"])),
            limit_caps: core::array::from_fn(|i| short(&request["limits"][i]["cap"])),
            limit_cosign: core::array::from_fn(|i| short(&request["limits"][i]["cosignAbove"])),
        };
        // The full fixture must be accepted by the account's table validator.
        table.decode().unwrap();
        assert_eq!(table.rule_count, 16);
        assert_eq!(table.inline_count, 8);
        assert_eq!(table.limit_count, 8);
        let trees: Vec<_> = request["treeSlots"]
            .as_array()
            .unwrap()
            .iter()
            .take_while(|slot| field(&slot["utxoRoot"]) != [0; 32])
            .map(|slot| {
                TreeSlot::new(
                    u16::from_be_bytes(field(&slot["id"])[30..].try_into().unwrap()),
                    field(&slot["utxoRoot"]),
                    field(&slot["nullifierRoot"]),
                )
            })
            .collect();
        let recomputed = policy_table_inputs(
            field(&request["publicInputHash"]),
            table.hash(&sources).unwrap(),
            &sources,
            &table,
            populated_tree_slots_hash_chain(&trees).unwrap(),
        );
        assert_eq!(*recomputed, public);
        let config = custom_ring_interface::PolicyConfig {
            policy_hash: table.hash(&sources).unwrap(),
            rules: table,
            sources: core::array::from_fn(|i| custom_ring_interface::SourceSlot {
                list_id: sources.slots()[i].list_id,
                registry: if sources.slots()[i].registry == [0; 32] {
                    Address::default()
                } else {
                    Address::new_from_array([0x12; 32])
                },
            }),
            ..custom_ring_interface::PolicyConfig::zeroed()
        };
        assert_eq!(
            *config.public_table_inputs(public[0], public[77]).unwrap(),
            public
        );
        let proof = Proof::from_gnark_json(&vector["proof"].to_string()).unwrap();
        verify_proof_inputs(&proof, &public, key).unwrap();
        assert_eq!(key.nr_pubinputs, 78);
        assert_eq!(key.vk_ic.len(), 80);
        for index in 0..public.len() {
            let mut forged = public;
            forged[index][31] ^= 1;
            assert!(
                verify_proof_inputs(&proof, &forged, key).is_err(),
                "public field {index}"
            );
        }
        for (_, other_key) in &cases {
            if !core::ptr::eq(*other_key, *key) {
                assert!(verify_proof_inputs(&proof, &public, other_key).is_err());
            }
        }
        let mut missing = proof;
        missing.commitment = None;
        assert!(verify_proof_inputs(&missing, &public, key).is_err());
    }
}
