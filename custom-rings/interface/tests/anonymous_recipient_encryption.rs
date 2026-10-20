//! Pins the recipient stream secret, the body layout, the base statement and the policy
//! statement to the Go vector.

use custom_ring_interface::{
    anonymous_output_body, anonymous_output_body_hash, recipient_stream_secret,
    AnonymousOutputPlaintext, CustomRingBasePublicInput, CustomRingPolicyPublicInput,
    ANONYMOUS_OUTPUT_PLAINTEXT_LEN, AUDIT_STREAM_INFO, BASE_PUBLIC_INPUT_ELEMENTS,
    BODY_CHAIN_INDEX, POLICY_INDEXED_INPUTS, POLICY_PUBLIC_INPUT_ELEMENTS,
};
use zolana_hasher::hash_chain::{create_hash_chain_4_from_slice, create_hash_chain_from_slice};
use zolana_hasher::primitives::hash_bytes;
use zolana_interface::tree_slot::TreeSlot;
use zolana_keypair::{symmetric_apply_audit, X25519Keypair, X25519Pubkey};

const VECTOR: &str = include_str!("../../../test-vectors/anonymous_recipient_encryption.json");

fn bytes<const N: usize>(value: &serde_json::Value) -> [u8; N] {
    let decoded = hex::decode(value.as_str().expect("hex string")).expect("hex");
    decoded.try_into().expect("length")
}

fn fields(value: &serde_json::Value) -> Vec<[u8; 32]> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(bytes::<32>)
        .collect()
}

#[test]
fn recipient_stream_and_body_follow_the_go_vector() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector json");
    let tx_sk = X25519Keypair::from_bytes(&bytes::<32>(&v["tx_sk"]));
    let recipient_sk = X25519Keypair::from_bytes(&bytes::<32>(&v["recipient_viewing_sk"]));
    let tx_pk = X25519Pubkey::from_bytes(bytes::<33>(&v["tx_pk"])).expect("tx pk");
    let recipient_pk =
        X25519Pubkey::from_bytes(bytes::<33>(&v["recipient_viewing_pk"])).expect("recipient pk");
    assert_eq!(tx_sk.pubkey(), tx_pk);
    assert_eq!(recipient_sk.pubkey(), recipient_pk);

    let dh = bytes::<32>(&v["dh"]);
    assert_eq!(*tx_sk.ecdh(&recipient_pk).expect("sender dh"), dh);
    assert_eq!(*recipient_sk.ecdh(&tx_pk).expect("recipient dh"), dh);

    let salt = bytes::<16>(&v["salt"]);
    let slot = u8::try_from(v["slot"].as_u64().expect("slot")).expect("slot byte");
    let secret =
        recipient_stream_secret(&dh, tx_pk.as_bytes(), recipient_pk.as_bytes(), &salt, slot)
            .expect("secret");
    assert_eq!(secret, bytes::<32>(&v["secret"]));

    let opening = AnonymousOutputPlaintext {
        asset_address: bytes::<32>(&v["asset_address"]),
        amount: v["amount"].as_u64().expect("amount"),
        blinding: bytes::<32>(&v["blinding"]),
        pair_u: bytes::<32>(&v["pair_u"]),
    };
    let plaintext = bytes::<ANONYMOUS_OUTPUT_PLAINTEXT_LEN>(&v["plaintext"]);
    assert_eq!(opening.to_bytes(), plaintext);
    assert_eq!(
        AnonymousOutputPlaintext::from_bytes(&plaintext),
        Ok(opening)
    );

    let mut body = plaintext;
    symmetric_apply_audit(&secret, AUDIT_STREAM_INFO, &mut body).expect("stream");
    let ciphertext = bytes::<ANONYMOUS_OUTPUT_PLAINTEXT_LEN>(&v["ciphertext"]);
    assert_eq!(body, ciphertext);
    symmetric_apply_audit(&secret, AUDIT_STREAM_INFO, &mut body).expect("stream");
    assert_eq!(body, plaintext);

    let published = anonymous_output_body(&ciphertext);
    assert_eq!(published, bytes::<105>(&v["body"]));
    assert_eq!(
        anonymous_output_body_hash(&published).expect("body hash"),
        bytes::<32>(&v["body_hash"])
    );
}

#[test]
fn noncanonical_blinding_alias_does_not_open() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector json");
    let mut plaintext = bytes::<ANONYMOUS_OUTPUT_PLAINTEXT_LEN>(&v["plaintext"]);
    plaintext[40..72].copy_from_slice(&[0xff; 32]);
    assert!(AnonymousOutputPlaintext::from_bytes(&plaintext).is_err());
}

/// The `statement` block of the vector, owned so the borrowed public input can be built from it.
struct BaseStatement {
    private_tx_hash: [u8; 32],
    tx_viewing_pk: [u8; 33],
    auditor_pk: [u8; 33],
    eph_pk: [u8; 33],
    ciphertext: [u8; 32],
    output_body_hashes: Vec<[u8; 32]>,
    output_hashes: Vec<[u8; 32]>,
    salt: [u8; 16],
    disclosure: Vec<[u8; 32]>,
    anonymous: bool,
}

impl BaseStatement {
    fn parse(s: &serde_json::Value) -> Self {
        Self {
            private_tx_hash: bytes(&s["private_tx_hash"]),
            tx_viewing_pk: bytes(&s["tx_viewing_pk"]),
            auditor_pk: bytes(&s["auditor_pk"]),
            eph_pk: bytes(&s["eph_pk"]),
            ciphertext: bytes(&s["audit_ciphertext"]),
            output_body_hashes: fields(&s["output_body_hashes"]),
            output_hashes: fields(&s["output_hashes"]),
            salt: bytes(&s["salt"]),
            disclosure: fields(&s["disclosure"]),
            anonymous: s["anonymous"].as_bool().expect("anonymous"),
        }
    }

    fn public_input(&self) -> CustomRingBasePublicInput<'_> {
        CustomRingBasePublicInput {
            private_tx_hash: &self.private_tx_hash,
            tx_viewing_pk: &self.tx_viewing_pk,
            auditor_pk: &self.auditor_pk,
            eph_pk: &self.eph_pk,
            ciphertext: &self.ciphertext,
            output_body_hashes: &self.output_body_hashes,
            output_hashes: &self.output_hashes,
            salt: &self.salt,
            disclosure: &self.disclosure,
            anonymous: self.anonymous,
        }
    }
}

#[test]
fn base_statement_follows_the_go_chain() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector json");
    let s = &v["statement"];
    let base = BaseStatement::parse(s);
    let statement = base.public_input();
    let padding = bytes::<105>(&s["padding_body"]);
    assert_eq!(
        base.output_body_hashes,
        [
            bytes::<32>(&v["body_hash"]),
            anonymous_output_body_hash(&padding).expect("padding hash")
        ]
    );
    let elements = statement.elements().expect("elements");
    assert_eq!(elements.to_vec(), fields(&s["elements"]));
    assert_eq!(
        elements[BODY_CHAIN_INDEX],
        create_hash_chain_4_from_slice(&base.output_body_hashes).expect("chain")
    );
    assert_eq!(
        statement.hash().expect("hash"),
        bytes::<32>(&s["public_input_hash"])
    );
}

/// The policy statement keeps the 13 base elements, body chain included, as its prefix.
#[test]
fn policy_statement_extends_the_go_base_chain() {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector json");
    let base = BaseStatement::parse(&v["statement"]);
    let p = &v["policy_statement"];
    let tree_slots: Vec<TreeSlot> = p["tree_slots"]
        .as_array()
        .expect("tree slots")
        .iter()
        .map(|slot| {
            TreeSlot::new(
                u16::try_from(slot["id"].as_u64().expect("tree id")).expect("u16 tree id"),
                bytes(&slot["utxo_root"]),
                bytes(&slot["nullifier_root"]),
            )
        })
        .collect();
    let ring_id = bytes::<32>(&p["ring_id"]);
    assert_eq!(
        ring_id,
        hash_bytes(&bytes::<32>(&v["ring_program_id"])).expect("ring id")
    );
    let policy = CustomRingPolicyPublicInput {
        audit: base.public_input(),
        policy_hash: &bytes(&p["policy_hash"]),
        tree_slots: &tree_slots,
        address_tree_id: u16::try_from(p["address_tree_id"].as_u64().expect("address tree"))
            .expect("u16 address tree"),
        ring_id: &ring_id,
        namespace_owner_hash: &bytes(&p["namespace_owner_hash"]),
        approval_required: p["approval_required"].as_bool().expect("approval"),
        key_escrow: p["key_escrow"].as_bool().expect("escrow"),
        member_registry_root: &bytes(&p["member_registry_root"]),
        foreign_root: &bytes(&p["foreign_root"]),
    };
    let elements = policy.elements().expect("elements");
    assert_eq!(elements.len(), POLICY_PUBLIC_INPUT_ELEMENTS);
    assert_eq!(elements.to_vec(), fields(&p["elements"]));
    assert_eq!(
        elements[..BASE_PUBLIC_INPUT_ELEMENTS],
        base.public_input().elements().expect("base elements")
    );
    assert_eq!(
        policy.hash().expect("hash"),
        bytes::<32>(&p["public_input_hash"])
    );
    let indexed = policy.indexed_inputs().expect("indexed");
    assert_eq!(indexed.len(), POLICY_INDEXED_INPUTS);
    assert_eq!(
        indexed[0],
        create_hash_chain_from_slice(&elements[..BASE_PUBLIC_INPUT_ELEMENTS + 1]).expect("fold")
    );
    assert_eq!(indexed[1..], elements[BASE_PUBLIC_INPUT_ELEMENTS + 2..]);
}
