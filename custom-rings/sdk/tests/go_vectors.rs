//! Cross-language vectors: the host crypto recomputed in Go with the fixture of
//! `prover/server/custom_rings/circuits/base/circuit_test.go`
//! (crypto/ecdh X25519, iden3 Poseidon, crypto/aes CTR), which is the same host
//! computation whose witness that test solves against the compiled circuit.
//!
//! The three scalars are the Go test's `scalar(0x11)`, `scalar(0x22)` and
//! `scalar(0x33)`: byte `i` is `seed ^ i`, with byte 0 forced to 0x01. The
//! transaction secret is clamped before publication and encryption. Every
//! expected value below was printed by the Go implementation, so a divergence
//! in either language fails this file.

use custom_ring_interface::{pack_2fe, FieldPair};
use zolana_keypair::{ViewingKey, X25519Pubkey, X25519Secret};
use zolana_ring_client::AuditorMessage;

const TX_SK: &str = "001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e";
const EPH_SK: &str = "01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d";
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

const TX_PK: &str = "043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63";
const EPH_PK: &str = "048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966";
const AUDITOR_PK: &str = "04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a";

const DH: &str = "464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c";
const DH_LO: &str = "00464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec9";
const DH_HI: &str = "000000000000000000000000000000000000000000000000000000000000002c";
const EPH_LO: &str = "00048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8eba";
const EPH_HI: &str = "000000000000000000000000000000000000000000000000000000000000a966";
const AUDITOR_LO: &str = "0004708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3";
const AUDITOR_HI: &str = "000000000000000000000000000000000000000000000000000000000000115a";

const CIPHERTEXT: &str = "da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90";

fn hex_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let decoded = hex::decode(hex_str).expect("valid hex");
    <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
}

fn viewing_key(hex_str: &str) -> ViewingKey {
    ViewingKey::from_canonical_bytes(&hex_bytes::<32>(hex_str)).expect("canonical X25519 secret")
}

fn pubkey(hex_str: &str) -> X25519Pubkey {
    X25519Pubkey::from_bytes(hex_bytes::<33>(hex_str)).expect("valid tagged key")
}

#[test]
fn tagged_public_keys_match_go() {
    assert_eq!(viewing_key(TX_SK).pubkey(), pubkey(TX_PK));
    assert_eq!(envelope_key(EPH_SK).pubkey(), envelope_pubkey(EPH_PK));
    assert_eq!(
        envelope_key(AUDITOR_SK).pubkey(),
        envelope_pubkey(AUDITOR_PK)
    );
}

#[test]
fn ecdh_matches_go_in_both_directions() {
    let expected = hex_bytes::<32>(DH);
    assert_eq!(
        *envelope_key(EPH_SK)
            .ecdh(&envelope_pubkey(AUDITOR_PK))
            .expect("ecdh"),
        expected
    );
    assert_eq!(
        *envelope_key(AUDITOR_SK)
            .ecdh(&envelope_pubkey(EPH_PK))
            .expect("ecdh"),
        expected
    );
}

#[test]
fn packing_matches_go() {
    assert_eq!(
        pack_2fe(&hex_bytes::<32>(DH)),
        FieldPair {
            lo: hex_bytes::<32>(DH_LO),
            hi: hex_bytes::<32>(DH_HI),
        }
    );
    assert_eq!(
        pack_2fe(&hex_bytes::<33>(EPH_PK)),
        FieldPair {
            lo: hex_bytes::<32>(EPH_LO),
            hi: hex_bytes::<32>(EPH_HI),
        }
    );
    assert_eq!(
        pack_2fe(&hex_bytes::<33>(AUDITOR_PK)),
        FieldPair {
            lo: hex_bytes::<32>(AUDITOR_LO),
            hi: hex_bytes::<32>(AUDITOR_HI),
        }
    );
}

#[test]
fn ciphertext_from_go_decrypts() {
    let expected = hex_bytes::<32>(CIPHERTEXT);
    let recovered = AuditorMessage::new(envelope_pubkey(EPH_PK), expected)
        .decrypt(&envelope_key(AUDITOR_SK))
        .expect("decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));
}

fn envelope_key(s: &str) -> X25519Secret {
    X25519Secret::from_bytes(&hex_bytes::<32>(s)).unwrap()
}
fn envelope_pubkey(s: &str) -> X25519Pubkey {
    X25519Pubkey::from_bytes(hex_bytes::<33>(s)).unwrap()
}

/// The zero-disclosure base statement, the TypeScript SDK and the Go revocation vector pin it.
#[test]
fn base_public_input_includes_the_ring_mode() {
    let statement = custom_ring_interface::CustomRingBasePublicInput {
        private_tx_hash: &hex_bytes::<32>(
            "0000000000000000000000000000000000000000000000000000000000abcdef",
        ),
        tx_viewing_pk: &hex_bytes::<33>(TX_PK),
        auditor_pk: &hex_bytes::<33>(AUDITOR_PK),
        eph_pk: &hex_bytes::<33>(EPH_PK),
        ciphertext: &hex_bytes::<32>(CIPHERTEXT),
        output_hashes: &[[0; 32]],
        salt: &[0; 16],
        disclosure: &[[0; 32]; custom_ring_interface::AUDIT_DISCLOSURE_FIELD_COUNT],
        anonymous: false,
    };
    let hash = statement.hash().unwrap();
    assert_eq!(
        hash,
        hex_bytes::<32>("291c6025244409748c719079f396ec892db1764098323df8f3a685ae5d7a3a22")
    );
    assert_ne!(
        hash,
        custom_ring_interface::CustomRingBasePublicInput {
            anonymous: true,
            ..statement
        }
        .hash()
        .unwrap()
    );
}
