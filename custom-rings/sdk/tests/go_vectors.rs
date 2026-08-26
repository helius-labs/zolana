//! Cross-language vectors: the host crypto recomputed in Go with the fixture of
//! `prover/server/circuits/custom_ring/circuit_test.go`
//! (crypto/ecdh P-256, iden3 Poseidon, crypto/aes CTR), which is the same host
//! computation whose witness that test solves against the compiled circuit.
//!
//! The three scalars are the Go test's `scalar(0x11)`, `scalar(0x22)` and
//! `scalar(0x33)`: byte `i` is `seed ^ i`, with byte 0 forced to 0x01 to stay
//! below the group order. Every expected value below was printed by the Go
//! implementation, so a divergence in either language fails this file.

use custom_ring_interface::{pack32_to_2fe, pack33_to_2fe, FieldPair};
use custom_ring_sdk::AuditorMessage;
use zolana_keypair::{P256Pubkey, ViewingKey};

const TX_SK: &str = "011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e";
const EPH_SK: &str = "01232021262724252a2b28292e2f2c2d32333031363734353a3b38393e3f3c3d";
const AUDITOR_SK: &str = "01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c";

const TX_PK: &str = "0268737cf1d852483220d399b5321261d5e9e90d8214dc62b4f7e4d0fee955c5d5";
const EPH_PK: &str = "038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a133c";
const AUDITOR_PK: &str = "039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b71dec";

const DH: &str = "0adc4a9b4fc9112518acab2c346559372e9a5c2a9d8b93fb1b7650ea1edd4823";
const DH_LO: &str = "000adc4a9b4fc9112518acab2c346559372e9a5c2a9d8b93fb1b7650ea1edd48";
const DH_HI: &str = "0000000000000000000000000000000000000000000000000000000000000023";
const EPH_LO: &str = "00038bd43dcdaea72a1db879b1ca6faac09593fd17893d22eeef926b5c1c245a";
const EPH_HI: &str = "000000000000000000000000000000000000000000000000000000000000133c";
const AUDITOR_LO: &str = "00039dc51b59006b13f143944d4e432db7c032241ceb3698a6cc0cdabadf29b7";
const AUDITOR_HI: &str = "0000000000000000000000000000000000000000000000000000000000001dec";

const CIPHERTEXT: &str = "6de7c18c3c3676ca517647a25df33a7150ace3e07b410bc296fac11b1355382b";

fn hex_bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    let decoded = hex::decode(hex_str).expect("valid hex");
    <[u8; N]>::try_from(decoded.as_slice()).expect("expected byte length")
}

fn viewing_key(hex_str: &str) -> ViewingKey {
    ViewingKey::from_bytes(&hex_bytes::<32>(hex_str)).expect("valid P-256 scalar")
}

fn pubkey(hex_str: &str) -> P256Pubkey {
    P256Pubkey::from_bytes(hex_bytes::<33>(hex_str)).expect("valid compressed key")
}

#[test]
fn compressed_public_keys_match_go() {
    assert_eq!(viewing_key(TX_SK).pubkey(), pubkey(TX_PK));
    assert_eq!(viewing_key(EPH_SK).pubkey(), pubkey(EPH_PK));
    assert_eq!(viewing_key(AUDITOR_SK).pubkey(), pubkey(AUDITOR_PK));
}

#[test]
fn ecdh_matches_go_in_both_directions() {
    let expected = hex_bytes::<32>(DH);
    assert_eq!(
        viewing_key(EPH_SK).ecdh(&pubkey(AUDITOR_PK)).expect("ecdh"),
        expected
    );
    assert_eq!(
        viewing_key(AUDITOR_SK).ecdh(&pubkey(EPH_PK)).expect("ecdh"),
        expected
    );
}

#[test]
fn packing_matches_go() {
    assert_eq!(
        pack32_to_2fe(&hex_bytes::<32>(DH)),
        FieldPair {
            lo: hex_bytes::<32>(DH_LO),
            hi: hex_bytes::<32>(DH_HI),
        }
    );
    assert_eq!(
        pack33_to_2fe(&hex_bytes::<33>(EPH_PK)),
        FieldPair {
            lo: hex_bytes::<32>(EPH_LO),
            hi: hex_bytes::<32>(EPH_HI),
        }
    );
    assert_eq!(
        pack33_to_2fe(&hex_bytes::<33>(AUDITOR_PK)),
        FieldPair {
            lo: hex_bytes::<32>(AUDITOR_LO),
            hi: hex_bytes::<32>(AUDITOR_HI),
        }
    );
}

#[test]
fn ciphertext_from_go_decrypts() {
    let expected = hex_bytes::<32>(CIPHERTEXT);
    let recovered = AuditorMessage::new(pubkey(EPH_PK), expected)
        .decrypt(&viewing_key(AUDITOR_SK))
        .expect("decrypt");
    assert_eq!(*recovered, hex_bytes::<32>(TX_SK));
}
