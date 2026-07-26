//! Emits the adversarial key-certification corpus for suites K1 through K5 of
//! `planning/typescript-sdk-port/proof-and-key-parity.md`, and fails when the
//! committed file no longer matches what this crate produces.
//!
//! `parity_vectors.rs` records what the two languages do on well-formed input.
//! This file records what they do on input designed to separate a correct
//! implementation from a plausible one: every byte outside the two defined key
//! prefixes, points off the curve and coordinates at or above the field
//! modulus, scalars at the ends of the group, signatures with `r` or `s` at
//! zero or at the order, the high-`s` twin the deployed circuit accepts, the
//! non-canonical Ed25519 encodings the Solana runtime refuses, and the BN254
//! boundary a nullifier input must not cross.
//!
//! Every disposition is taken from the current crate rather than asserted here,
//! so a behaviour change breaks this test before it can be read as agreement.
//!
//! Regenerate with `UPDATE_KEY_CERTIFICATION_VECTORS=1 cargo test -p
//! zolana-keypair --test key_certification_vectors`.

use serde_json::{json, Map, Value};
use zolana_keypair::{
    constants::{BLINDING_LEN, DST_VIEW_ROOT_P_CONST, P256_PUBKEY_LEN, PUBLIC_KEY_LEN, P_CONST_SEC1},
    error::KeypairError,
    hash::{owner_hash, sha256, sha256_be},
    nullifier_key::NullifierKey,
    pubkey::{P256Pubkey, PublicKey},
    signing_key::SigningKey,
    viewing_key::ViewingKey,
};

const VECTOR_PATH: &str = "../ts/vectors/key-certification-v1.json";

/// The P-256 group order `n`. Secret scalars and both signature components are
/// valid strictly below it.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// The P-256 field modulus `p`. An x-coordinate at or above it is a
/// non-canonical SEC1 encoding rather than a point.
const P256_FIELD_MODULUS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// The BN254 scalar modulus. Poseidon inputs are field elements, so a UTXO hash
/// at or above it has no nullifier.
const BN254_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// RFC 8032 test key 1. The small-order `R` vector below is derived from it, and
/// `sdk-libs/ts/keypair/test/ed25519-acceptance.test.ts` rebuilds that vector
/// from this same secret rather than trusting the constant.
const ED25519_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// `R` is the identity point and `s = k * x mod L`, so the cofactored equation
/// accepts it and `verify_strict` refuses it for the small-order `R`.
const ED25519_SMALL_ORDER_R: &str = concat!(
    "0100000000000000000000000000000000000000000000000000000000000000",
    "756cf9b1d6f0d7a979b9d2af3dc2bc1294ec7cb6daa20eaff534c024fc57920f",
);

/// The Ed25519 group order `L`, little-endian, as `s` is encoded.
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn decode32(value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).expect("test hex");
    bytes
}

fn decode64(value: &str) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    hex::decode_to_slice(value, &mut bytes).expect("test hex");
    bytes
}

/// The same deterministic secret schedule `parity_vectors.rs` uses, so the two
/// corpora name the same keys.
fn secret32(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8).wrapping_mul(7) | 1;
    }
    bytes
}

fn variant(error: &KeypairError) -> &'static str {
    match error {
        KeypairError::InvalidPublicKey => "InvalidPublicKey",
        KeypairError::InvalidSecretKey => "InvalidSecretKey",
        KeypairError::ZeroScalar => "ZeroScalar",
        KeypairError::InvalidSignatureType(_) => "InvalidSignatureType",
        KeypairError::NotEd25519 => "NotEd25519",
        KeypairError::Hkdf => "Hkdf",
        KeypairError::Poseidon(_) => "Poseidon",
        KeypairError::FieldElementTooLong => "FieldElementTooLong",
        KeypairError::InvalidPrehashLength(_) => "InvalidPrehashLength",
        KeypairError::InfoTooLong => "InfoTooLong",
    }
}

fn disposition<T>(result: Result<T, KeypairError>) -> Value {
    match result {
        Ok(_) => json!({ "accepted": true }),
        Err(error) => json!({ "accepted": false, "variant": variant(&error) }),
    }
}

/// Big-endian 256-bit subtraction, used to build the high-`s` twin and the
/// "one below the modulus" boundaries. Byte arithmetic on a recorded value is
/// not a second implementation of a protocol formula.
fn u256_sub(left: &[u8; 32], right: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let diff = left[index] as i16 - right[index] as i16 - borrow;
        if diff < 0 {
            out[index] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[index] = diff as u8;
            borrow = 0;
        }
    }
    out
}

fn u256_add(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        out[index] = sum as u8;
        carry = sum >> 8;
    }
    out
}

fn u256_add_le(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = left[index] as u16 + right[index] as u16 + carry;
        out[index] = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// K1: every byte value in the scheme-tag position, both key bodies, and the
/// malformed P256 and Ed25519 bodies the parser must separate.
fn k1_public_keys() -> Value {
    let p256_public = SigningKey::from_bytes(&secret32(3))
        .expect("seeded p256 secret is in range")
        .pubkey();
    let ed_public = SigningKey::from_ed25519(&decode32(ED25519_SECRET)).pubkey();
    let p256_body = *p256_public.as_p256().expect("p256 rail").as_bytes();
    let mut ed_body = [0u8; P256_PUBKEY_LEN];
    ed_body[..32].copy_from_slice(&ed_public.as_ed25519().expect("ed25519 rail"));

    // Each sweep entry is `prefix || body`, so the body travels once and the 256
    // dispositions stay readable.
    let sweep = |body: &[u8; P256_PUBKEY_LEN]| -> Vec<Value> {
        (0..=255u8)
            .map(|prefix| {
                let mut bytes = [0u8; PUBLIC_KEY_LEN];
                bytes[0] = prefix;
                bytes[1..].copy_from_slice(body);
                json!({
                    "prefix": prefix,
                    "disposition": disposition(PublicKey::from_bytes(bytes)),
                })
            })
            .collect()
    };

    let even_y = P256Pubkey::from_bytes(p256_body).expect("recorded key parses");
    let mut off_curve = p256_body;
    off_curve[P256_PUBKEY_LEN - 1] ^= 0xff;
    let mut x_at_modulus = [0u8; P256_PUBKEY_LEN];
    x_at_modulus[0] = 0x02;
    x_at_modulus[1..].copy_from_slice(&P256_FIELD_MODULUS);
    let mut x_above_modulus = [0u8; P256_PUBKEY_LEN];
    x_above_modulus[0] = 0x02;
    x_above_modulus[1..].copy_from_slice(&u256_add(&P256_FIELD_MODULUS, &{
        let mut one = [0u8; 32];
        one[31] = 1;
        one
    }));
    let mut x_max = [0u8; P256_PUBKEY_LEN];
    x_max[0] = 0x02;
    x_max[1..].copy_from_slice(&[0xff; 32]);
    let mut x_zero = [0u8; P256_PUBKEY_LEN];
    x_zero[0] = 0x02;
    let mut uncompressed_prefix = p256_body;
    uncompressed_prefix[0] = 0x04;
    let mut sec1_zero_prefix = p256_body;
    sec1_zero_prefix[0] = 0x00;
    let mut flipped_parity = p256_body;
    flipped_parity[0] ^= 0x01;

    let points = [
        ("recordedKey", p256_body),
        ("flippedParityBit", flipped_parity),
        ("allZero", [0u8; P256_PUBKEY_LEN]),
        ("allOnes", [0xff; P256_PUBKEY_LEN]),
        ("offCurveX", off_curve),
        ("xZero", x_zero),
        ("xAtFieldModulus", x_at_modulus),
        ("xAboveFieldModulus", x_above_modulus),
        ("xAllOnes", x_max),
        ("uncompressedSec1Prefix", uncompressed_prefix),
        ("identitySec1Prefix", sec1_zero_prefix),
    ]
    .into_iter()
    .map(|(name, body)| {
        json!({
            "name": name,
            "bodyBytes": hex(&body),
            "disposition": disposition(P256Pubkey::from_bytes(body)),
        })
    })
    .collect::<Vec<_>>();

    // The Ed25519 body is 32 bytes inside a 33-byte slot, so byte 33 is padding
    // the parser must require to be zero.
    let ed_bodies = (0..=2u8)
        .map(|padding| {
            let mut body = ed_body;
            body[P256_PUBKEY_LEN - 1] = padding;
            let mut bytes = [0u8; PUBLIC_KEY_LEN];
            bytes[0] = 1;
            bytes[1..].copy_from_slice(&body);
            json!({
                "paddingByte": padding,
                "bodyBytes": hex(&body),
                "disposition": disposition(PublicKey::from_bytes(bytes)),
            })
        })
        .collect::<Vec<_>>();

    let mut zero_ed_body = [0u8; P256_PUBKEY_LEN];
    zero_ed_body[0] = 0;
    let mut zero_ed = [0u8; PUBLIC_KEY_LEN];
    zero_ed[0] = 1;
    zero_ed[1..].copy_from_slice(&zero_ed_body);

    json!({
        "taggedLength": PUBLIC_KEY_LEN,
        "p256BodyLength": P256_PUBKEY_LEN,
        "p256BodyBytes": hex(&p256_body),
        "ed25519BodyBytes": hex(&ed_body),
        "p256TaggedBytes": hex(p256_public.as_bytes()),
        "ed25519TaggedBytes": hex(ed_public.as_bytes()),
        "p256PrefixSweep": sweep(&p256_body),
        "ed25519PrefixSweep": sweep(&ed_body),
        "p256Points": points,
        "ed25519Padding": ed_bodies,
        // An all-zero Ed25519 body is not a curve point, and the parser does not
        // look: only the P256 rail validates its body.
        "ed25519ZeroBodyDisposition": disposition(PublicKey::from_bytes(zero_ed)),
        "p256RoundTripBytes": hex(
            PublicKey::from_bytes(*p256_public.as_bytes())
                .expect("round trip")
                .as_bytes(),
        ),
        "ed25519RoundTripBytes": hex(
            PublicKey::from_bytes(*ed_public.as_bytes())
                .expect("round trip")
                .as_bytes(),
        ),
        "p256XBytes": hex(&even_y.x()),
        "p256YIsOdd": even_y.y_is_odd(),
        "zeroedTaggedBytes": hex(PublicKey::zeroed().as_bytes()),
        // `zeroed()` reads as the P256 prefix, so the dummy owner and a real
        // P256 owner are separated by `is_zero`, not by the tag.
        "zeroedSignatureType": PublicKey::zeroed().signature_type().map(u8::from).ok(),
        "zeroedParsesAsKey": PublicKey::from_bytes(*PublicKey::zeroed().as_bytes()).is_ok(),
    })
}

/// K2: the P256 scalar domain, the signature corpus, and the high-`s` policy
/// ruled in `authority-rulings.md` (G2-1).
fn k2_p256_signatures() -> Value {
    let secret = secret32(3);
    let key = SigningKey::from_bytes(&secret).expect("seeded p256 secret is in range");
    let other = SigningKey::from_bytes(&secret32(5)).expect("seeded p256 secret is in range");

    let mut one = [0u8; 32];
    one[31] = 1;
    let max = u256_sub(&P256_ORDER, &one);
    let above_order = u256_add(&P256_ORDER, &one);
    let scalars = [
        ("one", one),
        ("orderMinusOne", max),
        ("zero", [0u8; 32]),
        ("order", P256_ORDER),
        ("orderPlusOne", above_order),
        ("allOnes", [0xff; 32]),
    ]
    .into_iter()
    .map(|(name, bytes)| {
        json!({
            "name": name,
            "secretBytes": hex(&bytes),
            "disposition": disposition(SigningKey::from_bytes(&bytes).map(|_| ())),
            "publicKeyBytes": SigningKey::from_bytes(&bytes)
                .ok()
                .map(|key| hex(key.pubkey().as_bytes())),
        })
    })
    .collect::<Vec<_>>();

    // RFC 6979 fixes `k`, so which half `s` lands in is a property of the digest
    // and not of the signer. A port that normalizes `s` diverges on the entries
    // marked high here, which is exactly what G2-1 ruled against.
    let half_order = {
        let mut half = [0u8; 32];
        let mut carry = 0u16;
        for index in 0..32 {
            let value = (carry << 8) | P256_ORDER[index] as u16;
            half[index] = (value >> 1) as u8;
            carry = value & 1;
        }
        half
    };
    let digest_sweep = (0..16u8)
        .map(|index| {
            let digest = sha256(format!("k2/digest/{index}").as_bytes());
            let signature = key.sign(&digest);
            json!({
                "digestBytes": hex(&digest),
                "signatureBytes": hex(&signature),
                "sIsHigh": signature[32..] > half_order[..],
                "verified": key.verify(&digest, &signature),
            })
        })
        .collect::<Vec<_>>();

    let digest = sha256(b"k2/canonical");
    let signature = key.sign(&digest);
    let mut high_s = signature;
    high_s[32..].copy_from_slice(&u256_sub(&P256_ORDER, &signature[32..]));
    let mut r_zero = signature;
    r_zero[..32].fill(0);
    let mut s_zero = signature;
    s_zero[32..].fill(0);
    let mut r_at_order = signature;
    r_at_order[..32].copy_from_slice(&P256_ORDER);
    let mut s_at_order = signature;
    s_at_order[32..].copy_from_slice(&P256_ORDER);
    let mut s_above_order = signature;
    s_above_order[32..].copy_from_slice(&above_order);
    let mut flipped_r = signature;
    flipped_r[0] ^= 0x01;
    let mut flipped_s = signature;
    flipped_s[63] ^= 0x01;

    let cases = [
        ("canonical", digest, signature),
        ("highSTwin", digest, high_s),
        ("rZero", digest, r_zero),
        ("sZero", digest, s_zero),
        ("rAtOrder", digest, r_at_order),
        ("sAtOrder", digest, s_at_order),
        ("sAboveOrder", digest, s_above_order),
        ("allZero", digest, [0u8; 64]),
        ("allOnes", digest, [0xff; 64]),
        ("flippedRBit", digest, flipped_r),
        ("flippedSBit", digest, flipped_s),
        ("wrongDigest", sha256(b"k2/other"), signature),
        ("zeroDigest", [0u8; 32], signature),
        ("maxDigest", [0xff; 32], signature),
    ]
    .into_iter()
    .map(|(name, message, candidate)| {
        json!({
            "name": name,
            "digestBytes": hex(&message),
            "signatureBytes": hex(&candidate),
            "verified": key.verify(&message, &candidate),
        })
    })
    .collect::<Vec<_>>();

    // A digest is an opaque 32-byte prehash on this rail, so nothing refuses one
    // at or above the group order. The signer still has to decide what to feed
    // the RFC 6979 nonce derivation, and that decision is only observable here:
    // `matchesReducedDigestSignature` says whether signing the digest and
    // signing the digest reduced modulo `n` give the same bytes.
    let digest_boundaries = [
        ("zero", [0u8; 32]),
        ("one", one),
        ("orderMinusOne", max),
        ("order", P256_ORDER),
        ("orderPlusOne", above_order),
        ("allOnes", [0xff; 32]),
    ]
    .into_iter()
    .map(|(name, message)| {
        let below_order = message < P256_ORDER;
        let reduced = if below_order {
            message
        } else {
            u256_sub(&message, &P256_ORDER)
        };
        let produced = key.sign(&message);
        json!({
            "name": name,
            "digestBytes": hex(&message),
            "belowOrder": below_order,
            "reducedDigestBytes": hex(&reduced),
            "signatureBytes": hex(&produced),
            "verified": key.verify(&message, &produced),
            "verifiedUnderReducedDigest": key.verify(&reduced, &produced),
            "matchesReducedDigestSignature": produced == key.sign(&reduced),
        })
    })
    .collect::<Vec<_>>();

    let ed_signature = SigningKey::from_ed25519(&decode32(ED25519_SECRET)).sign(&digest);

    json!({
        "orderBytes": hex(&P256_ORDER),
        "halfOrderBytes": hex(&half_order),
        "fieldModulusBytes": hex(&P256_FIELD_MODULUS),
        "keySecretBytes": hex(&secret),
        "keyPublicKeyBytes": hex(key.pubkey().as_bytes()),
        "otherKeySecretBytes": hex(&secret32(5)),
        "otherKeyPublicKeyBytes": hex(other.pubkey().as_bytes()),
        "scalars": scalars,
        "digestSweep": digest_sweep,
        "signatureCases": cases,
        "digestBoundaries": digest_boundaries,
        "canonicalDigestBytes": hex(&digest),
        "canonicalSignatureBytes": hex(&signature),
        "otherKeyVerifiesCanonical": other.verify(&digest, &signature),
        "wrongRailSignatureBytes": hex(&ed_signature),
        "wrongRailVerified": key.verify(&digest, &ed_signature),
        // G2-1: the deployed gadget range-checks `s` against the order alone.
        "acceptsHighS": key.verify(&digest, &high_s),
        "prehashLengths": [
            {"length": 0, "disposition": disposition(key.try_sign(&[]))},
            {"length": 31, "disposition": disposition(key.try_sign(&digest[..31]))},
            {"length": 32, "disposition": disposition(key.try_sign(&digest))},
            {"length": 33, "disposition": disposition(key.try_sign(&[7u8; 33]))},
            {"length": 64, "disposition": disposition(key.try_sign(&[7u8; 64]))},
        ],
    })
}

/// K3: the Ed25519 acceptance policy ruled in `authority-rulings.md` (G2-2),
/// which is the Solana runtime's `verify_strict`.
fn k3_ed25519_signatures() -> Value {
    let secret = decode32(ED25519_SECRET);
    let key = SigningKey::from_ed25519(&secret);
    let other = SigningKey::from_ed25519(&secret32(9));

    let messages = [
        ("empty", Vec::new()),
        ("single", vec![0x2a]),
        ("digestWidth", sha256(b"k3/message").to_vec()),
        ("long", (0..1000u32).map(|index| index as u8).collect()),
    ]
    .into_iter()
    .map(|(name, message)| {
        let signature = key.sign(&message);
        json!({
            "name": name,
            "messageBytes": hex(&message),
            "signatureBytes": hex(&signature),
            "verified": key.verify(&message, &signature),
        })
    })
    .collect::<Vec<_>>();

    let signature = key.sign(&[]);
    let small_order_r = decode64(ED25519_SMALL_ORDER_R);
    let mut non_canonical_r = signature;
    // `y = p + 3`, which decodes to a full-order point rather than being refused
    // at parse time, so only the byte comparison against `R` rejects it.
    non_canonical_r[..32].copy_from_slice(&decode32(
        "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    let mut s_at_order = signature;
    s_at_order[32..].copy_from_slice(&ED25519_ORDER_LE);
    let mut s_plus_order = signature;
    let mut low = [0u8; 32];
    low.copy_from_slice(&signature[32..]);
    s_plus_order[32..].copy_from_slice(&u256_add_le(&low, &ED25519_ORDER_LE));
    let mut flipped_s = signature;
    flipped_s[32] ^= 0x01;
    let mut flipped_r = signature;
    flipped_r[0] ^= 0x01;

    let cases = [
        ("canonical", Vec::new(), signature),
        ("smallOrderR", Vec::new(), small_order_r),
        ("nonCanonicalR", Vec::new(), non_canonical_r),
        ("sAtOrder", Vec::new(), s_at_order),
        ("sPlusOrder", Vec::new(), s_plus_order),
        ("flippedRBit", Vec::new(), flipped_r),
        ("flippedSBit", Vec::new(), flipped_s),
        ("allZero", Vec::new(), [0u8; 64]),
        ("allOnes", Vec::new(), [0xff; 64]),
        ("wrongMessage", vec![0x2a], signature),
    ]
    .into_iter()
    .map(|(name, message, candidate)| {
        json!({
            "name": name,
            "messageBytes": hex(&message),
            "signatureBytes": hex(&candidate),
            "verified": key.verify(&message, &candidate),
        })
    })
    .collect::<Vec<_>>();

    let p256_signature = SigningKey::from_bytes(&secret32(3))
        .expect("seeded p256 secret is in range")
        .sign(&sha256(b"k3/prehash"));

    json!({
        "acceptancePolicy": "ed25519_dalek::VerifyingKey::verify_strict",
        "orderLittleEndianBytes": hex(&ED25519_ORDER_LE),
        "secretBytes": hex(&secret),
        "taggedPublicKeyBytes": hex(key.pubkey().as_bytes()),
        "rawPublicKeyBytes": hex(&key.pubkey().as_ed25519().expect("ed25519 rail")),
        "otherSecretBytes": hex(&secret32(9)),
        "otherTaggedPublicKeyBytes": hex(other.pubkey().as_bytes()),
        "messages": messages,
        "signatureCases": cases,
        "otherKeyVerifiesCanonical": other.verify(&[], &signature),
        "wrongRailSignatureBytes": hex(&p256_signature),
        "wrongRailVerified": key.verify(&[], &p256_signature),
        // A small-order or non-canonically encoded public key cannot reach this
        // helper: it derives the verifying key from the secret.
        "publicKeyIsDerivedFromSecret": true,
    })
}

/// K4: nullifier derivation, its BN254 input boundary, and the binding of the
/// nullifier secret into the owner hash.
fn k4_nullifiers() -> Value {
    let signing = SigningKey::from_bytes(&secret32(3)).expect("seeded p256 secret is in range");
    let key = NullifierKey::from_signing_key(&signing).expect("hkdf");
    let other = NullifierKey::from_secret([5u8; BLINDING_LEN]);
    let utxo_hash = sha256_be(b"k4/utxo");

    let derivations = [
        ("recorded", utxo_hash, [3u8; BLINDING_LEN]),
        ("zeroBlinding", utxo_hash, [0u8; BLINDING_LEN]),
        ("maxBlinding", utxo_hash, [0xff; BLINDING_LEN]),
        ("zeroUtxoHash", [0u8; 32], [3u8; BLINDING_LEN]),
    ]
    .into_iter()
    .map(|(name, hash, blinding)| {
        json!({
            "name": name,
            "utxoHashBytes": hex(&hash),
            "blindingBytes": hex(&blinding),
            "nullifierBytes": hex(&key.nullifier(&hash, &blinding).expect("field inputs")),
        })
    })
    .collect::<Vec<_>>();

    let mut one = [0u8; 32];
    one[31] = 1;
    let modulus_minus_one = u256_sub(&BN254_MODULUS, &one);
    let modulus_plus_one = u256_add(&BN254_MODULUS, &one);
    let field_boundary = [
        ("modulusMinusOne", modulus_minus_one),
        ("modulus", BN254_MODULUS),
        ("modulusPlusOne", modulus_plus_one),
        ("allOnes", [0xff; 32]),
    ]
    .into_iter()
    .map(|(name, hash)| {
        json!({
            "name": name,
            "utxoHashBytes": hex(&hash),
            "disposition": disposition(key.nullifier(&hash, &[3u8; BLINDING_LEN])),
        })
    })
    .collect::<Vec<_>>();

    let public = signing.pubkey();
    json!({
        "bn254ModulusBytes": hex(&BN254_MODULUS),
        "signingSecretBytes": hex(&secret32(3)),
        "nullifierSecretBytes": hex(key.secret()),
        "nullifierPublicKeyBytes": hex(&key.pubkey().expect("field input")),
        "otherNullifierSecretBytes": hex(other.secret()),
        "otherNullifierPublicKeyBytes": hex(&other.pubkey().expect("field input")),
        "derivations": derivations,
        "fieldBoundary": field_boundary,
        "ownerPkFieldBytes": hex(&public.owner_pk_field().expect("owner field")),
        "ownerHashBytes": hex(
            &owner_hash(&public, &key.pubkey().expect("field input")).expect("owner hash"),
        ),
        // The owner hash commits to the nullifier public key, so a second
        // nullifier key under the same signing key is a different owner.
        "ownerHashWithOtherNullifierBytes": hex(
            &owner_hash(&public, &other.pubkey().expect("field input")).expect("owner hash"),
        ),
        "repeatsIdentically": NullifierKey::from_signing_key(&signing).expect("hkdf").secret()
            == key.secret(),
        "secretLength": BLINDING_LEN,
    })
}

/// K5: `P_const`, the view-tag streams at their counter boundaries, viewing
/// epochs, and the transaction viewing key.
fn k5_viewing_keys() -> Value {
    let key = ViewingKey::from_bytes(&secret32(11)).expect("seeded p256 secret is in range");
    let counterparty = ViewingKey::from_bytes(&secret32(23)).expect("seeded p256 secret is in range");
    let stranger = ViewingKey::from_bytes(&secret32(37)).expect("seeded p256 secret is in range");

    let counters = [0u64, 1, 2, 255, 256, u64::from(u32::MAX), 1 << 63, u64::MAX];
    let tags = counters
        .iter()
        .map(|counter| {
            json!({
                "counter": counter.to_string(),
                "senderBytes": hex(&key.get_sender_view_tag(*counter).expect("hkdf")),
                "recipientRequestBytes": hex(
                    &key.get_recipient_request_view_tag(*counter).expect("hkdf"),
                ),
                "mergeBytes": hex(&key.get_merge_view_tag(*counter).expect("hkdf")),
                "sendSharedBytes": hex(
                    &key.get_send_shared_view_tag(&counterparty.pubkey(), *counter).expect("hkdf"),
                ),
                "recipientSharedBytes": hex(
                    &key.get_recipient_shared_view_tag(&counterparty.pubkey(), *counter)
                        .expect("hkdf"),
                ),
                "strangerSendSharedBytes": hex(
                    &key.get_send_shared_view_tag(&stranger.pubkey(), *counter).expect("hkdf"),
                ),
            })
        })
        .collect::<Vec<_>>();

    // A rotated viewing epoch is a new account index under the same wallet seed.
    let epochs = [0u32, 1, 2, 7, 65_536, u32::MAX]
        .into_iter()
        .map(|account| {
            let derived = ViewingKey::from_seed(&secret32(31), account).expect("hkdf");
            json!({
                "account": account,
                "secretBytes": hex(derived.secret_bytes().as_slice()),
                "publicKeyBytes": hex(derived.pubkey().as_bytes()),
                "senderTagBytes": hex(&derived.get_sender_view_tag(0).expect("hkdf")),
            })
        })
        .collect::<Vec<_>>();

    // `from_seed` reduces a 48-byte HKDF output to a scalar. The corpus spans
    // seed and account values so a port that reduces differently diverges here
    // rather than at a boundary no test reaches.
    let okm_derivations = (0..24u8)
        .map(|index| {
            let seed = secret32(index.wrapping_mul(11).wrapping_add(3));
            let account = u32::from(index) * 0x0101_0101;
            let derived = ViewingKey::from_seed(&seed, account).expect("hkdf");
            json!({
                "seedBytes": hex(&seed),
                "account": account,
                "secretBytes": hex(derived.secret_bytes().as_slice()),
            })
        })
        .collect::<Vec<_>>();

    let mut one = [0u8; 32];
    one[31] = 1;
    let transaction_keys = [
        ("recorded", sha256_be(b"k5/nullifier")),
        ("zero", [0u8; 32]),
        ("allOnes", [0xff; 32]),
        ("bn254ModulusMinusOne", u256_sub(&BN254_MODULUS, &one)),
    ]
    .into_iter()
    .map(|(name, first_nullifier)| {
        let derived = key
            .get_transaction_viewing_key(&first_nullifier)
            .expect("hkdf");
        json!({
            "name": name,
            "firstNullifierBytes": hex(&first_nullifier),
            "secretBytes": hex(derived.secret_bytes().as_slice()),
            "publicKeyBytes": hex(derived.pubkey().as_bytes()),
        })
    })
    .collect::<Vec<_>>();

    let first_nullifier = sha256_be(b"k5/nullifier");
    let transaction = key
        .get_transaction_viewing_key(&first_nullifier)
        .expect("hkdf");
    let repeated = key
        .get_transaction_viewing_key(&first_nullifier)
        .expect("hkdf");

    json!({
        "pConstSec1Bytes": hex(&P_CONST_SEC1),
        "pConstDstBytes": hex(DST_VIEW_ROOT_P_CONST),
        "pConstSuite": "P256_XMD:SHA-256_SSWU_RO_",
        "pConstMessageBytes": "",
        "secretBytes": hex(&secret32(11)),
        "publicKeyBytes": hex(key.pubkey().as_bytes()),
        "counterpartySecretBytes": hex(&secret32(23)),
        "counterpartyPublicKeyBytes": hex(counterparty.pubkey().as_bytes()),
        "strangerSecretBytes": hex(&secret32(37)),
        "strangerPublicKeyBytes": hex(stranger.pubkey().as_bytes()),
        "ecdhBytes": hex(&key.ecdh(&counterparty.pubkey()).expect("ecdh")),
        "ecdhStrangerBytes": hex(&key.ecdh(&stranger.pubkey()).expect("ecdh")),
        "ecdhWithPConstBytes": hex(
            &key.ecdh(&P256Pubkey::from_bytes(P_CONST_SEC1).expect("committed P_const")).expect("ecdh"),
        ),
        "bootstrapTagBytes": hex(&key.recipient_bootstrap_view_tag()),
        "tags": tags,
        "epochs": epochs,
        "seedBytes": hex(&secret32(31)),
        "okmDerivations": okm_derivations,
        "transactionKeys": transaction_keys,
        // The transaction viewing key is a function of the first nullifier
        // alone, so a retry that respends the same first input reuses it; a
        // nullifier is spendable once, which is what keeps the key single-use.
        "transactionKeyRepeatsForSameNullifier": transaction.secret_bytes() == repeated.secret_bytes(),
        "transactionKeyDiffersFromBase": transaction.secret_bytes() != key.secret_bytes(),
        "sharedTagDirectionsAgree": key
            .get_send_shared_view_tag(&counterparty.pubkey(), 42)
            .expect("hkdf")
            == counterparty
                .get_recipient_shared_view_tag(&key.pubkey(), 42)
                .expect("hkdf"),
        "strangerSharedTagDiffers": key
            .get_send_shared_view_tag(&counterparty.pubkey(), 42)
            .expect("hkdf")
            != key.get_send_shared_view_tag(&stranger.pubkey(), 42).expect("hkdf"),
        // Both languages define a zero-scalar error for the reduction, and
        // neither can be driven to it: HKDF would have to land on a multiple of
        // the group order.
        "zeroScalarReachable": false,
    })
}

fn document() -> Value {
    let mut root = Map::new();
    root.insert("schema".into(), json!("zolana-key-certification-v1"));
    root.insert(
        "source".into(),
        json!("sdk-libs/keypair/tests/key_certification_vectors.rs"),
    );
    root.insert(
        "note".into(),
        json!(
            "Adversarial key-certification corpus for suites K1-K5. Every \
             disposition is produced by the current zolana-keypair crate. \
             Regenerate with UPDATE_KEY_CERTIFICATION_VECTORS=1."
        ),
    );
    root.insert("k1PublicKeys".into(), k1_public_keys());
    root.insert("k2P256Signatures".into(), k2_p256_signatures());
    root.insert("k3Ed25519Signatures".into(), k3_ed25519_signatures());
    root.insert("k4Nullifiers".into(), k4_nullifiers());
    root.insert("k5ViewingKeys".into(), k5_viewing_keys());
    Value::Object(root)
}

#[test]
fn committed_vectors_match_current_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTOR_PATH);
    let generated = format!("{}\n", serde_json::to_string_pretty(&document()).unwrap());

    if std::env::var_os("UPDATE_KEY_CERTIFICATION_VECTORS").is_some() {
        std::fs::write(&path, &generated).expect("write certification vectors");
        return;
    }

    let committed = std::fs::read_to_string(&path).expect(
        "sdk-libs/ts/vectors/key-certification-v1.json is missing; regenerate with \
         UPDATE_KEY_CERTIFICATION_VECTORS=1",
    );
    assert_eq!(
        committed, generated,
        "committed certification vectors drifted from the current Rust crate",
    );
}
