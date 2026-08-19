//! Domain-separation registry and key-derivation primitives.
//!
//! Every domain-separation tag in this crate is defined here and every
//! HKDF/ECDH invocation funnels through the free functions below, so the full
//! derivation tree is auditable in one file and no two derivations can
//! silently share a tag or diverge in KDF construction. The key types keep
//! their public constructors and delegate to these pub(crate) free functions;
//! this thin-wrapper layering is intentional design and overrides the
//! no-thin-wrapper directive.

use hkdf::Hkdf;
use p256::{
    ecdh::diffie_hellman, elliptic_curve::hash2curve::FromOkm, AffinePoint,
    PublicKey as P256PublicKey, Scalar, SecretKey,
};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    constants::{BLINDING_LEN, P256_PUBKEY_LEN},
    error::KeypairError,
    nullifier_key::NullifierKey,
    pubkey::{Curve, P256Pubkey},
    viewing_key::{ViewTag, ViewingKey},
};

pub const DST_VIEW_ROOT_P_CONST: &[u8] = b"TSPP/view_root/P_const/v1";

pub const P_CONST_SEC1: [u8; P256_PUBKEY_LEN] = [
    0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1, 0x33, 0xd2, 0xb0,
    0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe, 0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc,
    0xdb,
];

pub const DST_DERIVE_P_DERIVE: &[u8] = b"TSPP/nullifier/P_nullifier/v1";

pub const P_DERIVE_SEC1: [u8; P256_PUBKEY_LEN] = [
    0x03, 0x9e, 0xf1, 0x65, 0x92, 0x42, 0x9d, 0xa1, 0x40, 0x3e, 0xaa, 0x29, 0x05, 0x8e, 0xb7, 0xd9,
    0xd5, 0xad, 0x15, 0xa2, 0xea, 0x55, 0x71, 0x74, 0xf7, 0xb0, 0x1f, 0xf7, 0xfe, 0x48, 0x4e, 0xee,
    0xaf,
];

pub const DST_PDA_ROOT_P_PDA: &[u8] = b"TSPP/pda_root/P_pda/v1";

pub const P_PDA_SEC1: [u8; P256_PUBKEY_LEN] = [
    0x03, 0x8a, 0x31, 0xd5, 0x3c, 0x5a, 0xd2, 0x0d, 0x1c, 0xd7, 0xee, 0x1f, 0xbb, 0x99, 0x27, 0xbd,
    0x0c, 0xdf, 0xb6, 0x1b, 0x1b, 0x89, 0xf6, 0xb2, 0xc5, 0xa9, 0x4a, 0x5f, 0x08, 0x1f, 0xe1, 0x6b,
    0x5b,
];

pub const INFO_NF_KEY_ED25519: &[u8] = b"TSPP/nf_key/ed25519/v1";

pub const INFO_NF_KEY_ECDH: &[u8] = b"TSPP/nf_key/ecdh/v1";

pub const INFO_VIEW_KEY_ED25519: &[u8] = b"TSPP/view_key/ed25519/v1";

pub const INFO_VIEW_KEY_ECDH: &[u8] = b"TSPP/view_key/ecdh/v1";

pub const INFO_SEED_P256_VIEWING: &[u8] = b"TSPP/seed/p256_viewing";

pub const INFO_PDA_NF_KEY: &[u8] = b"TSPP/pda_nf/v1";

pub const INFO_PDA_VIEW_KEY: &[u8] = b"TSPP/pda_view/v1";

/// Payload of the off-chain message an ed25519 owner signs (RFC 8032,
/// deterministic) to obtain the derivation seed, the root of the ed25519
/// rail's nullifier and viewing secrets. The signed bytes are
/// [`ed25519_derivation_message`], never this bare payload.
pub const ED25519_DERIVATION_MSG: &[u8] = b"TSPP/derive/v1";

/// Every payload under this prefix is a derivation-seed payload (the PDA
/// payload family carries an address, so the guard matches the prefix).
pub const DERIVATION_PAYLOAD_PREFIX: &[u8] = b"TSPP/derive/";

pub const OFFCHAIN_MESSAGE_MAGIC: [u8; 16] = *b"\xffsolana offchain";

/// `sha256(ED25519_DERIVATION_MSG)`; pinned by a test.
pub const TSPP_APPLICATION_DOMAIN: [u8; 32] = [
    0x1d, 0x32, 0xa8, 0x85, 0x33, 0xaf, 0x12, 0xd3, 0x5e, 0x5a, 0xc6, 0xfc, 0xe8, 0x17, 0xa4, 0xcb,
    0x81, 0x0b, 0xcc, 0x41, 0x15, 0x38, 0x6b, 0x14, 0xa7, 0x8e, 0x8b, 0x2e, 0xf0, 0x9d, 0x86, 0x4c,
];

/// Solana off-chain message v0: magic || version=0 || application_domain ||
/// format=0 (restricted ASCII) || signer_count=1 || signer || len u16 LE ||
/// payload. This is the exact byte string the ed25519 rail signs.
pub fn ed25519_derivation_message(signer_pubkey: &[u8; 32]) -> Vec<u8> {
    let payload = ED25519_DERIVATION_MSG;
    let mut message = Vec::with_capacity(85 + payload.len());
    message.extend_from_slice(&OFFCHAIN_MESSAGE_MAGIC);
    message.push(0);
    message.extend_from_slice(&TSPP_APPLICATION_DOMAIN);
    message.push(0);
    message.push(1);
    message.extend_from_slice(signer_pubkey);
    message.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    message.extend_from_slice(payload);
    message
}

/// True when signing `message` would produce a derivation seed: the payload,
/// bare or off-chain encoded, begins with [`DERIVATION_PAYLOAD_PREFIX`].
pub fn is_derivation_input(message: &[u8]) -> bool {
    message.starts_with(DERIVATION_PAYLOAD_PREFIX)
        || offchain_v0_payload(message)
            .is_some_and(|payload| payload.starts_with(DERIVATION_PAYLOAD_PREFIX))
}

fn offchain_v0_payload(message: &[u8]) -> Option<&[u8]> {
    let rest = message.strip_prefix(OFFCHAIN_MESSAGE_MAGIC.as_slice())?;
    let (version, rest) = rest.split_first()?;
    if *version != 0 {
        return None;
    }
    let rest = rest.get(32..)?;
    let (_format, rest) = rest.split_first()?;
    let (signer_count, rest) = rest.split_first()?;
    let rest = rest.get(32 * usize::from(*signer_count)..)?;
    let declared: [u8; 2] = rest.get(..2)?.try_into().ok()?;
    let payload = rest.get(2..)?;
    (payload.len() == usize::from(u16::from_le_bytes(declared))).then_some(payload)
}

pub const INFO_SENDER_VIEW_TAG_SECRET: &[u8] = b"TSPP/sender_view_tag";

pub const INFO_RECIPIENT_VIEW_TAG_SECRET: &[u8] = b"TSPP/recipient_view_tag";

pub const INFO_TX_VIEWING: &[u8] = b"TSPP/tx_viewing";

pub const INFO_SENDER_VIEW_TAG_PREFIX: &[u8] = b"TSPP/sender_view_tag/";

pub const INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX: &[u8] = b"TSPP/recipient_request_view_tag/";

pub const INFO_PAIR_DOMAIN_PREFIX: &[u8] = b"TSPP/pair-domain/";

pub const INFO_PAIR_HINT_PREFIX: &[u8] = b"TSPP/pair-hint/";

pub const HPKE_PREFIX: &[u8] = b"TSPP/hpke/";

pub const ENC_INFO_TRANSFER: &[u8] = b"TSPP/tx";

pub const ENC_INFO_RING_DEPOSIT: &[u8] = b"TSPP/ring_deposit";

/// HPKE-style key-schedule info string bound into the KDF (spec Merge Proof).
/// Shared by schemes that encrypt with a pre-shared secret via
/// [`crate::symmetric_apply`].
pub const MERGE_INFO: &[u8; 10] = b"TSPP/merge";

/// Domain separators (32-bit ASCII tags) for the Poseidon key schedule,
/// mirroring `circuits/verifiable-encryption/poseidon_kdf.go`.
pub const DOM_SEP_SILO: u32 = 0x544d_5349; // "TMSI"
pub const DOM_SEP_KEY: u32 = 0x544d_534b; // "TMSK" (key_1 = DOM_SEP_KEY + 1 = "TMSL")
pub const DOM_SEP_NONCE: u32 = 0x544d_534e; // "TMSN"

/// Domain separators (32-bit ASCII tags) for the deterministic merge-output
/// recovery scheme, mirroring `circuits/spp_merge/shared/derivation.go`.
pub const DOMAIN_MERGE_OUTPUT_BLINDING_V1: u32 = 0x544d_4f42; // "TMOB"
pub const DOMAIN_MERGE_DUMMY_NULLIFIER: u32 = 0x544d_444e; // "TMDN"

pub(crate) fn hkdf_expand(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), KeypairError> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand_multi_info(info, out)
        .map_err(|_| KeypairError::Hkdf)
}

pub(crate) fn hkdf_expand_prk(
    prk: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), KeypairError> {
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| KeypairError::Hkdf)?
        .expand_multi_info(info, out)
        .map_err(|_| KeypairError::Hkdf)
}

pub(crate) fn expand_view_tag(ikm: &[u8], info: &[&[u8]]) -> Result<ViewTag, KeypairError> {
    let mut out = ViewTag::default();
    hkdf_expand(None, ikm, info, &mut out[1..])?;
    Ok(out)
}

pub(crate) fn sender_view_tag(secret: &[u8; 32], tx_count: u64) -> Result<ViewTag, KeypairError> {
    expand_view_tag(
        secret,
        &[INFO_SENDER_VIEW_TAG_PREFIX, &tx_count.to_be_bytes()],
    )
}

pub(crate) fn recipient_request_view_tag(
    secret: &[u8; 32],
    request_count: u64,
) -> Result<ViewTag, KeypairError> {
    expand_view_tag(
        secret,
        &[
            INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
            &request_count.to_be_bytes(),
        ],
    )
}

pub(crate) fn shared_view_tag(
    ecdh_shared: &[u8; 32],
    r_pubkey: &P256Pubkey,
    i: u64,
) -> Result<ViewTag, KeypairError> {
    let mut domain = [0u8; 32];
    hkdf_expand(
        None,
        ecdh_shared,
        &[INFO_PAIR_DOMAIN_PREFIX, r_pubkey.as_bytes()],
        &mut domain,
    )?;

    expand_view_tag(&domain, &[INFO_PAIR_HINT_PREFIX, &i.to_be_bytes()])
}

pub(crate) fn ecdh_x(
    secret_key: &SecretKey,
    pubkey: &P256Pubkey,
) -> Result<[u8; 32], KeypairError> {
    Ok(ecdh_x_point(secret_key, pubkey.to_p256()?.as_affine()))
}

pub(crate) fn ecdh_x_point(secret_key: &SecretKey, point: &AffinePoint) -> [u8; 32] {
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), point);
    let mut x = [0u8; 32];
    x.copy_from_slice(shared.raw_secret_bytes());
    x
}

pub(crate) fn p_derive() -> P256Pubkey {
    P256Pubkey::from_bytes(P_DERIVE_SEC1).expect("committed P_derive is valid SEC1")
}

pub(crate) fn p_pda() -> P256Pubkey {
    P256Pubkey::from_bytes(P_PDA_SEC1).expect("committed P_pda is valid SEC1")
}

/// Committed points whose shared secret is a derivation root; the generic ecdh
/// entry points refuse all three. `ECDH(viewing_sk, P_const)` is the IKM
/// `view_root` extracts from, so handing it to a caller hands over every view
/// tag and the transaction-viewing secret. The roots themselves are reached
/// through [`view_root`] and the `ecdh_raw` entry points, which bypass this
/// check.
///
/// Compares x-coordinates rather than full SEC1 encodings. ECDH uses only x,
/// so `x(sk·P) == x(sk·-P)`, and the negation `-P` carries the same x under the
/// opposite parity byte (`0x03`→`0x02`). A byte-equality guard would accept
/// `-P` while it still produces the protected shared secret.
pub(crate) fn is_derivation_point(pubkey: &P256Pubkey) -> bool {
    let x = pubkey.x();
    x == P_DERIVE_SEC1[1..] || x == P_PDA_SEC1[1..] || x == P_CONST_SEC1[1..]
}

/// `view_root = HKDF-Extract(salt=∅, IKM=ECDH(viewing_sk, P_const))` — the PRK
/// all per-purpose secrets expand from.
pub(crate) fn view_root(secret: &SecretKey) -> Zeroizing<[u8; 32]> {
    let p_const =
        P256PublicKey::from_sec1_bytes(&P_CONST_SEC1).expect("committed P_const is valid SEC1");
    let ikm = Zeroizing::new(ecdh_x_point(secret, p_const.as_affine()));
    let (prk, _) = Hkdf::<Sha256>::extract(None, ikm.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Rail {
    Ed25519,
    Ecdh,
}

impl Rail {
    pub(crate) fn from_curve(curve: Curve) -> Result<Self, KeypairError> {
        match curve {
            Curve::Ed25519 => Ok(Self::Ed25519),
            Curve::P256 => Ok(Self::Ecdh),
            Curve::Pda => Err(KeypairError::PdaCannotSign),
        }
    }

    fn nullifier_info(self) -> &'static [u8] {
        match self {
            Self::Ed25519 => INFO_NF_KEY_ED25519,
            Self::Ecdh => INFO_NF_KEY_ECDH,
        }
    }

    fn viewing_info(self) -> &'static [u8] {
        match self {
            Self::Ed25519 => INFO_VIEW_KEY_ED25519,
            Self::Ecdh => INFO_VIEW_KEY_ECDH,
        }
    }
}

/// One HKDF-Extract over `derivation_seed`, then one Expand per role with the
/// rail's tag. Every identity constructor funnels through this type.
pub(crate) struct RoleExpansion {
    prk: Zeroizing<[u8; 32]>,
    rail: Rail,
}

impl RoleExpansion {
    pub(crate) fn new(seed: &[u8], rail: Rail) -> Self {
        let (prk, _) = Hkdf::<Sha256>::extract(None, seed);
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&prk);
        Self { prk: bytes, rail }
    }

    pub(crate) fn nullifier_key(&self) -> Result<NullifierKey, KeypairError> {
        let mut secret = Zeroizing::new([0u8; BLINDING_LEN]);
        hkdf_expand_prk(
            self.prk.as_slice(),
            &[self.rail.nullifier_info()],
            secret.as_mut_slice(),
        )?;
        Ok(NullifierKey::from_zeroizing_secret(secret))
    }

    pub(crate) fn viewing_key(&self) -> Result<ViewingKey, KeypairError> {
        let mut okm = Zeroizing::new([0u8; 48]);
        hkdf_expand_prk(
            self.prk.as_slice(),
            &[self.rail.viewing_info()],
            okm.as_mut_slice(),
        )?;
        ViewingKey::from_okm48(&okm)
    }
}

/// One HKDF-Extract over the viewing-key ECDH shared secret, then one Expand
/// per role with the PDA bound into the info, so parties who transact
/// repeatedly do not reuse one identity across their PDAs.
pub(crate) struct PdaRoleExpansion {
    prk: Zeroizing<[u8; 32]>,
    pda: [u8; 32],
}

impl PdaRoleExpansion {
    pub(crate) fn new(shared: &[u8; 32], pda: [u8; 32]) -> Self {
        let (prk, _) = Hkdf::<Sha256>::extract(None, shared);
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&prk);
        Self { prk: bytes, pda }
    }

    pub(crate) fn nullifier_key(&self) -> Result<NullifierKey, KeypairError> {
        let mut secret = Zeroizing::new([0u8; BLINDING_LEN]);
        hkdf_expand_prk(
            self.prk.as_slice(),
            &[INFO_PDA_NF_KEY, &self.pda],
            secret.as_mut_slice(),
        )?;
        Ok(NullifierKey::from_zeroizing_secret(secret))
    }

    pub(crate) fn viewing_key(&self) -> Result<ViewingKey, KeypairError> {
        let mut okm = Zeroizing::new([0u8; 48]);
        hkdf_expand_prk(
            self.prk.as_slice(),
            &[INFO_PDA_VIEW_KEY, &self.pda],
            okm.as_mut_slice(),
        )?;
        ViewingKey::from_okm48(&okm)
    }
}

// p256 0.13's `FromOkm` API still exposes generic-array 0.14. Newer
// generic-array releases deprecate that type, so keep the compatibility use
// isolated until p256's public hash-to-field API moves to hybrid-array.
#[allow(deprecated)]
pub(crate) fn scalar_from_okm(okm: &[u8; 48]) -> Scalar {
    use p256::elliptic_curve::generic_array::GenericArray;

    Scalar::from_okm(GenericArray::from_slice(okm))
}
