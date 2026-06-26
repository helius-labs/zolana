pub const PUBLIC_KEY_LEN: usize = 34;

pub const P256_PUBKEY_LEN: usize = 33;

pub const BLINDING_LEN: usize = 31;

pub(crate) const ED25519_PUBKEY_LEN: usize = 32;

pub(crate) const CTR_NONCE_LEN: usize = 12;

pub const SALT_LEN: usize = 16;

pub const DST_VIEW_ROOT_P_CONST: &[u8] = b"TSPP/view_root/P_const/v1";

pub const P_CONST_SEC1: [u8; P256_PUBKEY_LEN] = [
    0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1, 0x33, 0xd2, 0xb0,
    0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe, 0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc,
    0xdb,
];

pub(crate) const INFO_NULLIFIER: &[u8] = b"TSPP/nullifier";

pub(crate) const INFO_SENDER_VIEW_TAG_SECRET: &[u8] = b"TSPP/sender_view_tag";

pub(crate) const INFO_RECIPIENT_VIEW_TAG_SECRET: &[u8] = b"TSPP/recipient_view_tag";

pub(crate) const INFO_MERGE_VIEW_TAG_SECRET: &[u8] = b"TSPP/merge_view_tag";

pub(crate) const INFO_TX_VIEWING: &[u8] = b"TSPP/tx_viewing";

pub(crate) const INFO_SENDER_VIEW_TAG_PREFIX: &[u8] = b"TSPP/sender_view_tag/";

pub(crate) const INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX: &[u8] =
    b"TSPP/recipient_request_view_tag/";

pub(crate) const INFO_MERGE_VIEW_TAG_PREFIX: &[u8] = b"TSPP/merge_view_tag/";

pub(crate) const INFO_PAIR_DOMAIN_PREFIX: &[u8] = b"TSPP/pair-domain/";

pub(crate) const INFO_PAIR_HINT_PREFIX: &[u8] = b"TSPP/pair-hint/";

pub const VIEW_TAG_LEN: usize = 32;

pub(crate) const HPKE_PREFIX: &[u8] = b"TSPP/hpke/";

pub(crate) const ENC_INFO_TRANSFER: &[u8] = b"TSPP/tx";
