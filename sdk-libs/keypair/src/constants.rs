pub const PUBLIC_KEY_LEN: usize = 34;

pub const P256_PUBKEY_LEN: usize = 33;

pub const BLINDING_LEN: usize = 31;

pub(crate) const ED25519_PUBKEY_LEN: usize = 32;

pub(crate) const GCM_NONCE_LEN: usize = 12;

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

pub(crate) const VIEW_TAG_LEN: usize = 32;

pub(crate) const HPKE_PREFIX: &[u8] = b"TSPP/hpke/";

pub(crate) const ENC_INFO_TRANSFER: &[u8] = b"TSPP/tx";
