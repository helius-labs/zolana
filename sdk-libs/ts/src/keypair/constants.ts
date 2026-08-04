export const BLINDING_LENGTH = 31;
export const SALT_LENGTH = 16;
export const P256_PUBLIC_KEY_LENGTH = 33;
export const SHIELDED_PUBLIC_KEY_LENGTH = 34;
export const VIEW_TAG_LENGTH = 32;

export const DST_VIEW_ROOT = "TSPP/view_root/P_const/v1";
export const P_CONST_SEC1 = Uint8Array.from([
  0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1, 0x33, 0xd2, 0xb0,
  0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe, 0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc,
  0xdb,
]);

export const INFO_NULLIFIER = "TSPP/nullifier";
export const INFO_MERGE_VIEW_TAG_SECRET = "TSPP/merge_view_tag";
export const INFO_TX_VIEWING = "TSPP/tx_viewing";
export const INFO_MERGE_VIEW_TAG_PREFIX = "TSPP/merge_view_tag/";
export const HPKE_PREFIX = "TSPP/hpke/";
export const ENC_INFO_TRANSFER = "TSPP/tx";
