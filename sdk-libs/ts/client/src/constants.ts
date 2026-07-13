import { PublicKey } from "@solana/web3.js";

export const PUBLIC_KEY_LEN = 34;
export const P256_PUBKEY_LEN = 33;
export const ED25519_PUBKEY_LEN = 32;
export const BLINDING_LEN = 31;
export const SALT_LEN = 16;
export const VIEW_TAG_LEN = 32;
export const CTR_NONCE_LEN = 12;

export const UTXO_DOMAIN = 1;

export const SHIELDED_POOL_PROGRAM_ID = new PublicKey(
  "sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA",
);
export const SPL_TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
);
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
);
export const SOL_INTERFACE = new PublicKey([
  153, 202, 212, 28, 214, 25, 170, 103, 127, 203, 31, 129, 56, 221, 77, 131, 217,
  62, 194, 23, 222, 98, 111, 179, 160, 182, 255, 213, 208, 236, 115, 61,
]);
export const SHIELDED_POOL_CPI_AUTHORITY = new PublicKey([
  88, 254, 248, 74, 86, 156, 76, 98, 4, 160, 29, 78, 152, 238, 8, 247, 252, 20,
  54, 18, 242, 184, 160, 99, 112, 248, 135, 246, 47, 245, 181, 43,
]);

export const SOL_MINT = PublicKey.default;
export const SOL_ASSET_ID = 1;

export const SIGNATURE_TYPE_P256 = 0x00;
export const SIGNATURE_TYPE_ED25519 = 0x01;

export const P_CONST_SEC1 = new Uint8Array([
  0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1,
  0x33, 0xd2, 0xb0, 0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe,
  0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc, 0xdb,
]);

export const INFO_NULLIFIER = new TextEncoder().encode("TSPP/nullifier");
export const INFO_SENDER_VIEW_TAG_SECRET = new TextEncoder().encode("TSPP/sender_view_tag");
export const INFO_RECIPIENT_VIEW_TAG_SECRET = new TextEncoder().encode(
  "TSPP/recipient_view_tag",
);
export const INFO_MERGE_VIEW_TAG_SECRET = new TextEncoder().encode("TSPP/merge_view_tag");
export const INFO_TX_VIEWING = new TextEncoder().encode("TSPP/tx_viewing");
export const INFO_SENDER_VIEW_TAG_PREFIX = new TextEncoder().encode("TSPP/sender_view_tag/");
export const INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX = new TextEncoder().encode(
  "TSPP/recipient_request_view_tag/",
);
export const INFO_MERGE_VIEW_TAG_PREFIX = new TextEncoder().encode("TSPP/merge_view_tag/");
export const INFO_PAIR_DOMAIN_PREFIX = new TextEncoder().encode("TSPP/pair-domain/");
export const INFO_PAIR_HINT_PREFIX = new TextEncoder().encode("TSPP/pair-hint/");
export const HPKE_PREFIX = new TextEncoder().encode("TSPP/hpke/");
export const ENC_INFO_TRANSFER = new TextEncoder().encode("TSPP/tx");

export const InstructionTag = {
  Transact: 0,
  Deposit: 1,
  ZoneTransact: 2,
  ZoneAuthorityTransact: 3,
  CreateSplInterface: 4,
  CreateTree: 5,
  CreateProtocolConfig: 6,
  UpdateProtocolConfig: 7,
  PauseTree: 8,
  CreateZoneConfig: 9,
  UpdateZoneConfigOwner: 10,
  UpdateZoneConfig: 11,
  MergeTransact: 12,
  ZoneMergeTransact: 13,
  EmitEvent: 14,
  ZoneDeposit: 15,
  CreateAssetCounter: 16,
  BatchUpdateNullifierTree: 51,
} as const;
