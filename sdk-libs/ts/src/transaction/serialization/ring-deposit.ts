import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  EncryptedRingDepositData,
} from "../../interface/types.js";
import { Reader, encodeBase58 } from "../../interface/internal.js";

/** Borsh body after the scheme byte. The ciphertext length is u32 here and u16 in the instruction. */
export interface RingDepositOutput {
  readonly ownerUtxoHash: Bytes32;
  readonly asset: Address;
  readonly amount: bigint;
  readonly dataHash?: Bytes32;
  readonly ringProgramId: Address;
  readonly ringDataHash: Bytes32;
  readonly encrypted: EncryptedRingDepositData;
}

export function decodeRingDepositOutput(body: Uint8Array): RingDepositOutput {
  const reader = new Reader(body);
  const ownerUtxoHash = reader.bytes(32, "ownerUtxoHash") as Bytes32;
  const asset = encodeBase58(reader.bytes(32, "asset"));
  const amount = reader.u64("amount");
  const dataHash = reader.option("dataHash", (input) => input.bytes(32, "dataHash") as Bytes32);
  const ringProgramId = encodeBase58(reader.bytes(32, "ringProgramId"));
  const ringDataHash = reader.bytes(32, "ringDataHash") as Bytes32;
  const txViewingPublicKey = reader.bytes(33, "txViewingPublicKey") as Bytes33;
  const salt = reader.bytes(16, "salt") as Bytes16;
  const ciphertext = reader.bytes(reader.u32("ciphertext.length"), "ciphertext");
  reader.done();
  return Object.freeze({
    ownerUtxoHash,
    asset,
    amount,
    ...(dataHash === undefined ? {} : { dataHash }),
    ringProgramId,
    ringDataHash,
    encrypted: Object.freeze({ txViewingPublicKey, salt, ciphertext }),
  });
}

export type DepositPayloadDecoder = (bytes: Uint8Array) => Uint8Array;
