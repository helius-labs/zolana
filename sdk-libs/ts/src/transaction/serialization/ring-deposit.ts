import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  EncryptedRingDepositData,
} from "../../interface/types.js";
import { Reader, Writer, encodeBase58 } from "../../interface/internal.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import type { ShieldedPublicKey } from "../../keypair/public-key.js";
import type { ViewingKeyLike } from "../../keypair/shielded.js";

import { Data, type DataRecord } from "../data.js";
import { Utxo } from "../utxo.js";

/** Rust `RingDepositPlaintext`. */
export interface RingDepositPlaintext {
  readonly blinding: Bytes32;
  readonly utxoData?: Uint8Array;
  readonly memo?: Uint8Array;
  readonly ringData: Uint8Array;
}

function byteVector(writer: Writer, value: Uint8Array, name: string): void {
  writer.u16(value.length, `${name}.length`).bytes(value);
}

function readByteVector(reader: Reader, name: string): Uint8Array {
  return reader.bytes(reader.u16(`${name}.length`), name);
}

export function encodeRingDepositPlaintext(value: RingDepositPlaintext): Uint8Array {
  const writer = new Writer();
  writer
    .bytes(value.blinding, 32, "blinding")
    .option(value.utxoData, (output, data) => {
      byteVector(output, data, "utxoData");
    })
    .option(value.memo, (output, memo) => {
      byteVector(output, memo, "memo");
    });
  byteVector(writer, value.ringData, "ringData");
  return writer.finish();
}

export function decodeRingDepositPlaintext(bytes: Uint8Array): RingDepositPlaintext {
  const reader = new Reader(bytes);
  const blinding = reader.bytes(32, "blinding") as Bytes32;
  const utxoData = reader.option("utxoData", (input) => readByteVector(input, "utxoData"));
  const memo = reader.option("memo", (input) => readByteVector(input, "memo"));
  const ringData = readByteVector(reader, "ringData");
  reader.done();
  return Object.freeze({
    blinding,
    ...(utxoData === undefined ? {} : { utxoData }),
    ...(memo === undefined ? {} : { memo }),
    ringData,
  });
}

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

/** Rust `RingDepositPlaintext::decrypt` + `into_utxo`. The ring data record is always present, the UTXO is ring-bound. */
export function decryptRingDepositUtxo(
  output: RingDepositOutput,
  key: ViewingKeyLike,
  owner: ShieldedPublicKey,
): Utxo {
  const plaintext = decodeRingDepositPlaintext(
    key.decryptRingDeposit(
      output.encrypted.ciphertext,
      P256PublicKey.fromBytes(output.encrypted.txViewingPublicKey),
      output.encrypted.salt,
    ),
  );
  const records: DataRecord[] = [{ kind: "ringData", bytes: plaintext.ringData }];
  if (plaintext.utxoData) records.push({ kind: "utxoData", bytes: plaintext.utxoData });
  if (plaintext.memo) records.push({ kind: "memo", bytes: plaintext.memo });
  return new Utxo({
    owner,
    asset: output.asset,
    amount: output.amount,
    blinding: plaintext.blinding,
    data: new Data(records),
    ringProgramId: output.ringProgramId,
  });
}
