import type { Address, TransactInstructionData } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import proofFixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import { buildUnsignedTransaction } from "../../src/client.js";
import { assemble } from "../../src/prover/assembly.js";
import { compressProof, parseProof } from "../../src/prover/proof.js";
import oracle from "../oracles/legacy-message-order-v1.json" with { type: "json" };
import { buildProofInputs, type ProverShapesFixture } from "../helpers/prover-vectors.js";

/// `sdk-libs/client/src/client.rs::build_unsigned_solana_transaction` generated
/// `oracles/legacy-message-order-v1.json`; regenerate it with
/// `ZOLANA_WRITE_ORACLES=1 cargo test -p zolana-client --lib --features client
/// legacy_message_account_order_oracle`. The two frozen legacy-message vectors
/// in `rpc-indexer-v1.json` only cover `withdrawal: None`, where every privilege
/// class already happens to be in ascending address order, so they cannot tell
/// `CompiledKeys` ordering apart from first-appearance ordering. A SOL
/// withdrawal can.
interface CompiledMessage {
  readonly numRequiredSignatures: number;
  readonly numReadonlySignedAccounts: number;
  readonly numReadonlyUnsignedAccounts: number;
  readonly accountKeys: readonly string[];
  readonly instructions: readonly Readonly<{
    programIdIndex: number;
    accounts: readonly number[];
  }>[];
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let out = "";
  while (value > 0n) {
    out = BASE58[Number(value % 58n)] + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = `1${out}`;
  }
  return out === "" ? "1" : out;
}

function readCompactU16(bytes: Uint8Array, offset: number): readonly [number, number] {
  let value = 0;
  let shift = 0;
  let cursor = offset;
  for (;;) {
    const byte = bytes[cursor++] ?? 0;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [value, cursor];
    shift += 7;
  }
}

function decodeLegacyMessage(messageBytes: Uint8Array): CompiledMessage {
  let cursor = 0;
  const numRequiredSignatures = messageBytes[cursor++] ?? 0;
  const numReadonlySignedAccounts = messageBytes[cursor++] ?? 0;
  const numReadonlyUnsignedAccounts = messageBytes[cursor++] ?? 0;
  const [accountCount, afterCount] = readCompactU16(messageBytes, cursor);
  cursor = afterCount;
  const accountKeys: string[] = [];
  for (let index = 0; index < accountCount; index++) {
    accountKeys.push(encodeBase58(messageBytes.subarray(cursor, cursor + 32)));
    cursor += 32;
  }
  cursor += 32; // recent blockhash
  const [instructionCount, afterInstructions] = readCompactU16(messageBytes, cursor);
  cursor = afterInstructions;
  const instructions: { programIdIndex: number; accounts: number[] }[] = [];
  for (let index = 0; index < instructionCount; index++) {
    const programIdIndex = messageBytes[cursor++] ?? 0;
    const [accountLength, afterAccounts] = readCompactU16(messageBytes, cursor);
    cursor = afterAccounts;
    const accounts = [...messageBytes.subarray(cursor, cursor + accountLength)];
    cursor += accountLength;
    const [dataLength, afterData] = readCompactU16(messageBytes, cursor);
    cursor = afterData + dataLength;
    instructions.push({ programIdIndex, accounts });
  }
  return {
    numRequiredSignatures,
    numReadonlySignedAccounts,
    numReadonlyUnsignedAccounts,
    accountKeys,
    instructions,
  };
}

function transactProof() {
  const c = proofFixture.expected.vanilla.uncompressed.cBytes;
  const b = proofFixture.expected.vanilla.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return compressProof(
    parseProof(
      {
        ar: g1,
        bs: [
          [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
          [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
        ],
        krs: g1,
      },
      false,
    ),
  ).toTransactProof();
}

function withdrawalData(data: TransactInstructionData): TransactInstructionData {
  return Object.freeze({ ...data, publicSolAmount: 4n });
}

describe("legacy message account order against the Rust oracle", () => {
  const source = buildProofInputs(proverFixtureJson as ProverShapesFixture, "eddsa", {
    inputs: 1,
    outputs: 2,
  });
  const data = withdrawalData(
    assemble(source.proofInputs, source.spendProofs).withProof(transactProof()),
  );

  for (const testCase of oracle.cases) {
    it(`matches ${testCase.name}`, () => {
      const price = testCase.input.computeUnitPriceMicroLamports;
      const transaction = buildUnsignedTransaction({
        computeUnitLimit: testCase.input.computeUnitLimit,
        ...(price === null ? {} : { computeUnitPriceMicroLamports: BigInt(price) }),
        feePayer: testCase.input.feePayer as Address,
        tree: testCase.input.tree as Address,
        withdrawal: {
          kind: "sol",
          recipient: testCase.input.recipient as Address,
        },
        data,
        recentBlockhash: testCase.input.recentBlockhash,
      });

      const compiled = decodeLegacyMessage(transaction.messageBytes);
      expect(compiled.accountKeys).toEqual(testCase.expected.accountKeys);
      expect(compiled.numRequiredSignatures).toBe(testCase.expected.numRequiredSignatures);
      expect(compiled.numReadonlySignedAccounts).toBe(testCase.expected.numReadonlySignedAccounts);
      expect(compiled.numReadonlyUnsignedAccounts).toBe(
        testCase.expected.numReadonlyUnsignedAccounts,
      );
      expect(compiled.instructions.map((item) => item.programIdIndex)).toEqual(
        testCase.expected.instructions.map((item) => item.programIdIndex),
      );
      expect(compiled.instructions.map((item) => item.accounts)).toEqual(
        testCase.expected.instructions.map((item) => item.accounts),
      );
    });
  }
});
