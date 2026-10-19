import { describe, expect, it } from "vitest";
import { blockhash, getAddressDecoder } from "@solana/kit";
import { SPP_SUPPORTED_SHAPES, RING_POLICY_SUPPORTED_SHAPES } from "../src/interface/shape.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { transactionSize } from "../src/interface/transaction-size.js";
import { ringTransactInstruction } from "../src/ring/instructions.js";
import { compileUnsignedTransaction } from "../src/flows/compile.js";
import {
  encodeConfidential,
  encodeOutputData,
  EncryptedScheme,
} from "../src/transaction/serialization/codecs.js";
import { Data } from "../src/transaction/data.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  TransactInstructionData,
} from "../src/interface/types.js";

const bytes = (n: number): Bytes32 => {
  const b = new Uint8Array(32);
  new DataView(b.buffer).setUint32(28, n);
  return b as Bytes32;
};
const payer = getAddressDecoder().decode(bytes(122));
const ring = getAddressDecoder().decode(bytes(123));
const tree = treeAddress(0);

describe("ring transaction shape transport", () => {
  it("measures full-output policy transactions", async () => {
    const plaintext = encodeConfidential({
      assetId: 0n,
      amount: 1n,
      blinding: bytes(1),
      data: new Data(),
      ringProgramId: ring,
    });
    const payload = encodeOutputData(
      EncryptedScheme.ringConfidential,
      new Uint8Array(33 + plaintext.length),
      "encrypted",
    );
    const sizes = new Map<string, number>();
    for (const shape of SPP_SUPPORTED_SHAPES) {
      const data: TransactInstructionData = {
        expiryUnixTs: 1_800_000_000n,
        privateTxHash: bytes(1),
        circuit: { kind: "ringEddsa", ...shape, publicAssetSlots: 3 },
        txViewingPk: new Uint8Array(33) as Bytes33,
        salt: new Uint8Array(16) as Bytes16,
        proof: { a: bytes(1), b: new Uint8Array(128) as Bytes128, c: bytes(1) },
        inputs: Array.from({ length: shape.inputs }, (_, index) => ({
          nullifierHash: bytes(index + 1000),
          treeIndex: 0,
        })),
        treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
        interfaceTransfers: [],
        outputs: Array.from({ length: shape.outputs }, (_, index) => ({
          utxoHash: bytes(index + 1),
          ownerTag: { kind: "inline", value: bytes(index + 10) },
          data: payload,
        })),
        messages: [
          {
            viewTag: bytes(1),
            data: new Uint8Array(
              65 +
                32 *
                  (shape.inputs === 24 && shape.outputs === 2
                    ? 18
                    : 9 * Math.max(4, shape.outputs)),
            ),
          },
        ],
      };
      const instruction = await ringTransactInstruction({
        ringProgramId: ring,
        payer,
        inputTrees: [tree],
        outputTree: tree,
        policy: {
          trees: [treeAddress(1)],
          treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
          memberRegistryRootIndex: 0,
        },
        proof: new Uint8Array(192),
        data,
      });
      let size: number | undefined;
      try {
        size = transactionSize(
          compileUnsignedTransaction({
            feePayer: payer,
            lifetime: {
              blockhash: blockhash("11111111111111111111111111111111"),
              lastValidBlockHeight: 1n,
            },
            instructions: [instruction],
            computeUnitLimit: 1_400_000,
          }),
        );
      } catch (error) {
        if (
          error !== null &&
          typeof error === "object" &&
          "details" in error &&
          error.details !== null &&
          typeof error.details === "object" &&
          "size" in error.details &&
          typeof error.details.size === "number"
        )
          size = error.details.size;
        else throw error;
      }
      expect(size).toBeTypeOf("number");
      if (size === undefined) throw new TypeError("Missing measured size");
      sizes.set(`${shape.inputs}x${shape.outputs}`, size);
      expect(size <= 4096).toBe(
        RING_POLICY_SUPPORTED_SHAPES.some(
          (supported) => supported.inputs === shape.inputs && supported.outputs === shape.outputs,
        ),
      );
    }
    expect(payload.length).toBe(121);
    expect(sizes.get("16x4")).toBe(4043);
    expect(sizes.get("24x2")).toBe(3617);
    expect(sizes.get("1x8")).toBe(4961);
  });
});
