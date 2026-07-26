import type { Transaction as KitTransaction } from "@solana/kit";
import { compileTransaction } from "@zolana/client";
import {
  encodeBase58,
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import { describe, expect, it } from "vitest";

import { fromKitTransaction, KitError, toKitTransaction } from "../src/index.js";

const PAYER = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const COSIGNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;

function signature(seed: number): Signature {
  return encodeBase58(new Uint8Array(64).fill(seed)) as Signature;
}

const unsigned = compileTransaction({
  feePayer: PAYER,
  recentBlockhash: "9zc4tqzHYbHRfnGYTVQVEBnHmXfDMFdKCUYzGvLbNZcm",
  instructions: [
    {
      programAddress: SHIELDED_POOL_PROGRAM_ID,
      accounts: [
        { address: PAYER, isSigner: true, isWritable: true },
        { address: COSIGNER, isSigner: true, isWritable: false },
      ],
      data: Uint8Array.of(0),
    },
  ],
});

function withSignatures(signatures: readonly (Signature | undefined)[]): Transaction {
  return Object.freeze({
    messageBytes: new Uint8Array(unsigned.messageBytes),
    signatures: Object.freeze(signatures),
  });
}

describe("transaction conversion", () => {
  it("keys the signature map by signer address in message order", () => {
    const converted = toKitTransaction(withSignatures([signature(1), signature(2)]));
    expect(Object.keys(converted.signatures)).toEqual([PAYER, COSIGNER]);
    expect(Object.values(converted.signatures)[0]).toEqual(new Uint8Array(64).fill(1));
  });

  it("maps an unfilled slot to null, not a missing key", () => {
    const converted = toKitTransaction(withSignatures([signature(1), undefined]));
    expect(Object.keys(converted.signatures)).toEqual([PAYER, COSIGNER]);
    expect(
      converted.signatures[COSIGNER as string as keyof typeof converted.signatures],
    ).toBeNull();
  });

  it("refuses a transaction whose slots do not match the message's signers", () => {
    expect(() => toKitTransaction(withSignatures([signature(1)]))).toThrow(KitError);
    expect(() =>
      toKitTransaction(withSignatures([signature(1), signature(2), signature(3)])),
    ).toThrow(KitError);
  });

  it("refuses a versioned message, whose keys sit behind a lookup section", () => {
    const versioned = withSignatures([signature(1), signature(2)]);
    versioned.messageBytes[0] = 0x80;
    expect(() => toKitTransaction(versioned)).toThrow(KitError);
  });

  it("refuses a signature map that is not in signer order", () => {
    const converted = toKitTransaction(withSignatures([signature(1), signature(2)]));
    const reordered = {
      messageBytes: converted.messageBytes,
      signatures: {
        [COSIGNER]: converted.signatures[COSIGNER as string as keyof typeof converted.signatures],
        [PAYER]: converted.signatures[PAYER as string as keyof typeof converted.signatures],
      },
    } as unknown as KitTransaction;
    expect(() => fromKitTransaction(reordered)).toThrow(KitError);
  });

  it("refuses a base58 signature that is not 64 bytes", () => {
    expect(() =>
      toKitTransaction(
        withSignatures([encodeBase58(new Uint8Array(32).fill(1)) as Signature, signature(2)]),
      ),
    ).toThrow(KitError);
  });
});
