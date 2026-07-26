import { verifySignature, type SignatureBytes } from "@solana/kit";
import { compileTransaction } from "@zolana/client";
import {
  decodeBase58,
  SHIELDED_POOL_PROGRAM_ID,
  signerIndex,
  type Address,
  type Bytes32,
  type Transaction,
} from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { createSolanaSigner } from "@zolana/wallet";
import { describe, expect, it } from "vitest";

import {
  fromKitSigner,
  fromKitTransaction,
  KitError,
  toKitSigner,
  toKitTransaction,
} from "../src/index.js";

const BLOCKHASH = "9zc4tqzHYbHRfnGYTVQVEBnHmXfDMFdKCUYzGvLbNZcm";

let seed = 0;
function ed25519Signer(): ReturnType<typeof createSolanaSigner> {
  seed += 1;
  return createSolanaSigner(
    ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(seed) as Bytes32, 0),
  );
}

function unsigned(feePayer: Address): Transaction {
  return compileTransaction({
    feePayer,
    recentBlockhash: BLOCKHASH,
    instructions: [
      {
        programAddress: SHIELDED_POOL_PROGRAM_ID,
        accounts: [{ address: feePayer, isSigner: true, isWritable: true }],
        data: Uint8Array.of(0),
      },
    ],
  });
}

async function verify(
  address: Address,
  messageBytes: Uint8Array,
  signature: SignatureBytes,
): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", decodeBase58(address), "Ed25519", true, [
    "verify",
  ]);
  return verifySignature(key, signature, messageBytes);
}

describe("signer bridging", () => {
  it("presents a Zolana signer as a Kit partial signer that really signs", async () => {
    const signer = ed25519Signer();
    const transaction = unsigned(signer.address);
    const [dictionary] = await toKitSigner(signer).signTransactions([
      toKitTransaction(transaction) as never,
    ]);

    expect(Object.keys(dictionary ?? {})).toEqual([signer.address]);
    const signature = dictionary?.[signer.address as never] as SignatureBytes;
    await expect(verify(signer.address, transaction.messageBytes, signature)).resolves.toBe(true);
  });

  it("presents a Kit partial signer as a Zolana signer, filling only its slot", async () => {
    const signer = ed25519Signer();
    const transaction = unsigned(signer.address);
    const round = fromKitSigner(toKitSigner(signer));

    expect(round.address).toBe(signer.address);
    const signed = await round.signNativeTransaction(transaction);
    expect(signed.messageBytes).toEqual(transaction.messageBytes);
    expect(signed.signatures).toEqual((await signer.signNativeTransaction(transaction)).signatures);
    expect(signed.signatures[signerIndex(signed, signer.address)]).toBeDefined();
  });

  it("round-trips a signed transaction Zolana → Kit → Zolana", async () => {
    const signer = ed25519Signer();
    const signed = await signer.signNativeTransaction(unsigned(signer.address));
    expect(fromKitTransaction(toKitTransaction(signed))).toEqual(signed);
  });

  it("reports a Kit signer that answers without its own entry", async () => {
    const signer = ed25519Signer();
    const empty = fromKitSigner({
      address: signer.address as never,
      signTransactions: () => Promise.resolve([Object.freeze({})]),
    });
    await expect(empty.signNativeTransaction(unsigned(signer.address))).rejects.toThrow(KitError);
  });

  it("reports a Kit signer that answers with no dictionary at all", async () => {
    const signer = ed25519Signer();
    const empty = fromKitSigner({
      address: signer.address as never,
      signTransactions: () => Promise.resolve([]),
    });
    await expect(empty.signNativeTransaction(unsigned(signer.address))).rejects.toThrow(KitError);
  });
});
