import {
  address,
  appendTransactionMessageInstruction,
  compileTransaction,
  createKeyPairSignerFromPrivateKeyBytes,
  createTransactionMessage,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import { KeypairError } from "../src/keypair/error.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import type { Bytes32 } from "../src/keypair/bytes.js";

const SEED = new Uint8Array(32).fill(7) as Bytes32;
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
const MEMO = address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

type SignableTransaction = Parameters<
  ReturnType<ShieldedKeypair["toSolanaSigner"]>["signTransactions"]
>[0][number];

/** A real compiled transaction: Kit's signer refuses anything it is not a signer for. */
function compileTransferTransaction(feePayer: Address): SignableTransaction {
  return compileTransaction(
    pipe(
      createTransactionMessage({ version: 0 }),
      (message) => setTransactionMessageFeePayer(feePayer, message),
      (message) =>
        setTransactionMessageLifetimeUsingBlockhash(
          { blockhash: BLOCKHASH, lastValidBlockHeight: 1n },
          message,
        ),
      (message) =>
        appendTransactionMessageInstruction(
          { programAddress: MEMO, data: new Uint8Array([1]) },
          message,
        ),
    ),
  ) as unknown as SignableTransaction;
}

describe("ShieldedKeypair.toSolanaSigner", () => {
  it("matches Kit's address and signs every transaction with Kit's signature", async () => {
    const keypair = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(SEED) as Bytes32),
    );
    const signer = keypair.toSolanaSigner();
    const kit = await createKeyPairSignerFromPrivateKeyBytes(SEED);
    expect(signer.address).toBe(kit.address);

    const compiled = compileTransferTransaction(kit.address);
    const ours = await signer.signTransactions([compiled, compiled]);
    const [theirs] = await kit.signTransactions([compiled]);

    expect(ours).toHaveLength(2);
    for (const signatures of ours) {
      expect(new Uint8Array(signatures[signer.address]!)).toEqual(
        new Uint8Array(theirs![kit.address]!),
      );
    }
  });

  it("refuses a P256 keypair", () => {
    expect.assertions(3);
    const p256 = ShieldedKeypair.generate("p256");
    try {
      p256.toSolanaSigner();
    } catch (error) {
      expect(error).toBeInstanceOf(KeypairError);
      const keypairError = error as KeypairError;
      expect(keypairError.code).toBe("KEYPAIR_NOT_ED25519");
      expect(keypairError.rustVariant).toBe("NotEd25519");
    }
  });
});
