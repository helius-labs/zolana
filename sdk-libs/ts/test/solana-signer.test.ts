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
  it("signs for the same address Kit derives from the seed", async () => {
    const keypair = ShieldedKeypair.fromEd25519(new Uint8Array(SEED) as Bytes32, 0);
    const kit = await createKeyPairSignerFromPrivateKeyBytes(SEED);
    expect(keypair.toSolanaSigner().address).toBe(kit.address);
  });

  /**
   * The signature has to be the one Kit's own signer produces, or the validator
   * rejects it. This is the check that the sync noble path is wired correctly.
   *
   * Kit's signer only signs a transaction that already lists its address, so
   * the comparison runs over a real compiled transaction.
   */
  it("produces the signature Kit produces", async () => {
    const keypair = ShieldedKeypair.fromEd25519(new Uint8Array(SEED) as Bytes32, 0);
    const signer = keypair.toSolanaSigner();
    const kit = await createKeyPairSignerFromPrivateKeyBytes(SEED);
    expect(signer.address).toBe(kit.address);

    const compiled = compileTransferTransaction(kit.address);
    const [ours] = await signer.signTransactions([compiled]);
    const [theirs] = await kit.signTransactions([compiled]);

    expect(ours?.[signer.address]).toBeDefined();
    expect(new Uint8Array(ours![signer.address]!)).toEqual(new Uint8Array(theirs![kit.address]!));
  });

  it("signs every transaction it is handed", async () => {
    const signer = ShieldedKeypair.fromEd25519(new Uint8Array(SEED) as Bytes32, 0).toSolanaSigner();
    const compiled = compileTransferTransaction(signer.address);
    const dictionaries = await signer.signTransactions([compiled, compiled]);
    expect(dictionaries).toHaveLength(2);
    expect(dictionaries[0]?.[signer.address]).toBeDefined();
  });

  /** A P256 signing key has no Solana address to sign for. */
  it("refuses a P256 keypair", () => {
    const p256 = ShieldedKeypair.generate("p256");
    expect(() => p256.toSolanaSigner()).toThrow(KeypairError);
    try {
      p256.toSolanaSigner();
    } catch (error) {
      expect((error as KeypairError).code).toBe("KEYPAIR_NOT_ED25519");
      expect((error as KeypairError).rustVariant).toBe("NotEd25519");
    }
  });
});
