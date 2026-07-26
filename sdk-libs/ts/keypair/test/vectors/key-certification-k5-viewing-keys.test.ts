import { p256_hasher } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes33 } from "../../src/bytes.js";
import { P_CONST_SEC1, VIEW_TAG_LENGTH } from "../../src/constants.js";
import { P256PublicKey, ViewingKey } from "../../src/index.js";
import { certification, expectHex, fromHex, toHex } from "./certification.js";

const recorded = certification.k5ViewingKeys;
const key = () => ViewingKey.fromBytes(fromHex(recorded.secretBytes) as Bytes32);
const counterparty = () =>
  P256PublicKey.fromBytes(fromHex(recorded.counterpartyPublicKeyBytes) as Bytes33);
const stranger = () => P256PublicKey.fromBytes(fromHex(recorded.strangerPublicKeyBytes) as Bytes33);

describe("K5 viewing and transaction-viewing keys", () => {
  /**
   * `P_const` is the fixed point the view root hangs off, so a wrong constant
   * would silently give a wallet a view root nobody else derives. Deriving it
   * from the suite and domain separator rather than trusting the committed
   * bytes is what makes the constant itself certified.
   */
  it("derives P_const from the hash-to-curve suite rather than trusting it", () => {
    expect(recorded.pConstSuite).toBe("P256_XMD:SHA-256_SSWU_RO_");
    expect(recorded.pConstMessageBytes).toBe("");
    const point = p256_hasher.hashToCurve(new Uint8Array(), {
      DST: fromHex(recorded.pConstDstBytes),
    });
    expectHex(point.toBytes(true), recorded.pConstSec1Bytes);
    expectHex(P_CONST_SEC1, recorded.pConstSec1Bytes);
  });

  it("agrees on the public key and on ECDH with every counterparty", () => {
    const viewing = key();
    expectHex(viewing.publicKey().toBytes(), recorded.publicKeyBytes);
    expectHex(viewing.ecdh(counterparty()), recorded.ecdhBytes);
    expectHex(viewing.ecdh(stranger()), recorded.ecdhStrangerBytes);
    expectHex(
      viewing.ecdh(P256PublicKey.fromBytes(fromHex(recorded.pConstSec1Bytes) as Bytes33)),
      recorded.ecdhWithPConstBytes,
    );
    expect(recorded.ecdhBytes).not.toBe(recorded.ecdhStrangerBytes);
  });

  it("produces every view tag byte for byte across the counter range", () => {
    const viewing = key();
    const other = counterparty();
    const outsider = stranger();
    for (const entry of recorded.tags) {
      const counter = BigInt(entry.counter);
      expectHex(viewing.senderViewTag(counter), entry.senderBytes);
      expectHex(viewing.recipientRequestViewTag(counter), entry.recipientRequestBytes);
      expectHex(viewing.mergeViewTag(counter), entry.mergeBytes);
      expectHex(viewing.sendSharedViewTag(other, counter), entry.sendSharedBytes);
      expectHex(viewing.recipientSharedViewTag(other, counter), entry.recipientSharedBytes);
      expectHex(viewing.sendSharedViewTag(outsider, counter), entry.strangerSendSharedBytes);
    }
    expectHex(viewing.recipientBootstrapViewTag(), recorded.bootstrapTagBytes);
  });

  it("keeps every tag a 32-byte field element with a zero leading byte", () => {
    const viewing = key();
    for (const entry of recorded.tags) {
      for (const tag of [entry.senderBytes, entry.mergeBytes, entry.sendSharedBytes]) {
        expect(tag).toHaveLength(64);
        expect(tag.slice(0, 2)).toBe("00");
      }
    }
    expect(viewing.senderViewTag(0n)).toHaveLength(VIEW_TAG_LENGTH);
    expect(viewing.senderViewTag(0n)[0]).toBe(0);
  });

  it("separates the four tag domains at the same counter", () => {
    const viewing = key();
    const distinct = new Set([
      toHex(viewing.senderViewTag(0n)),
      toHex(viewing.recipientRequestViewTag(0n)),
      toHex(viewing.mergeViewTag(0n)),
      toHex(viewing.sendSharedViewTag(counterparty(), 0n)),
      toHex(viewing.recipientBootstrapViewTag()),
    ]);
    expect(distinct.size).toBe(5);
  });

  it("refuses a counter outside the u64 range", () => {
    const viewing = key();
    for (const counter of [-1n, 1n << 64n, (1n << 64n) + 1n]) {
      expect(() => viewing.senderViewTag(counter), `${counter}`).toThrow();
      expect(() => viewing.mergeViewTag(counter)).toThrow();
      expect(() => viewing.sendSharedViewTag(counterparty(), counter)).toThrow();
    }
    expect(() => viewing.senderViewTag((1n << 64n) - 1n)).not.toThrow();
  });

  /**
   * A shared tag has to land on the same value whichever end derives it, or a
   * recipient scans for a tag the sender never wrote.
   */
  it("derives the same shared tag from either end of the pair", () => {
    const sender = key();
    const receiver = ViewingKey.fromBytes(fromHex(recorded.counterpartySecretBytes) as Bytes32);
    expect(toHex(sender.sendSharedViewTag(counterparty(), 42n))).toBe(
      toHex(receiver.recipientSharedViewTag(sender.publicKey(), 42n)),
    );
    expect(recorded.sharedTagDirectionsAgree).toBe(true);

    expect(toHex(sender.sendSharedViewTag(counterparty(), 42n))).not.toBe(
      toHex(sender.sendSharedViewTag(stranger(), 42n)),
    );
    expect(recorded.strangerSharedTagDiffers).toBe(true);
  });

  it("derives the same key from a wallet seed at every rotated account", () => {
    for (const entry of recorded.epochs) {
      const derived = ViewingKey.fromSeed(fromHex(recorded.seedBytes) as Bytes32, entry.account);
      expectHex(derived.secretBytes(), entry.secretBytes);
      expectHex(derived.publicKey().toBytes(), entry.publicKeyBytes);
      expectHex(derived.senderViewTag(0n), entry.senderTagBytes);
    }
    expect(new Set(recorded.epochs.map((entry) => entry.secretBytes)).size).toBe(
      recorded.epochs.length,
    );
  });

  /**
   * `from_seed` reduces a 48-byte HKDF output modulo the group order, which is
   * the one place a port can quietly differ (truncating, or reducing the wrong
   * width). The sweep is wide enough that such a port fails here.
   */
  it("reduces the seed expansion to the same scalar over the whole sweep", () => {
    for (const entry of recorded.okmDerivations) {
      const derived = ViewingKey.fromSeed(fromHex(entry.seedBytes) as Bytes32, entry.account);
      expectHex(derived.secretBytes(), entry.secretBytes);
    }
    expect(recorded.okmDerivations.length).toBeGreaterThanOrEqual(24);
  });

  it("refuses an account index outside u32", () => {
    const seed = fromHex(recorded.seedBytes) as Bytes32;
    for (const account of [-1, 1.5, 0x1_0000_0000]) {
      expect(() => ViewingKey.fromSeed(seed, account), `${account}`).toThrow();
    }
  });

  it("derives the transaction viewing key from the first nullifier alone", () => {
    const viewing = key();
    for (const entry of recorded.transactionKeys) {
      const derived = viewing.transactionViewingKey(fromHex(entry.firstNullifierBytes) as Bytes32);
      expectHex(derived.secretBytes(), entry.secretBytes);
      expectHex(derived.publicKey().toBytes(), entry.publicKeyBytes);
    }
    expect(new Set(recorded.transactionKeys.map((entry) => entry.secretBytes)).size).toBe(
      recorded.transactionKeys.length,
    );

    const nullifier = fromHex(recorded.transactionKeys[0]?.firstNullifierBytes ?? "") as Bytes32;
    expect(toHex(viewing.transactionViewingKey(nullifier).secretBytes())).toBe(
      toHex(viewing.transactionViewingKey(nullifier).secretBytes()),
    );
    expect(recorded.transactionKeyRepeatsForSameNullifier).toBe(true);
    expect(toHex(viewing.transactionViewingKey(nullifier).secretBytes())).not.toBe(
      toHex(viewing.secretBytes()),
    );
    expect(recorded.transactionKeyDiffersFromBase).toBe(true);
  });

  it("refuses a first nullifier of any width other than 32", () => {
    const viewing = key();
    for (const width of [0, 31, 33, 64]) {
      expect(() => viewing.transactionViewingKey(new Uint8Array(width) as Bytes32)).toThrow();
    }
  });

  it("returns owned copies and refuses use after destroy", () => {
    const viewing = key();
    viewing.secretBytes().fill(0xff);
    expectHex(viewing.secretBytes(), recorded.secretBytes);

    viewing.destroy();
    expect(() => viewing.secretBytes()).toThrow();
    expect(() => viewing.senderViewTag(0n)).toThrow();
    expect(() => viewing.transactionViewingKey(new Uint8Array(32) as Bytes32)).toThrow();
  });
});
