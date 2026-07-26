import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes64 } from "../../src/bytes.js";
import { SigningKey } from "../../src/index.js";
import { certification, expectDisposition, expectHex, fromHex, toHex } from "./certification.js";

const recorded = certification.k2P256Signatures;
const key = () => SigningKey.fromBytes(fromHex(recorded.keySecretBytes) as Bytes32);
const otherKey = () => SigningKey.fromBytes(fromHex(recorded.otherKeySecretBytes) as Bytes32);

function greaterThanHalfOrder(signature: Uint8Array): boolean {
  return toHex(signature.subarray(32)) > recorded.halfOrderBytes;
}

describe("K2 P256 signing and verification", () => {
  it("takes the same decision on every scalar at the ends of the group", () => {
    for (const scalar of recorded.scalars) {
      const secret = fromHex(scalar.secretBytes) as Bytes32;
      expectDisposition(() => SigningKey.fromBytes(secret), scalar.disposition, scalar.name);
      if (scalar.publicKeyBytes !== null) {
        expectHex(SigningKey.fromBytes(secret).publicKey().toBytes(), scalar.publicKeyBytes);
      }
    }
    // The domain is `1 <= d < n`: both ends of it produce a key, and nothing at
    // or above the order does.
    expect(recorded.scalars.filter((scalar) => scalar.disposition.accepted)).toHaveLength(2);
  });

  it("produces the Rust signature byte for byte, including the high-s ones", () => {
    const signer = key();
    for (const entry of recorded.digestSweep) {
      const digest = fromHex(entry.digestBytes);
      const signature = signer.sign(digest);
      expectHex(signature, entry.signatureBytes);
      expect(greaterThanHalfOrder(signature)).toBe(entry.sIsHigh);
      expect(signer.verify(digest, signature)).toBe(entry.verified);
    }
    // G2-1 ruled that the SDK produces whatever RFC 6979 gives, because the
    // deployed gadget range-checks `s` against the order alone. A port that
    // normalized `s` would pass a low-s-only corpus and diverge here.
    expect(recorded.digestSweep.filter((entry) => entry.sIsHigh).length).toBeGreaterThan(0);
    expect(recorded.acceptsHighS).toBe(true);
  });

  it("takes the same verification decision on every malformed and mutated signature", () => {
    const signer = key();
    for (const entry of recorded.signatureCases) {
      expect(
        signer.verify(fromHex(entry.digestBytes), fromHex(entry.signatureBytes) as Bytes64),
        entry.name,
      ).toBe(entry.verified);
    }
    // One case must accept and the rest must refuse, or the corpus is asserting
    // nothing.
    expect(recorded.signatureCases.filter((entry) => entry.verified)).toHaveLength(2);
  });

  it("verifies the high-s twin the deployed circuit accepts", () => {
    const twin = recorded.signatureCases.find((entry) => entry.name === "highSTwin");
    expect(twin?.verified).toBe(true);
    const signature = fromHex(twin?.signatureBytes ?? "") as Bytes64;
    expect(greaterThanHalfOrder(signature)).toBe(true);
    expect(key().verify(fromHex(recorded.canonicalDigestBytes), signature)).toBe(true);
  });

  it("produces the Rust bytes for every prehash below the group order", () => {
    const signer = key();
    const below = recorded.digestBoundaries.filter((entry) => entry.belowOrder);
    expect(below.length).toBeGreaterThan(0);
    for (const entry of below) {
      const digest = fromHex(entry.digestBytes);
      expectHex(signer.sign(digest), entry.signatureBytes);
      expect(signer.verify(digest, fromHex(entry.signatureBytes) as Bytes64)).toBe(entry.verified);
    }
  });

  /**
   * A prehash at or above `n` was the one input class where the two signers
   * disagreed byte for byte. RFC 6979 section 2.3.4 seeds the nonce with the
   * digest reduced modulo `n`, which TypeScript has always done and which the
   * Rust `ecdsa` crate does not: it hands `rfc6979::generate_k` the unreduced
   * digest, against that crate's own contract. `zolana-keypair` now reduces
   * before it calls the crate, so these cases assert agreement. The pin still
   * holds from both sides, because whichever language stopped reducing would
   * fail here.
   */
  it("agrees with Rust byte for byte on a prehash at or above the group order", () => {
    const signer = key();
    const above = recorded.digestBoundaries.filter((entry) => !entry.belowOrder);
    expect(above.length).toBeGreaterThan(0);
    for (const entry of above) {
      const digest = fromHex(entry.digestBytes);
      const reduced = fromHex(entry.reducedDigestBytes);
      const rust = fromHex(entry.signatureBytes) as Bytes64;
      // Reduction has to be observable, or the case is not above the order.
      expect(entry.reducedDigestBytes, `${entry.name}: reduces`).not.toBe(entry.digestBytes);

      expectHex(signer.sign(digest), entry.signatureBytes);
      expect(entry.matchesReducedDigestSignature, `${entry.name}: Rust reduces`).toBe(true);
      expectHex(signer.sign(digest), toHex(signer.sign(reduced)));

      expect(signer.verify(digest, rust), `${entry.name}: interoperates`).toBe(entry.verified);
      expect(signer.verify(reduced, rust)).toBe(entry.verifiedUnderReducedDigest);
      expect(signer.verify(digest, signer.sign(digest))).toBe(true);
    }
  });

  /**
   * The same reduction read out of the corpus alone, without either signer:
   * a prehash at or above `n` must be recorded with the signature Rust gave the
   * digest it reduces to. This is what a TypeScript replay cannot show, since
   * a replay that reduced the same way twice would agree either way.
   */
  it("records one signature for a prehash and its reduction", () => {
    const byDigest = new Map(
      recorded.digestBoundaries.map((entry) => [entry.digestBytes, entry.signatureBytes]),
    );
    const twins = recorded.digestBoundaries.filter(
      (entry) => !entry.belowOrder && byDigest.has(entry.reducedDigestBytes),
    );
    expect(twins.length).toBeGreaterThan(0);
    for (const entry of twins) {
      expect(entry.signatureBytes, `${entry.name}: signs as its reduction`).toBe(
        byDigest.get(entry.reducedDigestBytes),
      );
    }
  });

  it("refuses a signature under the wrong key and under the wrong rail", () => {
    const digest = fromHex(recorded.canonicalDigestBytes);
    const signature = fromHex(recorded.canonicalSignatureBytes) as Bytes64;
    expect(otherKey().verify(digest, signature)).toBe(recorded.otherKeyVerifiesCanonical);
    expect(otherKey().verify(digest, signature)).toBe(false);
    expect(key().verify(digest, fromHex(recorded.wrongRailSignatureBytes) as Bytes64)).toBe(
      recorded.wrongRailVerified,
    );
    expectHex(otherKey().publicKey().toBytes(), recorded.otherKeyPublicKeyBytes);
  });

  it("refuses every signature width other than 64 bytes", () => {
    const signer = key();
    const digest = fromHex(recorded.canonicalDigestBytes);
    for (const length of [0, 32, 63, 65, 128]) {
      expect(
        signer.verify(digest, new Uint8Array(length) as Bytes64),
        `width ${String(length)}`,
      ).toBe(false);
    }
    const signature = fromHex(recorded.canonicalSignatureBytes) as Bytes64;
    expect(signer.verify(digest, signature.subarray(0, 63) as Bytes64)).toBe(false);
  });

  it("refuses every prehash width Rust refuses", () => {
    const signer = key();
    for (const entry of recorded.prehashLengths) {
      expectDisposition(
        () => signer.sign(new Uint8Array(entry.length)),
        entry.disposition,
        `prehash width ${String(entry.length)}`,
      );
    }
    // A message that is not 32 bytes is not signable, so it cannot be verified
    // either rather than being hashed into one that is.
    expect(
      signer.verify(new Uint8Array(31), fromHex(recorded.canonicalSignatureBytes) as Bytes64),
    ).toBe(false);
  });

  it("verifies its own signatures and rejects them after any single-bit change", () => {
    const signer = key();
    const digest = fromHex(recorded.canonicalDigestBytes);
    const signature = signer.sign(digest);
    expect(signer.verify(digest, signature)).toBe(true);
    for (const index of [0, 31, 32, 63]) {
      const mutated = new Uint8Array(signature) as Bytes64;
      mutated[index] ^= 0x01;
      expect(signer.verify(digest, mutated), `flipped byte ${String(index)}`).toBe(false);
    }
    const mutatedDigest = new Uint8Array(digest);
    mutatedDigest[0] ^= 0x01;
    expect(signer.verify(mutatedDigest, signature)).toBe(false);
  });
});
