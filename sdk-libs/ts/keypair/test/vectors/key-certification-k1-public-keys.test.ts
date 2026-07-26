import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes33, Bytes34 } from "../../src/bytes.js";
import { P256_PUBLIC_KEY_LENGTH, SHIELDED_PUBLIC_KEY_LENGTH } from "../../src/constants.js";
import { P256PublicKey, ShieldedPublicKey } from "../../src/index.js";
import { certification, expectDisposition, expectHex, fromHex, toHex } from "./certification.js";

const recorded = certification.k1PublicKeys;
const p256Body = fromHex(recorded.p256BodyBytes);
const ed25519Body = fromHex(recorded.ed25519BodyBytes);

function tagged(prefix: number, body: Uint8Array): Bytes34 {
  const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
  bytes[0] = prefix;
  bytes.set(body, 1);
  return bytes as Bytes34;
}

describe("K1 public-key encoding and parsing", () => {
  it("agrees on the tagged and body widths", () => {
    expect(SHIELDED_PUBLIC_KEY_LENGTH).toBe(recorded.taggedLength);
    expect(P256_PUBLIC_KEY_LENGTH).toBe(recorded.p256BodyLength);
    expect(p256Body).toHaveLength(P256_PUBLIC_KEY_LENGTH);
    expect(fromHex(recorded.p256TaggedBytes)).toHaveLength(SHIELDED_PUBLIC_KEY_LENGTH);
  });

  it("takes the same decision on all 256 scheme-tag bytes over a P256 body", () => {
    expect(recorded.p256PrefixSweep).toHaveLength(256);
    for (const entry of recorded.p256PrefixSweep) {
      expectDisposition(
        () => ShieldedPublicKey.fromBytes(tagged(entry.prefix, p256Body)),
        entry.disposition,
        `p256 body under prefix ${entry.prefix}`,
      );
    }
    expect(recorded.p256PrefixSweep.filter((entry) => entry.disposition.accepted)).toHaveLength(1);
  });

  it("takes the same decision on all 256 scheme-tag bytes over an Ed25519 body", () => {
    expect(recorded.ed25519PrefixSweep).toHaveLength(256);
    for (const entry of recorded.ed25519PrefixSweep) {
      expectDisposition(
        () => ShieldedPublicKey.fromBytes(tagged(entry.prefix, ed25519Body)),
        entry.disposition,
        `ed25519 body under prefix ${entry.prefix}`,
      );
    }
    expect(recorded.ed25519PrefixSweep.filter((entry) => entry.disposition.accepted)).toHaveLength(
      1,
    );
  });

  it("takes the same decision on every malformed P256 point", () => {
    for (const point of recorded.p256Points) {
      const body = fromHex(point.bodyBytes) as Bytes33;
      expectDisposition(() => P256PublicKey.fromBytes(body), point.disposition, point.name);
      expectDisposition(
        () => ShieldedPublicKey.fromBytes(tagged(0, body)),
        point.disposition,
        `tagged ${point.name}`,
      );
    }
  });

  it("requires the Ed25519 padding byte to be zero", () => {
    for (const entry of recorded.ed25519Padding) {
      expectDisposition(
        () => ShieldedPublicKey.fromBytes(tagged(1, fromHex(entry.bodyBytes))),
        entry.disposition,
        `ed25519 padding ${entry.paddingByte}`,
      );
    }
  });

  it("accepts an all-zero Ed25519 body, which Rust does not validate as a point", () => {
    expectDisposition(
      () => ShieldedPublicKey.fromBytes(tagged(1, new Uint8Array(P256_PUBLIC_KEY_LENGTH))),
      recorded.ed25519ZeroBodyDisposition,
      "all-zero ed25519 body",
    );
  });

  it("rejects every length either side of the two valid widths", () => {
    for (let length = 0; length <= SHIELDED_PUBLIC_KEY_LENGTH + 2; length++) {
      if (length === SHIELDED_PUBLIC_KEY_LENGTH) continue;
      expect(
        () => ShieldedPublicKey.fromBytes(new Uint8Array(length) as Bytes34),
        `tagged length ${length}`,
      ).toThrow(expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }));
    }
    for (let length = 0; length <= P256_PUBLIC_KEY_LENGTH + 2; length++) {
      if (length === P256_PUBLIC_KEY_LENGTH) continue;
      expect(
        () => P256PublicKey.fromBytes(new Uint8Array(length) as Bytes33),
        `body length ${length}`,
      ).toThrow(expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }));
    }
  });

  it("round-trips the Rust-recorded bytes on both rails", () => {
    const p256 = ShieldedPublicKey.fromBytes(fromHex(recorded.p256TaggedBytes) as Bytes34);
    expectHex(p256.toBytes(), recorded.p256RoundTripBytes);
    expectHex(p256.p256().toBytes(), recorded.p256BodyBytes);
    expectHex(p256.p256().x(), recorded.p256XBytes);
    expect(p256.p256().yIsOdd()).toBe(recorded.p256YIsOdd);

    const ed25519 = ShieldedPublicKey.fromBytes(fromHex(recorded.ed25519TaggedBytes) as Bytes34);
    expectHex(ed25519.toBytes(), recorded.ed25519RoundTripBytes);
    expectHex(ed25519.ed25519(), recorded.ed25519BodyBytes.slice(0, 64));
  });

  it("treats the zero sentinel as the dummy owner rather than a parseable key", () => {
    const zeroed = ShieldedPublicKey.zeroed();
    expectHex(zeroed.toBytes(), recorded.zeroedTaggedBytes);
    expect(zeroed.isZero()).toBe(true);
    // Byte 0 reads as the P256 tag, so a caller that skips `isZero` sees a P256
    // key whose body is not a point -- which is why re-parsing it fails.
    expect(zeroed.signatureType()).toBe("p256");
    expect(recorded.zeroedSignatureType).toBe(0);
    expect(recorded.zeroedParsesAsKey).toBe(false);
    expect(() => ShieldedPublicKey.fromBytes(zeroed.toBytes())).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_PUBLIC_KEY" }),
    );

    const real = ShieldedPublicKey.fromBytes(fromHex(recorded.p256TaggedBytes) as Bytes34);
    expect(real.isZero()).toBe(false);
    expect(real.equals(zeroed)).toBe(false);
  });

  it("compares equality over all tagged bytes, across rails and parities", () => {
    const key = ShieldedPublicKey.fromBytes(fromHex(recorded.p256TaggedBytes) as Bytes34);
    const same = ShieldedPublicKey.fromBytes(fromHex(recorded.p256TaggedBytes) as Bytes34);
    const ed25519 = ShieldedPublicKey.fromBytes(fromHex(recorded.ed25519TaggedBytes) as Bytes34);
    expect(key.equals(same)).toBe(true);
    expect(key.equals(ed25519)).toBe(false);

    const flipped = recorded.p256Points.find((point) => point.name === "flippedParityBit");
    expect(flipped?.disposition.accepted).toBe(true);
    const twin = P256PublicKey.fromBytes(fromHex(flipped?.bodyBytes ?? "") as Bytes33);
    expect(key.p256().equals(twin)).toBe(false);
    // The parity twin shares the x-coordinate, so a port comparing only x would
    // call two different keys equal.
    expect(toHex(twin.x())).toBe(recorded.p256XBytes);
  });

  it("returns owned copies rather than views into key state", () => {
    const key = ShieldedPublicKey.fromBytes(fromHex(recorded.p256TaggedBytes) as Bytes34);
    for (const mutate of [
      () => key.toBytes(),
      () => key.p256().toBytes(),
      () => key.p256().x(),
      () => key.confidentialViewTag(),
    ]) {
      const first = mutate();
      first.fill(0xff);
      expect(toHex(mutate())).not.toBe(toHex(first));
    }

    const input = fromHex(recorded.p256TaggedBytes) as Bytes34;
    const constructed = ShieldedPublicKey.fromBytes(input);
    input.fill(0);
    expectHex(constructed.toBytes(), recorded.p256TaggedBytes);

    const body = fromHex(recorded.p256BodyBytes) as Bytes33;
    const inner = P256PublicKey.fromBytes(body);
    body.fill(0);
    expectHex(inner.toBytes(), recorded.p256BodyBytes);
    expect(inner.x()).toHaveLength(32);
    expect(inner.x() as Bytes32).not.toBe(inner.x());
  });
});
