import { describe, expect, it } from "vitest";

import { solanaOwnerIdentity } from "../src/hasher/index.js";
import {
  P256PublicKey,
  ShieldedAddress,
  ShieldedPublicKey,
  initializePoseidon,
} from "../src/keypair/index.js";
import type { Bytes32 } from "../src/keypair/bytes.js";

const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;

describe("PDA owner", () => {
  it("round-trips a program-owned identity through the tag byte", () => {
    const address = filled(0x31);
    const key = ShieldedPublicKey.fromPda(address);
    expect(key.signatureType()).toBe("pda");
    expect([...key.toBytes()]).toEqual([2, ...address, 0]);
    const decoded = ShieldedPublicKey.fromBytes(key.toBytes());
    expect(decoded.signatureType()).toBe("pda");
    expect([...decoded.pda()]).toEqual([...address]);
    expect([...decoded.confidentialViewTag()]).toEqual([...address]);
  });

  it("hashes the identity as a Solana owner", () => {
    const address = filled(0x42);
    const key = ShieldedPublicKey.fromPda(address);
    expect([...key.ownerProofInputHash()]).toEqual([...solanaOwnerIdentity(address)]);
  });

  it("refuses a nonzero pad and the wrong accessor", () => {
    const bytes = new Uint8Array(34);
    bytes[0] = 2;
    bytes[33] = 1;
    expect(() => ShieldedPublicKey.fromBytes(bytes as never)).toThrow();
    expect(() => ShieldedPublicKey.fromPda(filled(0x11)).ed25519()).toThrow();
  });

  it("reads the PDA back as the output's Solana address", async () => {
    await initializePoseidon();
    const address = filled(0x51);
    const nullifier = filled(0x00);
    const viewing = P256PublicKey.fromSecret(filled(0x09));
    const shielded = ShieldedAddress.forPda(address, nullifier, viewing);
    expect(shielded.signingPublicKey.signatureType()).toBe("pda");
    expect([...shielded.solanaAddress().toString()].length).toBeGreaterThan(0);
  });
});
