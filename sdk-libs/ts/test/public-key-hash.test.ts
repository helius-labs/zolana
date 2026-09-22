import { expect, it, vi } from "vitest";

import * as hasher from "../src/hasher/index.js";
import { ShieldedKeypair, ShieldedPublicKey } from "../src/keypair/index.js";

it.each(["ed25519", "p256"] as const)("reuses the %s identity without sharing bytes", (curve) => {
  const owner = ShieldedKeypair.generate(curve);
  try {
    const bytes = owner.signingPublicKey().toBytes();
    const key = ShieldedPublicKey.fromBytes(bytes);
    const hash = vi.spyOn(
      hasher,
      curve === "ed25519" ? "solanaOwnerIdentity" : "p256OwnerIdentity",
    );
    try {
      const expected = key.ownerProofInputHash();
      bytes.fill(0);
      key.toBytes().fill(0);
      key.ownerProofInputHash().fill(0);
      expect(key.ownerProofInputHash()).toEqual(expected);
      expect(hash).toHaveBeenCalledTimes(1);
    } finally {
      hash.mockRestore();
    }
  } finally {
    owner.destroy();
  }
});
