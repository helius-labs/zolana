import { expect, it, vi } from "vitest";

import * as hasher from "../src/hasher/index.js";
import { ShieldedKeypair, ShieldedPublicKey } from "../src/keypair/index.js";

it("reuses the Ed25519 identity without sharing bytes", () => {
  const owner = ShieldedKeypair.generate();
  try {
    const bytes = owner.signingPublicKey().toBytes();
    const key = ShieldedPublicKey.fromBytes(bytes);
    const hash = vi.spyOn(hasher, "solanaOwnerIdentity");
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
