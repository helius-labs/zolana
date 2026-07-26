import type { Bytes32 } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, Wallet } from "@zolana/transaction";
import { LocalWalletAuthority } from "@zolana/wallet";

import { TestKitError } from "./error.js";
import { fixtureBytes } from "./fixtures/index.js";
import { startLocalStack } from "./node/index.js";

export { TestKitError, fixtureBytes, startLocalStack };

export interface LocalStack {
  readonly rpcUrl: URL;
  readonly indexerUrl: URL;
  readonly proverUrl: URL;
  stop(): Promise<void>;
}

export function createTestWallet(seed: Bytes32): Readonly<{
  wallet: Wallet;
  authority: LocalWalletAuthority;
}> {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: {
        field: "seed",
        expected: 32,
        actual: seed instanceof Uint8Array ? seed.length : -1,
      },
    });
  }
  const keypair = ShieldedKeypair.fromEd25519(new Uint8Array(seed) as Bytes32, 0);
  const identity = keypair.shieldedAddress();
  return Object.freeze({
    wallet: new Wallet({ identity, registry: new AssetRegistry() }),
    authority: new LocalWalletAuthority({
      solanaPublicKey: identity.solanaAddress() as unknown as import("@zolana/interface").Address,
      keypair,
    }),
  });
}
