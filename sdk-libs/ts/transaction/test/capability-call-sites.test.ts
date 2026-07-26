import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedKeypair, SigningKey, ViewingKey } from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  ConfidentialTransfer,
  SppProofInputUtxo,
  SOL_MINT,
  Utxo,
  deriveBlinding,
} from "../src/index.js";
import { ConfidentialSplit, Merge, MergeZone } from "../src/instructions/builders.js";
import { encodeAddress } from "../src/internal.js";

/**
 * K11/K12. Rust's four keypair-rail builders are generic over the capability
 * traits (`Transfer::sign` and `Split::sign` over `ShieldedKeypairTrait +
 * ViewingKeyTrait`, `Merge::new` and `MergeZone::new` over
 * `ShieldedKeypairTrait`), and the traits deliberately omit secret export:
 * `validate_merge_inputs` takes `keypair.nullifier_pubkey()` and the two `sign`
 * paths take `keypair.get_transaction_viewing_key(..)`.
 *
 * TypeScript's builders still name the concrete class in their signatures,
 * because `ShieldedKeypairLike` admits a promise for a remote signer and these
 * paths are synchronous. What they must not do is reach past the capability for
 * the key itself, which is what these cases pin.
 */

const SEED = new Uint8Array(31).fill(4) as Bytes31;
const ZONE = encodeAddress(new Uint8Array(32).fill(9));

function keypair(): ShieldedKeypair {
  const signing = SigningKey.fromBytes(new Uint8Array(32).fill(3) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(new Uint8Array(32).fill(7) as Bytes32, 0),
  );
}

function spend(owner: ShieldedKeypair, index: number, zoneProgramId?: Address): SppProofInputUtxo {
  const signing = SigningKey.fromBytes(new Uint8Array(32).fill(3) as Bytes32);
  return new SppProofInputUtxo({
    utxo: new Utxo({
      owner: owner.signingPublicKey(),
      asset: SOL_MINT,
      amount: 100n,
      blinding: deriveBlinding(SEED, index),
      zoneProgramId,
    }),
    nullifierKey: NullifierKey.fromSigningKey(signing),
  });
}

const SECRET_EXPORTS = ["viewingKey", "nullifierKey"];

/**
 * The keypair with its two secret-returning accessors removed. Methods are
 * bound to the target because the class reads private fields, which resolve
 * against the instance rather than the proxy.
 */
function capabilityOnly(owner: ShieldedKeypair): ShieldedKeypair {
  return new Proxy(owner, {
    get(target, property) {
      if (typeof property === "string" && SECRET_EXPORTS.includes(property)) {
        throw new Error(`builder reached past the capability for ${property}()`);
      }
      const value = Reflect.get(target, property) as unknown;
      return typeof value === "function"
        ? (value as (this: ShieldedKeypair, ...args: never[]) => unknown).bind(target)
        : value;
    },
  });
}

describe("keypair-rail builders against the Rust capability surface", () => {
  it("derives the transaction viewing key without exporting the viewing secret", () => {
    const owner = keypair();
    const guarded = capabilityOnly(owner);
    const registry = new AssetRegistry();
    const build = (): ConfidentialTransfer => {
      const transfer = new ConfidentialTransfer(owner.shieldedAddress(), [spend(owner, 0)], SOL_MINT);
      transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 10n);
      return transfer;
    };

    expect(() => build().sign(guarded, registry)).not.toThrow();
    expect(() => build().sign(owner, registry)).not.toThrow();

    const split = (): ConfidentialSplit =>
      new ConfidentialSplit({
        owner: owner.shieldedAddress(),
        input: spend(owner, 1),
        asset: SOL_MINT,
        numOutputs: 2,
        perOutputAmount: 50n,
        payer: SOL_MINT,
      });
    expect(() => split().sign(guarded, registry)).not.toThrow();
  });

  it("matches merge inputs against the nullifier public key alone", () => {
    const owner = keypair();
    const guarded = capabilityOnly(owner);

    expect(() => new Merge(guarded, [spend(owner, 2)])).not.toThrow();
    expect(() => new MergeZone(guarded, [spend(owner, 3, ZONE)], ZONE)).not.toThrow();
  });

  /**
   * The control: without it a guard that never fires would read as a pass, and
   * these cases would say nothing about where the builders reach.
   */
  it("refuses the secret-returning accessors it is guarding", () => {
    const guarded = capabilityOnly(keypair());
    for (const accessor of SECRET_EXPORTS) {
      expect(() => (guarded as unknown as Record<string, () => unknown>)[accessor]?.()).toThrow(
        /reached past the capability/u,
      );
    }
  });
});
