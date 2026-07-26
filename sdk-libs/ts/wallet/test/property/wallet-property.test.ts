import fc from "fast-check";
import { describe, expect, it } from "vitest";

import type { Address, Bytes32 } from "@zolana/interface";
import { randomBlinding, ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, OutputData, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";

import { createDeposit, createSplit, WalletError } from "../../src/index.js";

const OWNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const TREE = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const MINT = "BMLm6t2ykqZ8TJ974ze9CR8ApeR44XoFAearTLeHj8ya" as Address;
const bytes32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;

function fundedWallet(amounts: readonly bigint[]): Wallet {
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: randomBlinding(),
        data: new OutputData(),
      }),
      outputContext: {
        hash: bytes32(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: bytes32(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

describe("wallet non-deterministic properties", () => {
  it("keeps deposit view tags and amounts stable while blinding varies", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 1n, max: 1_000_000n }), (amount) => {
        const to = ShieldedKeypair.generate().shieldedAddress();
        const first = createDeposit({ recipient: to, asset: SOL_MINT, amount });
        const second = createDeposit({ recipient: to, asset: SOL_MINT, amount });
        expect(first.viewTag()).toEqual(second.viewTag());
        expect(first.viewTag()).toEqual(to.confidentialViewTag());
        expect(first.data.amount).toBe(amount);
        expect(second.data.amount).toBe(amount);
        expect(first.data.owner).toEqual(to.ownerHash());
        expect(second.data.owner).toEqual(to.ownerHash());
        expect(first.data.blinding).not.toEqual(second.data.blinding);
      }),
    );
  });

  it("refuses out-of-domain deposit amounts for every generated value", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.constant(-1n),
          fc.bigInt({ min: 0xffff_ffff_ffff_ffffn + 1n, max: 0xffff_ffff_ffff_ffffn + 1_000n }),
        ),
        (amount) => {
          expect(() =>
            createDeposit({
              recipient: ShieldedKeypair.generate().shieldedAddress(),
              asset: SOL_MINT,
              amount,
            }),
          ).toThrow(expect.objectContaining({ code: "WALLET_INVALID_AMOUNT" }));
        },
      ),
    );
  });

  it("conserves split value across generated part counts", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2, max: 8 }),
        fc.bigInt({ min: 1n, max: 5_000n }),
        (parts, per) => {
          const funded = per * BigInt(parts);
          const created = createSplit({
            wallet: fundedWallet([funded]),
            payer: OWNER,
            asset: SOL_MINT,
            parts,
          });
          expect(created.numOutputs).toBe(parts);
          expect(created.perOutputAmount).toBe(per);
          expect(created.perOutputAmount * BigInt(created.numOutputs)).toBe(funded);
        },
      ),
      { numRuns: 40 },
    );
  });

  it("names a WalletError code on every generated missing SPL deposit", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 1n, max: 1000n }), (amount) => {
        try {
          createDeposit({
            recipient: ShieldedKeypair.generate().shieldedAddress(),
            asset: MINT,
            amount,
          });
          throw new Error("expected missing SPL account");
        } catch (error) {
          expect(error).toBeInstanceOf(WalletError);
          expect((error as WalletError).code).toBe("WALLET_MISSING_SPL_TOKEN_ACCOUNT");
        }
      }),
    );
  });
});
