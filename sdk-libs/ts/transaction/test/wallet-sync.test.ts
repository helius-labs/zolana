import type { Bytes31, Bytes32, Signature } from "@zolana/interface";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type ShieldedAddress,
} from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet, decryptTransactions } from "../src/index.js";
import type { WalletAuthority, WalletSyncMaterial } from "../src/wallet/authority.js";
import { decryptTransactionsWorkerEquivalent } from "../src/wallet/sync.js";
import { encodeAddress } from "../src/internal.js";
import type { IndexedShieldedTransaction } from "../src/instructions/transact.js";
import { fixtureArray, fixtureObject, fixtureString, hexBytes, readFixture } from "./fixture.js";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function load(name: string): Readonly<Record<string, unknown>> {
  return readFixture(`transaction/${name}-v1.json`, fixtureObject);
}

function section(
  fixture: Readonly<Record<string, unknown>>,
  key: "inputs" | "expected",
): Readonly<Record<string, unknown>> {
  return fixtureObject(fixture[key], `fixture ${key}`);
}

function fixtureAuthority(
  inputs: Readonly<Record<string, unknown>>,
  offset = 0,
): Readonly<{
  authority: WalletAuthority;
  identity: ShieldedAddress;
  keypair: ShieldedKeypair;
  nullifier: NullifierKey;
  signing: SigningKey;
  viewing: ViewingKey;
}> {
  const secret = hexBytes(fixtureString(inputs, "signingSecretBytes"));
  secret[31] = (secret.at(31) ?? 0) + offset;
  const signing = SigningKey.fromBytes(secret as Bytes32);
  const nullifier = NullifierKey.fromSigningKey(signing);
  const viewingSeed = hexBytes(fixtureString(inputs, "viewingSeedBytes"));
  viewingSeed.fill((viewingSeed.at(0) ?? 0) + offset);
  const viewing = ViewingKey.fromSeed(viewingSeed as Bytes32, 0);
  const keypair = ShieldedKeypair.fromKeys(signing, nullifier, viewing);
  const identity = keypair.shieldedAddress();
  const material: WalletSyncMaterial = {
    identity,
    viewingKeys: [viewing],
    nullifierKey: nullifier,
  };
  const unsupported = (): Promise<never> => Promise.reject(new Error("not used by sync"));
  const solanaPublicKey =
    "solanaPubkeyBytes" in inputs
      ? encodeAddress(hexBytes(fixtureString(inputs, "solanaPubkeyBytes")))
      : SOL_MINT;
  const authority: WalletAuthority = {
    solanaPublicKey: () => solanaPublicKey,
    shieldedAddress: () => Promise.resolve(identity),
    viewingKeys: () => Promise.resolve([viewing]),
    spendNullifierKey: () => Promise.resolve(nullifier),
    syncMaterial: () => Promise.resolve(material),
    encryptConfidentialTransfer: unsupported,
    encryptAnonymousTransfer: unsupported,
    encryptSplit: unsupported,
    requestUserApproval: () => Promise.resolve(),
    signP256: unsupported,
  };
  return { authority, identity, keypair, nullifier, signing, viewing };
}

function shieldedTransactions(
  inputs: Readonly<Record<string, unknown>>,
): readonly IndexedShieldedTransaction[] {
  return fixtureArray(inputs, "transactions").map((entry) => {
    const transaction = fixtureObject(entry, "shielded transaction");
    return {
      slot: BigInt(fixtureString(transaction, "slot")),
      txSignature: fixtureString(transaction, "signature") as Signature,
      outputSlots: fixtureArray(transaction, "outputSlots").map((slotValue) => {
        const slot = fixtureObject(slotValue, "output slot");
        return {
          viewTag: hexBytes(fixtureString(slot, "viewTagBytes")) as Bytes32,
          outputContext: {
            hash: hexBytes(fixtureString(slot, "hashBytes")) as Bytes32,
            tree: encodeAddress(hexBytes(fixtureString(slot, "treeBytes"))),
            leafIndex: BigInt(fixtureString(slot, "leafIndex")),
          },
          payload: hexBytes(fixtureString(slot, "payloadBytes")),
        };
      }),
      messages: [],
      nullifiers: fixtureArray(transaction, "nullifiers").map((value) => {
        if (typeof value !== "string") throw new Error("nullifier must be a string");
        return hexBytes(value) as Bytes32;
      }),
      proofless: transaction.proofless === true,
    };
  });
}

describe("manifest-verified wallet behavior", () => {
  it("matches authority material, deterministic signature, and envelope fields", () => {
    const fixture = load("authority");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const value = fixtureAuthority(inputs);
    const authorityExpected = fixtureObject(expected.authority);
    const addressExpected = fixtureObject(authorityExpected.shieldedAddress);
    const signatureExpected = fixtureObject(expected.p256Signature);
    const signature = value.signing.sign(hexBytes(fixtureString(inputs, "messageHashBytes")));

    expect(hex(value.keypair.signingPublicKey().toBytes())).toBe(
      fixtureString(addressExpected, "signingPubkeyBytes"),
    );
    expect(hex(value.nullifier.publicKey())).toBe(
      fixtureString(authorityExpected, "nullifierPubkeyBytes"),
    );
    expect(hex(value.viewing.publicKey().toBytes())).toBe(
      fixtureString(addressExpected, "viewingPubkeyBytes"),
    );
    expect(hex(signature.slice(0, 32))).toBe(fixtureString(signatureExpected, "rBytes"));
    expect(hex(signature.slice(32))).toBe(fixtureString(signatureExpected, "sBytes"));
    expect(
      value.signing.verify(hexBytes(fixtureString(inputs, "messageHashBytes")), signature),
    ).toBe(true);
    expect(value.authority.solanaPublicKey()).toBe(
      encodeAddress(hexBytes(fixtureString(inputs, "solanaPubkeyBytes"))),
    );
    const envelope = fixtureObject(expected.envelope);
    expect(
      hex(
        ViewingKey.fromSeed(new Uint8Array(32).fill(9) as Bytes32, 0)
          .publicKey()
          .toBytes(),
      ),
    ).toBe(fixtureString(envelope, "txViewingPkBytes"));
  });

  it("matches wallet UTXOs, spent filtering, balances, and history ordering", () => {
    const fixture = load("wallet-state");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const value = fixtureAuthority(inputs);
    const mint = encodeAddress(hexBytes(fixtureString(inputs, "mintBytes")));
    const registry = new AssetRegistry([[2n, mint]]);
    const wallet = new Wallet({ identity: value.identity, registry });
    const utxos = fixtureArray(inputs, "walletUtxos").map((entry) => {
      const row = fixtureObject(entry, "wallet UTXO");
      const data = fixtureObject(row.utxo, "UTXO");
      const utxo = new Utxo({
        owner: value.keypair.signingPublicKey(),
        asset: encodeAddress(hexBytes(fixtureString(data, "assetBytes"))),
        amount: BigInt(fixtureString(data, "amount")),
        blinding: hexBytes(fixtureString(data, "blindingBytes")) as Bytes31,
        data: new Data(),
      });
      const outputContext = {
        hash: hexBytes(fixtureString(row, "hashBytes")) as Bytes32,
        tree: SOL_MINT,
        leafIndex: BigInt(fixtureString(row, "leafIndex")),
      };
      const nullifier = utxo.nullifier(outputContext.hash, value.nullifier);
      expect(hex(nullifier)).toBe(fixtureString(row, "nullifierBytes"));
      return {
        utxo,
        outputContext,
        nullifier,
        spent: row.spent === true,
      };
    });
    const historyExpected = fixtureArray(expected, "history").map((entry) =>
      fixtureObject(entry, "history row"),
    );
    wallet._replace({
      utxos,
      transactions: historyExpected.map((entry) => {
        const id = fixtureObject(entry.id, "history id");
        const kind = fixtureString(entry, "kind");
        const direction = fixtureString(entry, "direction");
        return {
          id: {
            signature: fixtureString(id, "signature") as Signature,
            index: Number(fixtureString(id, "index")),
          },
          kind: kind === "Deposit" ? ("deposit" as const) : ("transfer" as const),
          direction: direction === "Inbound" ? ("incoming" as const) : ("outgoing" as const),
          status: "confirmed" as const,
          slot: BigInt(fixtureString(id, "slot")),
        };
      }),
      nullifiers: new Set(),
    });
    const balances = fixtureArray(expected, "balances").map((entry) =>
      fixtureObject(entry, "balance"),
    );
    wallet.balances().forEach((balance, index) => {
      const expectedBalance = balances[index];
      if (!expectedBalance) throw new Error("missing balance fixture");
      expect(balance.amount).toBe(BigInt(fixtureString(expectedBalance, "amount")));
      expect(
        wallet.utxos().filter((entry) => !entry.spent && entry.utxo.asset === balance.mint),
      ).toHaveLength(Number(fixtureString(expectedBalance, "utxoCount")));
    });
    expect(wallet.privateTransactions().map((entry) => entry.id.signature)).toEqual(
      historyExpected.map((entry) =>
        fixtureString(fixtureObject(entry.id, "history id"), "signature"),
      ),
    );
    expect(wallet.balance(SOL_MINT)?.amount).toBe(40n);
    expect(wallet.utxos().filter((entry) => entry.spent)).toHaveLength(1);
  });

  it("matches incremental, idempotent, tamper, and worker-equivalent sync", async () => {
    const fixture = load("wallet-sync");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const value = fixtureAuthority(inputs);
    const transactions = shieldedTransactions(inputs);
    const wallet = new Wallet({ identity: value.identity, registry: new AssetRegistry() });

    expect(
      await decryptTransactions({
        wallet,
        authority: value.authority,
        transactions: transactions.slice(0, 1),
      }),
    ).toEqual({
      received: 1,
      spent: 0,
      transactions: 1,
      unknownAssetIds: [],
    });
    expect(
      await decryptTransactions({
        wallet,
        authority: value.authority,
        transactions: transactions.slice(1),
      }),
    ).toEqual({
      received: 1,
      spent: 0,
      transactions: 1,
      unknownAssetIds: [],
    });
    expect(await decryptTransactions({ wallet, authority: value.authority, transactions })).toEqual(
      {
        received: 0,
        spent: 0,
        transactions: 0,
        unknownAssetIds: [],
      },
    );
    const sequentialExpected = fixtureObject(expected.sequential);
    expect(wallet.utxos()).toHaveLength(Number(fixtureString(sequentialExpected, "utxoCount")));
    expect(wallet.privateTransactions()).toHaveLength(
      Number(fixtureString(sequentialExpected, "historyCount")),
    );
    expect(wallet.balance(SOL_MINT)?.amount).toBe(
      BigInt(fixtureString(sequentialExpected, "balance")),
    );

    const worker = new Wallet({ identity: value.identity, registry: new AssetRegistry() });
    const workerReport = await decryptTransactionsWorkerEquivalent({
      wallet: worker,
      authority: value.authority,
      transactions,
    });
    expect(workerReport.received).toBe(
      Number(
        fixtureString(
          fixtureObject(fixtureObject(expected.parallelEquivalent).report),
          "storedUtxos",
        ),
      ),
    );
    expect(worker.utxos()).toEqual(wallet.utxos());
    expect(worker.privateTransactions()).toEqual(wallet.privateTransactions());

    const tampered = transactions.map((transaction, index) => {
      if (index !== 0) return transaction;
      const slot = transaction.outputSlots[0];
      if (!slot) throw new Error("tamper slot missing");
      const payload = slot.payload.slice();
      payload[payload.length - 1] = (payload.at(-1) ?? 0) ^ 1;
      return { ...transaction, outputSlots: [{ ...slot, payload }] };
    });
    const tamperWallet = new Wallet({ identity: value.identity, registry: new AssetRegistry() });
    const tamperReport = await decryptTransactions({
      wallet: tamperWallet,
      authority: value.authority,
      transactions: tampered,
    });
    const tamperExpected = fixtureObject(expected.tamper);
    expect(tamperReport.received).toBe(
      Number(fixtureString(fixtureObject(tamperExpected.report), "storedUtxos")),
    );
    expect(tamperWallet.utxos()).toHaveLength(Number(fixtureString(tamperExpected, "utxoCount")));

    const other = fixtureAuthority(inputs, 1);
    const mismatched: WalletAuthority = {
      ...value.authority,
      syncMaterial: () => other.authority.syncMaterial(),
    };
    await expect(
      decryptTransactions({
        wallet: new Wallet({ identity: value.identity, registry: new AssetRegistry() }),
        authority: mismatched,
        transactions,
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_WALLET_AUTHORITY_MISMATCH" });
    const missingViewingKey: WalletAuthority = {
      ...value.authority,
      syncMaterial: () =>
        Promise.resolve({
          identity: value.identity,
          viewingKeys: [ViewingKey.fromSeed(new Uint8Array(32).fill(42) as Bytes32, 0)],
          nullifierKey: value.nullifier,
        }),
    };
    await expect(
      decryptTransactions({
        wallet: new Wallet({ identity: value.identity, registry: new AssetRegistry() }),
        authority: missingViewingKey,
        transactions: [],
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_MISSING_CURRENT_VIEWING_KEY" });
  });

  it("replays the persisted Rust regression seed amounts", () => {
    const fixture = load("frozen-tests");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const text = new TextDecoder().decode(
      hexBytes(fixtureString(expected, "regressionSeedFileBytes")),
    );
    const seedLines = text.split("\n").filter((line) => line.trimStart().startsWith("cc "));
    expect(seedLines).toHaveLength(Number(fixtureString(expected, "regressionSeedLines")));
    expect(fixtureArray(inputs, "frozenTestPaths")).toHaveLength(
      Number(fixtureString(expected, "frozenTestPathCount")),
    );
    const amounts = [...text.matchAll(/amount: (\d+)/gu)].map((match) => BigInt(match[1] ?? "0"));
    expect(amounts).toEqual([3n, 332_235n, 1n]);
    expect(amounts.reduce((sum, amount) => sum + amount, 0n)).toBe(332_239n);
  });
});
