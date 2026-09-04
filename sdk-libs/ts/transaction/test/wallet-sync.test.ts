import type { Address, Bytes16, Bytes32, Bytes33, Signature } from "../../src/interface/index.js";
import {
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type ShieldedAddress,
} from "../../src/keypair/index.js";
import { describe, expect, it } from "vitest";

import {
  AssetRegistry,
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  decryptTransactions as syncWalletWithKeys,
  type PrivateTransaction,
  type ShieldedKeys,
  type SyncReport,
  type ViewingKeyEntry,
} from "../../src/transaction/index.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeProofless,
} from "../../src/transaction/serialization/codecs.js";
import { decryptTransactionsWorkerEquivalent as syncWalletWorkerEquivalent } from "../../src/transaction/wallet/sync.js";
import { encodeAddress } from "../../src/transaction/internal.js";
import type { IndexedShieldedTransaction } from "../../src/transaction/instructions/transact.js";
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
  keys: LocalShieldedKeys;
  solanaPublicKey: Address;
  identity: ShieldedAddress;
  keypair: ShieldedKeypair;
  nullifier: NullifierKey;
  signing: SigningKey;
  viewing: ViewingKey;
}> {
  const secret = hexBytes(fixtureString(inputs, "signingSecretBytes"));
  secret[31] = (secret.at(31) ?? 0) + offset;
  const signing = SigningKey.fromP256Bytes(secret as Bytes32);
  const viewingSecret = hexBytes(fixtureString(inputs, "viewingSecretBytes"));
  viewingSecret[31] = (viewingSecret.at(31) ?? 0) + offset;
  const viewing = ViewingKey.fromBytes(viewingSecret as Bytes32);
  const keypair = ShieldedKeypair.withViewingKey(signing, viewing);
  const nullifier = keypair.nullifierKey();
  const identity = keypair.shieldedAddress();
  const keys = LocalShieldedKeys.fromKeys({
    address: identity,
    viewingKeys: [viewing],
    nullifierKey: nullifier,
  });
  const solanaPublicKey =
    "solanaPubkeyBytes" in inputs
      ? encodeAddress(hexBytes(fixtureString(inputs, "solanaPubkeyBytes")))
      : SOL_MINT;
  return { keys, solanaPublicKey, identity, keypair, nullifier, signing, viewing };
}

/**
 * TypeScript spells each Rust variant of the history enums in lower camel case
 * and changes nothing else, so the fixture's `Debug` names convert rather than
 * map. A variant Rust renames therefore fails here instead of being translated
 * back into the old spelling by a lookup table.
 */
function lowerFirst(variant: string): string {
  return variant.charAt(0).toLowerCase() + variant.slice(1);
}

function historyRow(entry: Readonly<Record<string, unknown>>): PrivateTransaction {
  const id = fixtureObject(entry.id, "history id");
  const counterparty = entry.counterpartyViewingPkBytes;
  return {
    id: {
      signature: fixtureString(id, "signature") as Signature,
      slot: BigInt(fixtureString(id, "slot")),
      index: BigInt(fixtureString(id, "index")),
    },
    kind: lowerFirst(fixtureString(entry, "kind")) as PrivateTransaction["kind"],
    direction: lowerFirst(fixtureString(entry, "direction")) as PrivateTransaction["direction"],
    status: lowerFirst(fixtureString(entry, "status")) as PrivateTransaction["status"],
    asset: encodeAddress(hexBytes(fixtureString(entry, "assetBytes"))),
    amount: BigInt(fixtureString(entry, "amount")),
    ...(typeof counterparty === "string"
      ? {
          counterpartyViewingPublicKey: P256PublicKey.fromBytes(hexBytes(counterparty) as Bytes33),
        }
      : {}),
  };
}

function viewingKeyHistoryRow(entry: ViewingKeyEntry): Readonly<Record<string, unknown>> {
  return {
    viewingPkBytes: hex(entry.viewingPublicKey.toBytes()),
  };
}

/** The counters `SyncReport` carries, read from a Rust-generated report. */
function reportRow(value: unknown): SyncReport {
  const report = fixtureObject(value, "sync report");
  return {
    storedUtxos: Number(fixtureString(report, "storedUtxos")),
    unparsedTransactions: Number(fixtureString(report, "unparsedTransactions")),
    undecryptableCandidates: Number(fixtureString(report, "undecryptableCandidates")),
    unknownAssetIds: fixtureArray(report, "unknownAssetIds").map((entry) => BigInt(String(entry))),
    // These fixtures predate merge-field recovery; no case contains an
    // unresolved merge asset.
    unknownAssetFields: [],
  };
}

function shieldedTransactions(
  inputs: Readonly<Record<string, unknown>>,
  keypair: ShieldedKeypair,
): readonly IndexedShieldedTransaction[] {
  return fixtureArray(inputs, "transactions").map((entry) => {
    const transaction = fixtureObject(entry, "shielded transaction");
    const txViewingPk = transaction.txViewingPkBytes;
    const salt = transaction.saltBytes;
    return {
      slot: BigInt(fixtureString(transaction, "slot")),
      txSignature: fixtureString(transaction, "signature") as Signature,
      ...(typeof txViewingPk === "string"
        ? { txViewingPublicKey: P256PublicKey.fromBytes(hexBytes(txViewingPk) as Bytes33) }
        : {}),
      ...(typeof salt === "string" ? { salt: hexBytes(salt) as Bytes16 } : {}),
      outputSlots: fixtureArray(transaction, "outputSlots").map((slotValue) => {
        const slot = fixtureObject(slotValue, "output slot");
        let payload = hexBytes(fixtureString(slot, "payloadBytes"));
        let hash = hexBytes(fixtureString(slot, "hashBytes")) as Bytes32;
        if (transaction.proofless === true) {
          const legacy = payload.slice(6);
          const blinding = new Uint8Array(32);
          blinding.set(legacy.slice(32, 63), 1);
          const asset = encodeAddress(legacy.slice(63, 95));
          const amount = new DataView(legacy.buffer, legacy.byteOffset + 95, 8).getBigUint64(
            0,
            true,
          );
          const output = {
            owner: legacy.slice(0, 32) as Bytes32,
            blinding: blinding as Bytes32,
            asset,
            amount,
          };
          payload = encodeOutputData(
            EncryptedScheme.proofless,
            encodeProofless(output),
            "plaintext",
          );
          hash = new Utxo({
            owner: keypair.signingPublicKey(),
            asset,
            amount,
            blinding: blinding as Bytes32,
          }).hash(keypair.nullifierPublicKey());
        }
        return {
          viewTag: hexBytes(fixtureString(slot, "viewTagBytes")) as Bytes32,
          outputContext: {
            hash,
            tree: encodeAddress(hexBytes(fixtureString(slot, "treeBytes"))),
            leafIndex: BigInt(fixtureString(slot, "leafIndex")),
          },
          payload,
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

async function decryptWallet(
  input: Readonly<{
    keys: ShieldedKeys;
    transactions: readonly IndexedShieldedTransaction[];
    registry: AssetRegistry;
  }>,
): Promise<Wallet> {
  const wallet = new Wallet({ identity: input.keys.address(), registry: input.registry });
  await syncWalletWithKeys({
    wallet,
    keys: input.keys,
    transactions: input.transactions,
  });
  return wallet;
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
    expect(value.solanaPublicKey).toBe(
      encodeAddress(hexBytes(fixtureString(inputs, "solanaPubkeyBytes"))),
    );
    const envelope = fixtureObject(expected.envelope);
    expect(
      hex(
        ViewingKey.fromBytes(hexBytes(fixtureString(inputs, "txViewingSecretBytes")) as Bytes32)
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
        blinding: hexBytes(fixtureString(data, "blindingBytes")) as Bytes32,
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
      historyRow(fixtureObject(entry, "history row")),
    );
    wallet._replace({ utxos, transactions: historyExpected, nullifiers: new Set() });
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
    expect(wallet.privateTransactions()).toEqual(historyExpected);
    expect(wallet.balance(SOL_MINT).amount).toBe(40n);
    expect(wallet.utxos().filter((entry) => entry.spent)).toHaveLength(1);
  });

  it("matches incremental, idempotent, tamper, and worker-equivalent sync", async () => {
    const fixture = load("wallet-sync");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const value = fixtureAuthority(inputs);
    const transactions = shieldedTransactions(inputs, value.keypair);
    const wallet = new Wallet({ identity: value.identity, registry: new AssetRegistry() });
    const sequentialExpected = fixtureObject(expected.sequential);

    // The three timestamps are the ones the fixture generator syncs at, so
    // `lastSynced` below is the value Rust recorded rather than an echo.
    expect(
      await syncWalletWithKeys({
        wallet,
        keys: value.keys,
        transactions: transactions.slice(0, 1),
        config: { syncedAt: 10n },
      }),
    ).toEqual(reportRow(fixtureArray(sequentialExpected, "reports")[0]));
    expect(
      await syncWalletWithKeys({
        wallet,
        keys: value.keys,
        transactions: transactions.slice(1),
        config: { syncedAt: 20n },
      }),
    ).toEqual(reportRow(fixtureArray(sequentialExpected, "reports")[1]));
    expect(
      await syncWalletWithKeys({
        wallet,
        keys: value.keys,
        transactions,
        config: { syncedAt: 30n },
      }),
    ).toEqual(reportRow(fixtureArray(sequentialExpected, "reports")[2]));
    expect(wallet.utxos()).toHaveLength(Number(fixtureString(sequentialExpected, "utxoCount")));
    expect(wallet.privateTransactions()).toHaveLength(
      Number(fixtureString(sequentialExpected, "historyCount")),
    );
    expect(wallet.balance(SOL_MINT).amount).toBe(
      BigInt(fixtureString(sequentialExpected, "balance")),
    );
    expect(wallet.lastSynced).toBe(BigInt(fixtureString(sequentialExpected, "lastSynced")));

    // Rust's free `decrypt_transactions` builds the wallet from the authority's
    // own identity, so the fresh wallet must reach the same state as the one
    // synced above from a wallet the caller constructed.
    const fresh = await decryptWallet({
      keys: value.keys,
      transactions,
      registry: new AssetRegistry(),
    });
    expect(fresh.identity).toEqual(value.identity);
    expect(fresh.balance(SOL_MINT).amount).toBe(wallet.balance(SOL_MINT).amount);
    expect(fresh.utxos()).toEqual(wallet.utxos());

    const worker = new Wallet({ identity: value.identity, registry: new AssetRegistry() });
    const workerReport = await syncWalletWorkerEquivalent({
      wallet: worker,
      keys: value.keys,
      transactions,
    });
    expect(workerReport).toEqual(reportRow(fixtureObject(expected.parallelEquivalent).report));
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
    const tamperReport = await syncWalletWithKeys({
      wallet: tamperWallet,
      keys: value.keys,
      transactions: tampered,
    });
    const tamperExpected = fixtureObject(expected.tamper);
    expect(tamperReport).toEqual(reportRow(tamperExpected.report));
    expect(tamperWallet.utxos()).toHaveLength(Number(fixtureString(tamperExpected, "utxoCount")));

    const other = fixtureAuthority(inputs, 1);
    await expect(
      syncWalletWithKeys({
        wallet: new Wallet({ identity: value.identity, registry: new AssetRegistry() }),
        keys: other.keys,
        transactions,
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_KEYS_IDENTITY_MISMATCH" });

    // A key holder that claims this identity but does not lead with its
    // viewing key would open nothing addressed to the wallet.
    const stranger = ViewingKey.fromBytes(new Uint8Array(32).fill(42) as Bytes32);
    const missingViewingKey: ShieldedKeys = {
      ...value.keys,
      address: () => value.identity,
      viewingPublicKeys: () => [stranger.publicKey()],
      decrypt: (requests) => value.keys.decrypt(requests),
      derive: (requests) => value.keys.derive(requests),
      transactionKeys: (requests) => value.keys.transactionKeys(requests),
    };
    await expect(
      syncWalletWithKeys({
        wallet: new Wallet({ identity: value.identity, registry: new AssetRegistry() }),
        keys: missingViewingKey,
        transactions: [],
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_MISSING_CURRENT_VIEWING_KEY" });

    // In-process keys refuse to be built for an identity they do not describe.
    expect(() =>
      LocalShieldedKeys.fromKeys({
        address: value.identity,
        viewingKeys: [stranger],
        nullifierKey: other.nullifier,
      }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_KEYS_IDENTITY_MISMATCH" }));
  });

  // `decrypt_transactions` keeps no wallet: it builds one, scans, reports the
  // balances, and drops it. The oracle balance is the one Rust's own call
  // produced over these transactions, so a TypeScript function that synced a
  // caller's wallet instead would not reach it.
  it("reports the balances Rust's decrypt_transactions reports, holding no wallet", async () => {
    const fixture = load("wallet-sync");
    const inputs = section(fixture, "inputs");
    const expected = section(fixture, "expected");
    const value = fixtureAuthority(inputs);
    const transactions = shieldedTransactions(inputs, value.keypair);

    const balances = (
      await decryptWallet({
        keys: value.keys,
        transactions,
        registry: new AssetRegistry(),
      })
    ).balances();

    expect(balances.find((balance) => balance.mint === SOL_MINT)?.amount).toBe(
      BigInt(fixtureString(expected, "decryptTransactionsBalance")),
    );
    expect(
      (
        await decryptWallet({
          keys: value.keys,
          transactions: [],
          registry: new AssetRegistry(),
        })
      ).balances(),
    ).toEqual([]);
  });

  it("records the canonical deposit history row", async () => {
    const fixture = load("wallet-sync");
    const inputs = section(fixture, "inputs");
    const value = fixtureAuthority(inputs);
    const history = fixtureObject(section(fixture, "expected").history, "wallet history");
    const transactions = shieldedTransactions(
      fixtureObject(inputs.history, "history inputs"),
      value.keypair,
    ).slice(0, 1);
    const wallet = new Wallet({ identity: value.identity, registry: new AssetRegistry() });
    const steps = fixtureArray(history, "steps").slice(0, 1);
    expect(steps).toHaveLength(transactions.length);

    // Synced one transaction at a time, in order: an outbound row can only net
    // the notes it spends down if the sync that stored them already ran.
    for (const [index, transaction] of transactions.entries()) {
      const step = fixtureObject(steps[index], "history step");
      const report = await syncWalletWithKeys({
        wallet,
        keys: value.keys,
        transactions: [transaction],
        config: { syncedAt: BigInt(300 + index) },
      });
      expect(report).toEqual(reportRow(step.report));
      expect(wallet.privateTransactions()).toEqual(
        fixtureArray(step, "rows").map((entry) => historyRow(fixtureObject(entry, "history row"))),
      );
      expect(wallet.viewingKeyHistory.map(viewingKeyHistoryRow)).toEqual(
        fixtureArray(step, "viewingKeyHistory").map((entry) =>
          fixtureObject(entry, "viewing key entry"),
        ),
      );
    }

    expect(wallet.utxos()).toHaveLength(1);
    expect(wallet.utxos().filter((entry) => !entry.spent)).toHaveLength(1);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
    expect(wallet.lastSynced).toBe(300n);
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
