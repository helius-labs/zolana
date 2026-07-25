import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Bytes33, Signature, Transaction } from "@zolana/interface";
import {
  NullifierKey,
  P256PublicKey,
  ShieldedAddress,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import {
  buildRegistrationTransaction,
  ensureRegistered,
  fetchUserRecord,
  registerIfAbsent,
  resolveRegisteredAddress,
  type TransactionSigner,
} from "../src/index.js";
import { base58, fromBase58, hex, hexBytes, walletFixture } from "./helpers/fixtures.js";

const REGISTRY_PROGRAM = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;

interface RegistryFixture {
  readonly inputs: Readonly<{
    owner: Address;
    ownerSigningSecretBytes: string;
    ownerViewingSeedBytes: string;
  }>;
  readonly expected: Readonly<{
    canonicalBump: string;
    recordPda: Address;
    register: Readonly<{ unsignedTransaction: Readonly<{ messageBytes: string }> }>;
    rotation: Readonly<{ unsignedTransaction: Readonly<{ messageBytes: string }> }>;
    resolved: Readonly<{
      signingPubkeyBytes: string;
      nullifierPubkeyBytes: string;
      viewingPubkeyBytes: string;
      viewTagBytes: string;
    }>;
  }>;
}

function keypair(fixture: RegistryFixture): ShieldedKeypair {
  const signing = SigningKey.fromBytes(hexBytes(fixture.inputs.ownerSigningSecretBytes) as Bytes32);
  return ShieldedKeypair.fromKeys(
    signing,
    NullifierKey.fromSigningKey(signing),
    ViewingKey.fromSeed(hexBytes(fixture.inputs.ownerViewingSeedBytes) as Bytes32, 0),
  );
}

interface DelegateEpoch {
  readonly delegate: Uint8Array;
  readonly syncPublicKey: Uint8Array;
  readonly viewingPublicKey: Uint8Array;
}

function recordBytes(
  fixture: RegistryFixture,
  options: Readonly<{
    mergingEnabled?: boolean;
    syncDelegate?: Uint8Array;
    entries?: readonly DelegateEpoch[];
    identity?: ShieldedAddress;
  }> = {},
): Uint8Array {
  const owner = fromBase58(fixture.inputs.owner);
  const published = options.identity;
  const signing =
    published === undefined
      ? hexBytes(fixture.expected.resolved.signingPubkeyBytes).slice(1)
      : published.signingPublicKey.p256().toBytes();
  const nullifier =
    published === undefined
      ? hexBytes(fixture.expected.resolved.nullifierPubkeyBytes)
      : published.nullifierPublicKey;
  const viewing =
    published === undefined
      ? hexBytes(fixture.expected.resolved.viewingPubkeyBytes)
      : published.viewingPublicKey.toBytes();
  const entries = options.entries ?? [];
  const entryCount = new Uint8Array(4);
  new DataView(entryCount.buffer).setUint32(0, entries.length, true);
  return Uint8Array.from([
    1,
    ...owner,
    Number(fixture.expected.canonicalBump),
    1,
    ...signing,
    ...nullifier,
    ...viewing,
    ...(options.syncDelegate === undefined ? [0] : [1, ...options.syncDelegate]),
    ...entryCount,
    ...entries.flatMap((entry, index) => [
      ...entry.delegate,
      ...entry.syncPublicKey,
      ...entry.viewingPublicKey,
      ...new Uint8Array(8).fill(0).map((_, byte) => (byte === 0 ? index + 1 : 0)),
    ]),
    options.mergingEnabled === true ? 1 : 0,
  ]);
}

function registryRpc(fixture: RegistryFixture, accountData?: Uint8Array): Rpc {
  const unsupported = (): Promise<never> => Promise.reject(new Error("unexpected RPC call"));
  return {
    getAccount: (address) => {
      expect(address).toBe(fixture.expected.recordPda);
      return Promise.resolve(
        accountData === undefined
          ? undefined
          : { owner: REGISTRY_PROGRAM, data: accountData, lamports: 1n },
      );
    },
    getMultipleAccounts: unsupported,
    getBalance: unsupported,
    getLatestBlockhash: () =>
      Promise.resolve({
        blockhash: base58(new Uint8Array(32).fill(41)),
        lastValidBlockHeight: 1n,
      }),
    sendTransaction: unsupported,
    confirmTransaction: unsupported,
    transactOutputViewTags: unsupported,
    getMerkleProofs: unsupported,
    getNonInclusionProofs: unsupported,
    getInputMerkleProofs: unsupported,
  };
}

function sendingRegistry(
  fixture: RegistryFixture,
  accountData?: Uint8Array,
): Readonly<{ rpc: Rpc; sent: Transaction[]; funding: TransactionSigner }> {
  const sent: Transaction[] = [];
  const base = registryRpc(fixture, accountData);
  return {
    rpc: {
      ...base,
      sendTransaction: (transaction) => {
        sent.push(transaction);
        return Promise.resolve(base58(new Uint8Array(64).fill(9)) as Signature);
      },
    },
    sent,
    funding: {
      address: fixture.inputs.owner,
      signNativeTransaction: (transaction) => Promise.resolve(transaction),
    },
  };
}

describe("wallet registry", () => {
  it("matches registration, checked fetch, and registered resolution vectors", async () => {
    const fixture = await walletFixture<RegistryFixture>("user_registry");
    const localKeypair = keypair(fixture);
    const transaction = await buildRegistrationTransaction({
      rpc: registryRpc(fixture),
      owner: fixture.inputs.owner,
      address: localKeypair.shieldedAddress(),
    });
    if (transaction === undefined) throw new Error("missing registration transaction");
    expect(hex(transaction.messageBytes)).toBe(
      fixture.expected.register.unsignedTransaction.messageBytes,
    );

    const data = recordBytes(fixture);
    const record = await fetchUserRecord({
      rpc: registryRpc(fixture, data),
      owner: fixture.inputs.owner,
    });
    if (record === undefined) throw new Error("missing registry record");
    expect(record.bump).toBe(Number(fixture.expected.canonicalBump));
    expect(hex(record.nullifierPublicKey)).toBe(fixture.expected.resolved.nullifierPubkeyBytes);
    const resolved = await resolveRegisteredAddress({
      rpc: registryRpc(fixture, data),
      owner: fixture.inputs.owner,
    });
    if (resolved === undefined) throw new Error("missing resolved address");
    expect(hex(resolved.address.signingPublicKey.toBytes())).toBe(
      fixture.expected.resolved.signingPubkeyBytes,
    );
    expect(hex(resolved.viewTag)).toBe(fixture.expected.resolved.viewTagBytes);
  });

  it("resolves a delegated recipient to the delegate's latest epoch viewing key", async () => {
    const fixture = await walletFixture<RegistryFixture>("user_registry");
    const delegate = new Uint8Array(32).fill(5);
    const firstEpoch = ViewingKey.fromSeed(new Uint8Array(32).fill(7) as Bytes32, 0).publicKey();
    const latestEpoch = ViewingKey.fromSeed(new Uint8Array(32).fill(8) as Bytes32, 0).publicKey();
    const entries = [firstEpoch, latestEpoch].map((epoch) => ({
      delegate,
      syncPublicKey: epoch.toBytes(),
      viewingPublicKey: epoch.toBytes(),
    }));

    const active = registryRpc(fixture, recordBytes(fixture, { syncDelegate: delegate, entries }));
    const delegated = await resolveRegisteredAddress({ rpc: active, owner: fixture.inputs.owner });
    if (delegated === undefined) throw new Error("missing delegated address");
    expect(hex(delegated.address.viewingPublicKey.toBytes())).toBe(hex(latestEpoch.toBytes()));
    expect(hex(delegated.viewTag)).toBe(hex(latestEpoch.x()));
    const record = await fetchUserRecord({ rpc: active, owner: fixture.inputs.owner });
    expect(hex(record?.viewingPublicKey ?? new Uint8Array())).toBe(
      fixture.expected.resolved.viewingPubkeyBytes,
    );

    const revoked = registryRpc(fixture, recordBytes(fixture, { entries }));
    const restored = await resolveRegisteredAddress({ rpc: revoked, owner: fixture.inputs.owner });
    if (restored === undefined) throw new Error("missing restored address");
    expect(hex(restored.address.viewingPublicKey.toBytes())).toBe(
      fixture.expected.resolved.viewingPubkeyBytes,
    );
  });

  it("registers, no-ops, and rotates through ensureRegistered", async () => {
    const fixture = await walletFixture<RegistryFixture>("user_registry");
    const localKeypair = keypair(fixture);

    const absent = sendingRegistry(fixture);
    const written = await ensureRegistered({
      rpc: absent.rpc,
      funding: absent.funding,
      keypair: localKeypair,
    });
    expect(written).toBeDefined();
    expect(hex(absent.sent[0]?.messageBytes ?? new Uint8Array())).toBe(
      fixture.expected.register.unsignedTransaction.messageBytes,
    );

    const current = sendingRegistry(fixture, recordBytes(fixture));
    expect(
      await ensureRegistered({
        rpc: current.rpc,
        funding: current.funding,
        keypair: localKeypair,
      }),
    ).toBeUndefined();
    expect(current.sent).toHaveLength(0);

    const stale = sendingRegistry(
      fixture,
      recordBytes(fixture, { identity: ShieldedKeypair.generate().shieldedAddress() }),
    );
    expect(
      await ensureRegistered({ rpc: stale.rpc, funding: stale.funding, keypair: localKeypair }),
    ).toBeDefined();
    expect(stale.sent).toHaveLength(1);
  });

  it("never rotates keys through registerIfAbsent", async () => {
    const fixture = await walletFixture<RegistryFixture>("user_registry");
    const localKeypair = keypair(fixture);

    const absent = sendingRegistry(fixture);
    expect(
      await registerIfAbsent({ rpc: absent.rpc, funding: absent.funding, keypair: localKeypair }),
    ).toMatchObject({ kind: "written" });
    expect(hex(absent.sent[0]?.messageBytes ?? new Uint8Array())).toBe(
      fixture.expected.register.unsignedTransaction.messageBytes,
    );

    const current = sendingRegistry(fixture, recordBytes(fixture));
    expect(
      await registerIfAbsent({ rpc: current.rpc, funding: current.funding, keypair: localKeypair }),
    ).toEqual({ kind: "current" });
    expect(current.sent).toHaveLength(0);

    // A record published by another identity must be reported, never overwritten:
    // the nullifier key it commits to cannot be rotated.
    const conflicting = sendingRegistry(
      fixture,
      recordBytes(fixture, { identity: ShieldedKeypair.generate().shieldedAddress() }),
    );
    expect(
      await registerIfAbsent({
        rpc: conflicting.rpc,
        funding: conflicting.funding,
        keypair: localKeypair,
      }),
    ).toEqual({ kind: "mismatch" });
    expect(conflicting.sent).toHaveLength(0);
  });

  it("no-ops for current keys and emits update tag five for rotated keys", async () => {
    const fixture = await walletFixture<RegistryFixture>("user_registry");
    const rpc = registryRpc(fixture, recordBytes(fixture));
    expect(
      await buildRegistrationTransaction({
        rpc,
        owner: fixture.inputs.owner,
        address: keypair(fixture).shieldedAddress(),
      }),
    ).toBeUndefined();

    const rotationBytes = fixture.expected.rotation.unsignedTransaction.messageBytes;
    const payload = rotationBytes.slice(-200);
    const ownerP256 = hexBytes(payload.slice(4, 70)) as Bytes33;
    const nullifier = hexBytes(payload.slice(70, 134)) as Bytes32;
    const viewing = hexBytes(payload.slice(134, 200)) as Bytes33;
    const rotated = ShieldedAddress.fromPublicKeys(
      ShieldedPublicKey.fromP256(P256PublicKey.fromBytes(ownerP256)),
      nullifier,
      P256PublicKey.fromBytes(viewing),
    );
    const transaction = await buildRegistrationTransaction({
      rpc,
      owner: fixture.inputs.owner,
      address: rotated,
    });
    if (transaction === undefined) throw new Error("missing rotation transaction");
    expect(hex(transaction.messageBytes)).toBe(rotationBytes);
  });
});
