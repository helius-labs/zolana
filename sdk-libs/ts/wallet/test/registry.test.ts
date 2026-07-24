import type { Rpc } from "@zolana/client";
import type { Address, Bytes32, Bytes33 } from "@zolana/interface";
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
  fetchUserRecord,
  resolveRegisteredAddress,
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

function recordBytes(fixture: RegistryFixture, mergingEnabled = false): Uint8Array {
  const owner = fromBase58(fixture.inputs.owner);
  const signing = hexBytes(fixture.expected.resolved.signingPubkeyBytes).slice(1);
  const nullifier = hexBytes(fixture.expected.resolved.nullifierPubkeyBytes);
  const viewing = hexBytes(fixture.expected.resolved.viewingPubkeyBytes);
  return Uint8Array.from([
    1,
    ...owner,
    Number(fixture.expected.canonicalBump),
    1,
    ...signing,
    ...nullifier,
    ...viewing,
    0,
    0,
    0,
    0,
    0,
    mergingEnabled ? 1 : 0,
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
