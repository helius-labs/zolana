// Shared by the ring live suites, the harness ring pins the released rows.
import { readFile } from "node:fs/promises";

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createKeyPairSignerFromBytes,
  lamports,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";

import type { ZolanaClient } from "../../src/client/client.js";
import { compileUnsignedTransaction } from "../../src/flows/compile.js";
import { ShieldedKeypair, SigningKey, Wallet, syncWallet, type Bytes32 } from "../../src/index.js";
import {
  ListId,
  RingListNamespace,
  buildRingListWriteTransaction,
  memberOfTag,
  readRingEntry,
  ringPolicyNamespaceAddress,
  type EntryState,
  type RingRpc,
  messageSignerReader,
} from "../../src/ring/index.js";
import { KeypairWalletAuthority } from "../../src/transaction/wallet/authority.js";

import { currentSlot, signSendAndConfirm, waitForSignature, type Actor } from "./live-helpers.js";

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the ring live test requires ${name}`);
  return value;
}

export async function freshActor(): Promise<Actor> {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  const signer = await createKeyPairSignerFromBytes(
    Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)),
  );
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed as Bytes32));
  return {
    signer,
    keypair,
    wallet: new Wallet({ identity: keypair.shieldedAddress() }),
    authority: new KeypairWalletAuthority({ solanaPublicKey: signer.address, keypair }),
  };
}

export async function airdrop(client: ZolanaClient, recipient: Address): Promise<void> {
  const signature = await client.solanaRpc
    .requestAirdrop(recipient, lamports(5_000_000_000n))
    .send();
  await waitForSignature(client.solanaRpc, signature);
}

export async function keypairSignerFromFile(path: string): Promise<KeyPairSigner> {
  const bytes = Uint8Array.from(JSON.parse(await readFile(path, "utf8")) as number[]);
  return createKeyPairSignerFromBytes(bytes);
}

export async function sendInstruction(
  client: ZolanaClient,
  instruction: Instruction,
  signer: KeyPairSigner,
): Promise<void> {
  const lifetime = await client.getLatestBlockhash();
  const transaction = compileUnsignedTransaction({
    feePayer: signer.address,
    lifetime,
    computeUnitLimit: 200_000,
    instructions: [instruction],
  });
  await signSendAndConfirm(client, transaction, [signer]);
}

export async function sync(client: ZolanaClient, actor: Actor): Promise<void> {
  await syncWallet({
    client,
    wallet: actor.wallet,
    authority: actor.authority,
    config: { requireSlot: await currentSlot(client) },
  });
}

/** The indexer and the ring RPC lag behind confirmation, so the view is polled. */
export async function waitForAudited(
  ringRpc: RingRpc,
  ringProgramId: Address,
  signer: KeyPairSigner,
  signature: string,
) {
  for (let attempt = 0; attempt < 120; attempt++) {
    const view = await ringRpc.getDecryptedTransactions({
      ringProgramId,
      signer: messageSignerReader(signer),
    });
    const item = view.items.find((entry) => entry.signature === signature);
    if (item !== undefined) return item;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`transaction ${signature} did not reach the ring view`);
}

/** Lands one list write and returns once the indexer serves the entry and its proof. */
export async function writeList(
  client: ZolanaClient,
  ringProgramId: Address,
  authority: KeyPairSigner,
  input: Readonly<{ listId: ListId; tag: Uint8Array; state: EntryState }>,
) {
  const member = memberOfTag(input.tag);
  const write = await buildRingListWriteTransaction({
    client,
    ringProgramId,
    payer: authority.address,
    listId: input.listId,
    member,
    state: input.state,
  });
  if (write.kind === "transaction") {
    await signSendAndConfirm(client, write.transaction, [authority]);
  }
  const namespace = await ringPolicyNamespaceAddress(ringProgramId);
  const entriesTree = client.tree;
  const deadline = Date.now() + 120_000;
  for (;;) {
    const live = await readRingEntry({
      indexer: client,
      entriesTree,
      entriesTreeId: client.treeId,
      namespace,
      listId: input.listId,
      member,
    });
    if (live !== undefined && live.entry.state === input.state) {
      const { proofs } = await client.getMerkleProofs(entriesTree, [live.utxoHash]);
      if (proofs.length === 1) return write;
    }
    if (Date.now() > deadline)
      throw new Error(`${input.state} ${String(input.listId)} entry not indexed`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

export async function enrolInAllow(
  client: ZolanaClient,
  ringProgramId: Address,
  authority: KeyPairSigner,
  parties: readonly Actor[],
): Promise<void> {
  for (const party of parties) {
    await writeList(client, ringProgramId, authority, {
      listId: ListId.allow,
      tag: party.keypair.shieldedAddress().confidentialViewTag(),
      state: "active",
    });
  }
}

export { RingListNamespace };
