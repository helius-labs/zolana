import { customRingDepositPayload } from "../../src/ring/deposit-payload.js";
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
import {
  LocalKeys,
  ShieldedKeypair,
  SigningKey,
  Wallet,
  syncWallet,
  type Bytes32,
} from "../../src/index.js";
import { ClientError } from "../../src/client/error.js";
import type { MemberRecord } from "../../src/interface/member-registry.js";
import {
  ListId,
  memberOfTag,
  recordBit,
  verifyRecordOpening,
  type Member,
} from "../../src/ring/advanced.js";
import {
  AuthorityListWrite,
  RecordApplication,
  RingError,
  RingInstructionTag,
  fetchRingMemberRegistry,
  listWrite,
  messageSignerReader,
  registryCurrentRoot,
  ringComputeUnitLimit,
  type RingRpc,
} from "../../src/ring/index.js";
import { MEMBER_REGISTRY_PROJECTION_ERRORS } from "../../src/ring/projection.js";
import { currentSlot, signSendAndConfirm, waitForSignature, type Actor } from "./live-helpers.js";

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the ring live test requires ${name}`);
  return value;
}

export async function freshActor(client: ZolanaClient): Promise<Actor> {
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
    keys: LocalKeys.fromKeypair(keypair, client.proofService),
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

/** A proof-carrying ring instruction declares its tag's budget, any other the default. */
export async function sendInstruction(
  client: ZolanaClient,
  instruction: Instruction,
  signer: KeyPairSigner,
  computeUnitLimit = 200_000,
): Promise<void> {
  const lifetime = await client.getLatestBlockhash();
  const transaction = compileUnsignedTransaction({
    feePayer: signer.address,
    lifetime,
    computeUnitLimit,
    instructions: [instruction],
  });
  await signSendAndConfirm(client, transaction, [signer]);
}

export async function sync(client: ZolanaClient, actor: Actor): Promise<void> {
  await syncWallet({
    client,
    wallet: actor.wallet,
    keys: actor.keys,
    config: {
      depositPayloadDecoder: customRingDepositPayload,
      requireSlot: await currentSlot(client),
    },
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

export type ListState = "active" | "cleared";

/** A member's record under the registry's newest root, `undefined` for an absent member. */
export interface IndexedRecord {
  readonly member: Member;
  readonly root: Bytes32;
  readonly nextIndex: number;
  readonly record: MemberRecord | undefined;
}

/** The record Photon serves, authenticated against the root the registry account holds. */
export async function indexedRecord(
  client: ZolanaClient,
  ringProgramId: Address,
  member: Member,
): Promise<IndexedRecord> {
  const registry = await fetchRingMemberRegistry(client, ringProgramId);
  const { root } = registryCurrentRoot(registry);
  const read = await client.getRingMemberRecord({
    ringProgramId,
    member,
    expectedRoot: root,
    expectedNextIndex: registry.nextIndex,
  });
  return {
    member,
    root,
    nextIndex: registry.nextIndex,
    record: verifyRecordOpening(read.opening, root, member),
  };
}

/** Retries `read` while the indexer's registry projection lags the chain. */
export async function indexedKeys<T>(read: () => Promise<T>): Promise<T> {
  const lagging: ReadonlySet<string> = MEMBER_REGISTRY_PROJECTION_ERRORS;
  const deadline = Date.now() + 120_000;
  for (;;) {
    try {
      return await read();
    } catch (cause) {
      const code =
        cause instanceof ClientError
          ? cause.code
          : cause instanceof RingError
            ? cause.causeCode
            : undefined;
      if (code === undefined || !lagging.has(code) || Date.now() > deadline) throw cause;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

/** Polls until the registry holds `bit` in the wanted state, the indexer lags the chain. */
async function awaitLists(
  client: ZolanaClient,
  ringProgramId: Address,
  member: Member,
  bit: bigint,
  wanted: boolean,
): Promise<IndexedRecord> {
  for (let attempt = 0; attempt < 240; attempt++) {
    const read = await indexedKeys(() => indexedRecord(client, ringProgramId, member));
    if ((((read.record?.lists ?? 0n) & bit) !== 0n) === wanted) return read;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("member list update not indexed");
}

export type ListWriteOutcome =
  | Readonly<{ kind: "transaction"; member: Member }>
  | (Readonly<{ kind: "unchanged" }> & IndexedRecord);

/** Lands one authority write unless the bit already holds, then authenticates it against the registry root. */
export async function writeList(
  client: ZolanaClient,
  ringProgramId: Address,
  authority: KeyPairSigner,
  input: Readonly<{ listId: ListId; tag: Uint8Array; state: ListState }>,
): Promise<ListWriteOutcome> {
  const member = memberOfTag(input.tag);
  const bit = recordBit(input.listId);
  const wanted = input.state === "active";
  const current = await indexedKeys(() => indexedRecord(client, ringProgramId, member));
  if ((((current.record?.lists ?? 0n) & bit) !== 0n) === wanted)
    return { kind: "unchanged", ...current };
  const proven = await new AuthorityListWrite({
    ringProgramId,
    authority: authority.address,
  })
    .withWrite(member, listWrite(wanted ? { set: [input.listId] } : { clear: [input.listId] }))
    .prove(client);
  await sendInstruction(
    client,
    proven.instruction,
    authority,
    ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
  );
  await awaitLists(client, ringProgramId, member, bit, wanted);
  return { kind: "transaction", member };
}

/** Applies every queued member write once the queue is due, `payer` signs the application. */
export async function applyQueuedWrites(
  client: ZolanaClient,
  ringProgramId: Address,
  payer: KeyPairSigner,
): Promise<void> {
  const application = new RecordApplication(ringProgramId);
  for (let attempt = 0; attempt < 600; attempt++) {
    const proven = await application.prove(client);
    if (proven !== undefined) {
      await sendInstruction(
        client,
        proven.instruction,
        payer,
        ringComputeUnitLimit(RingInstructionTag.applyRecords),
      );
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("the record queue never became due");
}

/** Puts every party on the allow list in one authority write. */
export async function enrolInAllow(
  client: ZolanaClient,
  ringProgramId: Address,
  authority: KeyPairSigner,
  parties: readonly Actor[],
): Promise<void> {
  const bit = recordBit(ListId.allow);
  const members = parties.map((party) =>
    memberOfTag(party.keypair.shieldedAddress().confidentialViewTag()),
  );
  let write = new AuthorityListWrite({
    ringProgramId,
    authority: authority.address,
  });
  for (const member of members) {
    const current = await indexedKeys(() => indexedRecord(client, ringProgramId, member));
    if (((current.record?.lists ?? 0n) & bit) === 0n)
      write = write.withWrite(member, listWrite({ set: [ListId.allow] }));
  }
  if (write.writes().length === 0) return;
  await sendInstruction(
    client,
    (await write.prove(client)).instruction,
    authority,
    ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
  );
  for (const member of members) await awaitLists(client, ringProgramId, member, bit, true);
}
