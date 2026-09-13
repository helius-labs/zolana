import type { BlockhashProvider, Prover, RingHeadReader, SlotReader } from "../client/ports.js";
import { ClientError } from "../client/error.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { hashBytes, initializePoseidon } from "../hasher/index.js";
import type { SignerAccount } from "../interface/instructions/index.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { bigIntBytes, hashChain } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchRingConfigs, fetchRingHeadMapRoot, ringPolicyNamespaceAddress } from "./config.js";
import { proveRingSpendRegistration, type RingEntryProofClient } from "./entry-proof.js";
import { RingError } from "./error.js";
import { HEAD_MAP_CAPACITY, checkedHeadMapField, verifyHeadMapInsert } from "./head-map.js";
import {
  registerRingSpendInstruction,
  RING_REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
} from "./instructions.js";
import { memberOfTag, memberOfIdentity, type LiveSpendRecord } from "./policy.js";
import { readCurrentSpendRecord } from "./head-reader.js";
import { RingTransactionSubmission, type RingSubmissionAttempt } from "./submission.js";
import { readVelocityFacts, type VelocityFacts } from "./velocity.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { SpendSession } from "../transaction/wallet/authority.js";

export type RingSpendRegistrationClient = RingEntryProofClient &
  RingHeadReader &
  BlockhashProvider &
  SlotReader &
  Pick<Prover, "proveCustomRingRegister">;

export interface RingSpendRegistrationParams {
  readonly client: RingSpendRegistrationClient;
  readonly ringProgramId: Address;
  /** The payer must be the registering member. */
  readonly payer: SignerAccount;
  readonly priorityFeeLamports?: bigint;
}

export type RingSpendRegistrationPreparation =
  | Readonly<{ kind: "registered"; record: LiveSpendRecord }>
  | Readonly<{ kind: "pending"; submission: RingTransactionSubmission }>;

export async function prepareRingSpendRegistration(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<RingSpendRegistrationPreparation> {
  await initializePoseidon();
  const configs = await fetchRingConfigs(input.client, input.ringProgramId, context);
  if (!configs.hasPolicy || configs.policy.windowSlots === 0n || configs.policy.velocityCount === 0)
    throw new RingError("RING_VELOCITY_DISABLED");
  const payer = typeof input.payer === "string" ? input.payer : input.payer.address;
  const member = memberOfTag(addressBytes(payer));
  try {
    const { live } = await readCurrentSpendRecord(
      {
        client: input.client,
        ringProgramId: input.ringProgramId,
        namespace: await ringPolicyNamespaceAddress(input.ringProgramId),
        entriesTree: configs.policy.entriesTree,
        entriesTreeId: configs.policy.entriesTreeId,
        sender: member,
      },
      context,
    );
    return { kind: "registered", record: live };
  } catch (cause) {
    if (!(cause instanceof ClientError) || cause.code !== "CLIENT_HEAD_MEMBER_UNREGISTERED")
      throw cause;
  }
  return {
    kind: "pending",
    submission: await createRingSpendRegistrationSubmission(input, context),
  };
}

export async function createRingSpendRegistrationSubmission(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const captured = { ...input };
  await initializePoseidon();
  const payer = typeof captured.payer === "string" ? captured.payer : captured.payer.address;
  const member = memberOfTag(addressBytes(payer));
  const intent = hashChain([
    checkedHeadMapField(hashBytes(addressBytes(captured.ringProgramId))),
    member,
  ]);
  const build = async (context?: RequestContext): Promise<RingSubmissionAttempt> => ({
    ...(await buildRegistrationAttempt(captured, context)),
    intentHash: intent,
    ringInstructionIndex: 0,
  });
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    release: () => {},
    windowChanged: async (window, context) =>
      (await captured.client.getSlot(context)) / window.slots !== window.index,
  });
}

/** Expired counters reset without decryption. */
export async function readRingVelocityState(
  input: Readonly<{
    client: Pick<RingSpendRegistrationClient, "getAccount" | "getRingHeadTransferProof"> &
      SlotReader;
    ringProgramId: Address;
    member: ShieldedAddress;
    session: Pick<SpendSession, "openSealedMessage">;
  }>,
  context?: RequestContext,
): Promise<VelocityFacts> {
  await initializePoseidon();
  const configs = await fetchRingConfigs(input.client, input.ringProgramId, context);
  if (!configs.hasPolicy || configs.policy.windowSlots === 0n || configs.policy.velocityCount === 0)
    throw new RingError("RING_VELOCITY_DISABLED");
  return readVelocityFacts(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      session: input.session,
      namespace: await ringPolicyNamespaceAddress(input.ringProgramId),
      entriesTree: configs.policy.entriesTree,
      entriesTreeId: configs.policy.entriesTreeId,
      sender: memberOfIdentity(input.member.signingPublicKey.ownerProofInputHash()),
      windowSlots: configs.policy.windowSlots,
      rows: configs.policy.velocity,
    },
    context,
  );
}

export async function buildRingSpendRegistrationTransaction(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (await buildRegistrationAttempt({ ...input }, context)).transaction;
}

async function buildRegistrationAttempt(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<Pick<RingSubmissionAttempt, "transaction" | "window">> {
  await initializePoseidon();
  const configs = await fetchRingConfigs(input.client, input.ringProgramId, context);
  if (!configs.hasPolicy || configs.policy.windowSlots === 0n || configs.policy.velocityCount === 0)
    throw new RingError("RING_VELOCITY_DISABLED");
  const payer = typeof input.payer === "string" ? input.payer : input.payer.address;
  const member = memberOfTag(addressBytes(payer));
  const windowIndex = (await input.client.getSlot(context)) / configs.policy.windowSlots;
  const root = await fetchRingHeadMapRoot(input.client, input.ringProgramId, context);
  if (root.nextIndex >= HEAD_MAP_CAPACITY)
    throw new RingError("RING_HEAD_MAP_INVALID", { details: { reason: "capacity" } });
  const head = await input.client.getRingHeadRegisterProof(
    {
      ringProgramId: input.ringProgramId,
      member,
      expectedRoot: root.root,
      expectedNextIndex: root.nextIndex,
    },
    context,
  );
  if (
    !equalBytes(head.root, root.root) ||
    !equalBytes(head.member, member) ||
    head.nextIndex !== root.nextIndex
  )
    throw new RingError("RING_HEAD_MAP_STALE");
  const entry = await proveRingSpendRegistration(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      entriesTree: configs.policy.entriesTree,
      entriesTreeId: configs.policy.entriesTreeId,
      payer,
      member,
      windowIndex,
    },
    context,
  );
  const headNewRoot = verifyHeadMapInsert({
    root: root.root,
    appendIndex: root.nextIndex,
    member,
    genesis: entry.genesis,
    lowMember: head.lowMember,
    lowNext: head.lowNext,
    lowNullifier: head.lowNullifier,
    lowIndex: head.lowIndex,
    lowProof: head.lowProof,
    newProof: head.newProof,
  });
  const publicInputHash = hashChain([
    root.root,
    headNewRoot,
    member,
    entry.genesis,
    bigIntBytes(root.nextIndex) as Bytes32,
  ]);
  const headProof = await input.client.proveCustomRingRegister(
    {
      publicInputHash,
      headOldRoot: root.root,
      headNewRoot,
      member,
      genesis: entry.genesis,
      newIndex: root.nextIndex,
      lowMember: head.lowMember,
      lowNext: head.lowNext,
      lowNullifier: head.lowNullifier,
      lowIndex: head.lowIndex,
      lowProof: head.lowProof,
      newProof: head.newProof,
    },
    context,
  );
  const instruction = await registerRingSpendInstruction({
    ringProgramId: input.ringProgramId,
    payer: input.payer,
    entriesTree: configs.policy.entriesTree,
    blinding: entry.record.blinding,
    proof: entry.proof,
    headOldRoot: root.root,
    headNewRoot,
    headNextIndex: root.nextIndex,
    headProof,
  });
  const transaction = compileUnsignedTransaction({
    feePayer: payer,
    lifetime: await input.client.getLatestBlockhash(context),
    instructions: [instruction],
    computeUnitLimit: RING_REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
    ...(input.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.priorityFeeLamports }),
  });
  return { transaction, window: { index: windowIndex, slots: configs.policy.windowSlots } };
}
