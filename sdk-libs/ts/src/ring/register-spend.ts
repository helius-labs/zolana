import type { BlockhashProvider, Prover, RingHeadReader, SlotReader } from "../client/ports.js";
import { ClientError } from "../client/error.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { hashBytes, initializePoseidon } from "../hasher/index.js";
import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { bigIntBytes, hashChain } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import type { RingPolicyConfig } from "./codecs.js";
import {
  fetchRingConfigs,
  fetchRingHeadMapRoot,
  ringPolicyNamespaceAddress,
  windowedPolicy,
} from "./config.js";
import { proveRingSpendRegistration, type RingEntryProofClient } from "./entry-proof.js";
import { RingError } from "./error.js";
import { HEAD_MAP_CAPACITY, checkedHeadMapField, verifyHeadMapInsert } from "./head-map.js";
import {
  registerRingSpendInstruction,
  RING_REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
} from "./instructions.js";
import { memberOfTag, memberOfIdentity, type LiveSpendRecord, type Member } from "./policy.js";
import { readCurrentSpendRecord } from "./head-reader.js";
import {
  RingTransactionSubmission,
  windowChangedOn,
  type RingSubmissionAttempt,
} from "./submission.js";
import { readVelocityFacts, type VelocityFacts } from "./velocity.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";

export type RingSpendRegistrationClient = RingEntryProofClient &
  RingHeadReader &
  BlockhashProvider &
  SlotReader &
  Pick<Prover, "proveCustomRingRegister">;

/** Registers the member's initial record and compressed head atomically. */
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
  const registration = await registrationContext(input, context);
  try {
    const { live } = await readCurrentSpendRecord(
      {
        client: input.client,
        ringProgramId: input.ringProgramId,
        namespace: await ringPolicyNamespaceAddress(input.ringProgramId),
        entriesTree: registration.policy.entriesTree,
        entriesTreeId: registration.policy.entriesTreeId,
        sender: registration.member,
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
    submission: await registrationSubmission({ params: input, registration }, context),
  };
}

export async function createRingSpendRegistrationSubmission(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const registration = await registrationContext(input, context);
  return registrationSubmission({ params: input, registration }, context);
}

/** Expired counters reset without decryption. */
export async function readRingVelocityState(
  input: Readonly<{
    client: Pick<RingSpendRegistrationClient, "getAccount" | "getRingHeadTransferProof"> &
      SlotReader;
    ringProgramId: Address;
    member: ShieldedAddress;
    keys: ShieldedKeys;
  }>,
  context?: RequestContext,
): Promise<VelocityFacts> {
  await initializePoseidon();
  const policy = windowedPolicy(await fetchRingConfigs(input.client, input.ringProgramId, context));
  if (policy === undefined) throw new RingError("RING_VELOCITY_DISABLED");
  return readVelocityFacts(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      keys: input.keys,
      namespace: await ringPolicyNamespaceAddress(input.ringProgramId),
      entriesTree: policy.entriesTree,
      entriesTreeId: policy.entriesTreeId,
      sender: memberOfIdentity(input.member.signingPublicKey.ownerProofInputHash()),
      windowSlots: policy.windowSlots,
      rows: policy.velocity,
    },
    context,
  );
}

export async function buildRingSpendRegistrationTransaction(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<Transaction> {
  const registration = await registrationContext(input, context);
  return (await buildRegistrationAttempt({ params: input, registration }, context)).transaction;
}

/** Pins the member identity and policy used for record creation. */
interface Registration {
  readonly policy: RingPolicyConfig;
  readonly payer: Address;
  readonly member: Member;
}

type RegistrationBuild = Readonly<{
  params: RingSpendRegistrationParams;
  registration: Registration;
}>;

async function registrationContext(
  input: RingSpendRegistrationParams,
  context?: RequestContext,
): Promise<Registration> {
  await initializePoseidon();
  const policy = windowedPolicy(await fetchRingConfigs(input.client, input.ringProgramId, context));
  if (policy === undefined) throw new RingError("RING_VELOCITY_DISABLED");
  const payer = signerAddress(input.payer);
  return Object.freeze({ policy, payer, member: memberOfTag(addressBytes(payer)) });
}

async function registrationSubmission(
  input: RegistrationBuild,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const held: RegistrationBuild = Object.freeze({
    params: Object.freeze({ ...input.params }),
    registration: input.registration,
  });
  const intent = hashChain([
    checkedHeadMapField(hashBytes(addressBytes(held.params.ringProgramId))),
    held.registration.member,
  ]);
  const build = async (context?: RequestContext): Promise<RingSubmissionAttempt> => ({
    ...(await buildRegistrationAttempt(held, context)),
    intentHash: intent,
    ringInstructionIndex: 0,
  });
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    windowChanged: windowChangedOn(held.params.client),
  });
}

async function buildRegistrationAttempt(
  input: RegistrationBuild,
  context?: RequestContext,
): Promise<Pick<RingSubmissionAttempt, "transaction" | "lastValidBlockHeight" | "window">> {
  const { params, registration } = input;
  const { policy, payer, member } = registration;
  // 1. Pin the window and authenticate the member's empty head.
  const windowIndex = (await params.client.getSlot(context)) / policy.windowSlots;
  const root = await fetchRingHeadMapRoot(params.client, params.ringProgramId, context);
  if (root.nextIndex >= HEAD_MAP_CAPACITY)
    throw new RingError("RING_HEAD_MAP_INVALID", { details: { reason: "capacity" } });
  const head = await params.client.getRingHeadRegisterProof(
    {
      ringProgramId: params.ringProgramId,
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
  // 2. Prove creation of the initial compressed record.
  const entry = await proveRingSpendRegistration(
    {
      client: params.client,
      ringProgramId: params.ringProgramId,
      entriesTree: policy.entriesTree,
      entriesTreeId: policy.entriesTreeId,
      payer,
      member,
      windowIndex,
    },
    context,
  );
  // 3. Bind head insertion to the nullifier of that exact record.
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
  const headProof = await params.client.proveCustomRingRegister(
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
    ringProgramId: params.ringProgramId,
    payer: params.payer,
    entriesTree: policy.entriesTree,
    blinding: entry.record.blinding,
    proof: entry.proof,
    headOldRoot: root.root,
    headNewRoot,
    headNextIndex: root.nextIndex,
    headProof,
  });
  const lifetime = await params.client.getLatestBlockhash(context);
  const transaction = compileUnsignedTransaction({
    feePayer: payer,
    lifetime,
    instructions: [instruction],
    computeUnitLimit: RING_REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
    ...(params.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: params.priorityFeeLamports }),
  });
  return {
    transaction,
    lastValidBlockHeight: lifetime.lastValidBlockHeight,
    window: { index: windowIndex, slots: policy.windowSlots },
  };
}
