import type {
  BlockhashProvider,
  ChainReader,
  RingSpendRecordReader,
  SlotReader,
} from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { hashBytes, initializePoseidon } from "../hasher/index.js";
import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, RequestContext, Transaction } from "../interface/types.js";
import { hashChain } from "../transaction/internal.js";
import type { RingPolicyConfig } from "./codecs.js";
import { fetchRingConfigs, ringPolicyNamespaceAddress, windowedPolicy } from "./config.js";
import { proveRingSpendRegistration, type RingEntryProofClient } from "./entry-proof.js";
import { RingError } from "./error.js";
import { checkedHeadMapField } from "./head-map.js";
import {
  registerRingSpendInstruction,
  RING_REGISTER_SPEND_COMPUTE_UNIT_LIMIT,
} from "./instructions.js";
import {
  memberOfTag,
  memberOfIdentity,
  type LiveSpendRecord,
  type Member,
  type RingRecordTrees,
} from "./policy.js";
import { findCurrentSpendRecord } from "./spend-record-reader.js";
import {
  RingTransactionSubmission,
  windowChangedOn,
  type RingSubmissionAttempt,
} from "./submission.js";
import { ringTreeIdResolver } from "./trees.js";
import { readVelocityFacts, type VelocityFacts } from "./velocity.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";

export type RingSpendRegistrationClient = RingEntryProofClient &
  RingSpendRecordReader &
  BlockhashProvider &
  SlotReader;

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
  const live = await findCurrentSpendRecord(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      namespace: await ringPolicyNamespaceAddress(input.ringProgramId),
      ...recordTrees(input.client, registration.policy, context),
      sender: registration.member,
    },
    context,
  );
  if (live !== undefined) return { kind: "registered", record: live };
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
    client: Pick<RingSpendRegistrationClient, "getAccount" | "getRingSpendRecord"> & SlotReader;
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
      ...recordTrees(input.client, policy, context),
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

/** Records claim their address in the policy's address tree and may land in any tree. */
function recordTrees(
  client: Pick<ChainReader, "getAccount">,
  policy: RingPolicyConfig,
  context: RequestContext | undefined,
): RingRecordTrees {
  const addressTree = { tree: policy.addressTree, treeId: policy.addressTreeId };
  return {
    addressTreeId: addressTree.treeId,
    resolveTreeId: ringTreeIdResolver(client, [addressTree], context),
  };
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
  const windowIndex = (await params.client.getSlot(context)) / policy.windowSlots;
  const addressTree = { tree: policy.addressTree, treeId: policy.addressTreeId };
  const entry = await proveRingSpendRegistration(
    {
      client: params.client,
      ringProgramId: params.ringProgramId,
      addressTree,
      outputTree: addressTree,
      payer,
      member,
      windowIndex,
    },
    context,
  );
  const instruction = await registerRingSpendInstruction({
    ringProgramId: params.ringProgramId,
    payer: params.payer,
    inputTree: addressTree.tree,
    outputTree: addressTree.tree,
    blinding: entry.record.blinding,
    proof: entry.proof,
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
