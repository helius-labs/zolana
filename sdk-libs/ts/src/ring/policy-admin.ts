import type { BlockhashProvider, ChainReader } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { ringMemberRegistryAddress } from "../interface/pda/index.js";
import type { Address, Instruction, RequestContext, Transaction } from "../interface/types.js";

import {
  RingInstructionTag,
  createRingPolicyInstruction,
  ringComputeUnitLimit,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
  type RingPolicySourceOwner,
  type RingPolicyTableInput,
  type RingSharedSource,
} from "./admin.js";
import { registryCurator } from "./codecs.js";
import { fetchRingMemberRegistry, fetchRingProgramConfig } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import type { ListId } from "./policy.js";

export type RingPolicyAdminClient = BlockhashProvider & Pick<ChainReader, "getAccount">;

interface RingPolicyAdminParams {
  readonly client: RingPolicyAdminClient;
  readonly ringProgramId: Address;
  /** The config authority, also the fee payer. */
  readonly authority: Address;
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}

export interface RingCreatePolicyTransactionParams
  extends RingPolicyAdminParams, RingPolicyTableInput {}

/** Pins the table and its sources, a policy ring takes one before it registers with the pool. */
export async function buildRingCreatePolicyTransaction(
  params: RingCreatePolicyTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    await checkTier(params, context);
    await checkCurators(params, params.sharedSources ?? [], context);
    return await compile(
      params,
      await createRingPolicyInstruction(params),
      RingInstructionTag.createPolicy,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

export interface RingSetPolicyRulesTransactionParams
  extends RingPolicyAdminParams, RingPolicyTableInput {}

/** Replaces the pinned table and the complete source map, a proof over the old hash fails from the next slot. */
export async function buildRingSetPolicyRulesTransaction(
  params: RingSetPolicyRulesTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    await checkTier(params, context);
    await checkCurators(params, params.sharedSources ?? [], context);
    return await compile(
      params,
      await setRingPolicyRulesInstruction(params),
      RingInstructionTag.setPolicyRules,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

export interface RingSetPolicySourceTransactionParams extends RingPolicyAdminParams {
  readonly listId: ListId;
  readonly source: RingPolicySourceOwner;
}

/** Re-points one referenced list, the rows stay and the sources keep at most one curator. */
export async function buildRingSetPolicySourceTransaction(
  params: RingSetPolicySourceTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const registry = await fetchRingMemberRegistry(params.client, params.ringProgramId, context);
    if (registry.sources[params.listId - 1]?.listId !== params.listId)
      throw sourceInvalid("UnreferencedList", { listId: params.listId });
    if (params.source.kind === "curator") {
      const curator = await ringMemberRegistryAddress(params.source.ringProgramId);
      const others = registry.sources.filter((slot) => slot.listId !== params.listId);
      const current = registryCurator({ ...registry, sources: others });
      if (current !== undefined && current !== curator) throw sourceInvalid("MultipleCurators");
      await checkCurators(
        params,
        [{ listId: params.listId, curatorRingProgramId: params.source.ringProgramId }],
        context,
      );
    }
    return await compile(
      params,
      await setRingPolicySourceInstruction(params),
      RingInstructionTag.setPolicySource,
      context,
    );
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

/** An audit-only ring takes no policy, Rust `PolicyOnAuditOnlyRing`. */
async function checkTier(
  params: RingPolicyAdminParams,
  context: RequestContext | undefined,
): Promise<void> {
  const config = await fetchRingProgramConfig(params.client, params.ringProgramId, context);
  if (!config.hasPolicy)
    throw new RingError("RING_POLICY_TIER_MISMATCH", {
      details: { ringProgramId: params.ringProgramId },
    });
}

/** Every curator ring holds the registry the program loads, Rust `load_curator_registry`. */
async function checkCurators(
  params: RingPolicyAdminParams,
  shared: readonly RingSharedSource[],
  context: RequestContext | undefined,
): Promise<void> {
  const curators = new Set(shared.map((source) => source.curatorRingProgramId));
  if (curators.size > 1) throw sourceInvalid("MultipleCurators");
  for (const curator of curators) {
    if (curator === params.ringProgramId) throw sourceInvalid("OwnCurator");
    await fetchRingMemberRegistry(params.client, curator, context);
  }
}

async function compile(
  params: RingPolicyAdminParams,
  instruction: Instruction,
  tag: RingInstructionTag,
  context: RequestContext | undefined,
): Promise<Transaction> {
  const lifetime = await params.client.getLatestBlockhash(context);
  return compileUnsignedTransaction({
    feePayer: params.authority,
    lifetime,
    instructions: [instruction],
    computeUnitLimit: params.computeUnitLimit ?? ringComputeUnitLimit(tag),
    ...(params.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: params.priorityFeeLamports }),
  });
}

function sourceInvalid(reason: string, details: Readonly<Record<string, unknown>> = {}): RingError {
  return new RingError("RING_POLICY_SOURCE_INVALID", { details: { reason, ...details } });
}
