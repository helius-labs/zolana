import type { BlockhashProvider, ChainReader } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import type { Address, RequestContext, Transaction } from "../interface/types.js";

import type { RingPolicyConfig } from "./codecs.js";
import { fetchRingPolicyConfig } from "./config.js";
import { wrapRingError, RingError } from "./error.js";
import {
  RING_CREATE_POLICY_COMPUTE_UNIT_LIMIT,
  RING_SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
  RING_SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
  createRingPolicyInstruction,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
  type RingPolicySourceOwner,
  type RingPolicyTableInput,
  type RingSharedSource,
} from "./instructions.js";
import type { ListId } from "./policy.js";

export type RingPolicyAdminClient = BlockhashProvider & Pick<ChainReader, "getAccount">;

interface RingPolicyAdminParams {
  readonly client: RingPolicyAdminClient;
  readonly ringProgramId: Address;
  readonly computeUnitLimit?: number;
  readonly computeUnitPriceMicroLamports?: bigint;
}

export interface RingCreatePolicyTransactionParams
  extends RingPolicyAdminParams, RingPolicyTableInput {
  readonly payer: Address;
  /** The upgrade authority. */
  readonly authority: Address;
  readonly entriesTree: Address;
}

/** Pins the table at generation one. */
export async function buildRingCreatePolicyTransaction(
  params: RingCreatePolicyTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const instruction = await createRingPolicyInstruction(params);
    await checkCurators(params, params.entriesTree, params.sharedSources ?? [], context);
    const lifetime = await params.client.getLatestBlockhash(context);
    return compileUnsignedTransaction({
      feePayer: params.payer,
      lifetime,
      instructions: [instruction],
      computeUnitLimit: params.computeUnitLimit ?? RING_CREATE_POLICY_COMPUTE_UNIT_LIMIT,
      ...priceOption(params),
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

export interface RingSetPolicyRulesTransactionParams
  extends RingPolicyAdminParams, RingPolicyTableInput {
  /** The upgrade authority, also the fee payer. */
  readonly authority: Address;
}

/** Replaces the pinned table, a proof over the old hash fails from the next slot on. */
export async function buildRingSetPolicyRulesTransaction(
  params: RingSetPolicyRulesTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const instruction = await setRingPolicyRulesInstruction(params);
    const own = await fetchRingPolicyConfig(params.client, params.ringProgramId, context);
    await checkCurators(params, own.entriesTree, params.sharedSources ?? [], context);
    const lifetime = await params.client.getLatestBlockhash(context);
    return compileUnsignedTransaction({
      feePayer: params.authority,
      lifetime,
      instructions: [instruction],
      computeUnitLimit: params.computeUnitLimit ?? RING_SET_POLICY_RULES_COMPUTE_UNIT_LIMIT,
      ...priceOption(params),
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

export interface RingSetPolicySourceTransactionParams extends RingPolicyAdminParams {
  /** The config authority, also the fee payer. */
  readonly authority: Address;
  readonly listId: ListId;
  readonly source: RingPolicySourceOwner;
}

/** Re-points one referenced list, the rows stay. */
export async function buildRingSetPolicySourceTransaction(
  params: RingSetPolicySourceTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const own = await fetchRingPolicyConfig(params.client, params.ringProgramId, context);
    if (own.sources[params.listId - 1]?.listId !== params.listId) {
      throw new RingError("RING_POLICY_SOURCE_INVALID", {
        details: { reason: "UnreferencedList", listId: params.listId },
      });
    }
    if (params.source.kind === "curator") {
      await checkCurators(
        params,
        own.entriesTree,
        [{ listId: params.listId, curatorRingProgramId: params.source.ringProgramId }],
        context,
      );
    }
    const [instruction, lifetime] = await Promise.all([
      setRingPolicySourceInstruction(params),
      params.client.getLatestBlockhash(context),
    ]);
    return compileUnsignedTransaction({
      feePayer: params.authority,
      lifetime,
      instructions: [instruction],
      computeUnitLimit: params.computeUnitLimit ?? RING_SET_POLICY_SOURCE_COMPUTE_UNIT_LIMIT,
      ...priceOption(params),
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_POLICY", cause);
  }
}

/** The checks `load_curator_policy_config` and `resolve_sources` apply on chain. */
async function checkCurators(
  params: RingPolicyAdminParams,
  entriesTree: Address,
  shared: readonly RingSharedSource[],
  context: RequestContext | undefined,
): Promise<void> {
  const curators = new Map<Address, RingPolicyConfig>();
  for (const source of shared) {
    const curator =
      curators.get(source.curatorRingProgramId) ??
      (await fetchRingPolicyConfig(params.client, source.curatorRingProgramId, context));
    curators.set(source.curatorRingProgramId, curator);
    if (curator.entriesTree !== entriesTree) {
      throw new RingError("RING_POLICY_SOURCE_INVALID", {
        details: { reason: "CuratorTreeMismatch", listId: source.listId },
      });
    }
    if (curator.sources[source.listId - 1]?.listId !== source.listId) {
      throw new RingError("RING_POLICY_SOURCE_INVALID", {
        details: { reason: "CuratorSourceMissing", listId: source.listId },
      });
    }
  }
}

function priceOption(
  params: RingPolicyAdminParams,
): Readonly<{ computeUnitPriceMicroLamports?: bigint }> {
  return params.computeUnitPriceMicroLamports === undefined
    ? {}
    : { computeUnitPriceMicroLamports: params.computeUnitPriceMicroLamports };
}
