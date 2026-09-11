import type { BlockhashProvider } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, RequestContext, Transaction } from "../interface/types.js";
import { U64_MAX, ZERO_32 } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";

import { fetchRingConfigs, ringPolicyNamespaceAddress } from "./config.js";
import { proveRingEntryTransition, type RingEntryProofClient } from "./entry-proof.js";
import { RingError, wrapRingError } from "./error.js";
import {
  RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
  createRingEntryInstruction,
  updateRingEntryInstruction,
} from "./instructions.js";
import {
  listWriter,
  memberOfTag,
  readRingEntry,
  type EntryIndexer,
  type EntryState,
  type ListEntry,
  type ListId,
  type LiveEntry,
  type Member,
} from "./policy.js";

export type RingListWriteClient = BlockhashProvider & RingEntryProofClient & EntryIndexer;

export interface RingListWriteTransactionParams {
  readonly client: RingListWriteClient;
  readonly ringProgramId: Address;
  readonly payer: Address;
  readonly listId: ListId;
  readonly member: Member;
  readonly state: EntryState;
  readonly computeUnitLimit?: number;
  readonly priorityFeeLamports?: bigint;
}

/** Mirrors Rust `EntryOutcome`, a write the entry already carries makes no transaction. */
export type RingListWrite =
  | Readonly<{ kind: "unchanged"; entry: LiveEntry }>
  | Readonly<{
      kind: "transaction";
      transaction: Transaction;
      entry: ListEntry;
      change: "claimed" | "moved";
    }>;

/** Mirrors Rust `EntryMutation::apply` up to the send. */
export async function buildRingListWriteTransaction(
  params: RingListWriteTransactionParams,
  context?: RequestContext,
): Promise<RingListWrite> {
  try {
    const configs = await fetchRingConfigs(params.client, params.ringProgramId, context);
    if (!configs.hasPolicy) {
      throw new RingError("RING_POLICY_CONFIG_NOT_FOUND", {
        details: { ringProgramId: params.ringProgramId },
      });
    }
    const { config, policy } = configs;
    const namespace = await ringPolicyNamespaceAddress(params.ringProgramId);
    const source = policy.sources[params.listId - 1];
    if (source !== undefined && source.listId !== 0 && source.namespace !== namespace) {
      throw new RingError("RING_LIST_SHARED", {
        details: { listId: params.listId, namespace: source.namespace },
      });
    }
    checkMutator(params, config.authority);
    const live = await readRingEntry(
      {
        indexer: params.client,
        entriesTree: policy.entriesTree,
        entriesTreeId: policy.entriesTreeId,
        namespace,
        listId: params.listId,
        member: params.member,
      },
      context,
    );
    if (live !== undefined && live.entry.state === params.state) {
      return Object.freeze({ kind: "unchanged", entry: live });
    }
    if (live !== undefined && live.entry.version >= U64_MAX) {
      throw new RingError("RING_ENTRY_INVALID", { details: { reason: "versionOverflow" } });
    }
    const { entry, proof } = await proveRingEntryTransition(
      {
        client: params.client,
        ringProgramId: params.ringProgramId,
        entriesTree: policy.entriesTree,
        entriesTreeId: policy.entriesTreeId,
        payer: params.payer,
        entry: {
          listId: params.listId,
          member: params.member,
          state: params.state,
          version: live === undefined ? 0n : live.entry.version + 1n,
          contentHash: ZERO_32,
        },
        ...(live === undefined ? {} : { spent: live.entry }),
      },
      context,
    );
    const instructionInput = {
      ringProgramId: params.ringProgramId,
      payer: params.payer,
      entriesTree: policy.entriesTree,
      entry,
      proof,
    };
    const [instruction, lifetime] = await Promise.all([
      live === undefined
        ? createRingEntryInstruction(instructionInput)
        : updateRingEntryInstruction({ ...instructionInput, spent: live.entry }),
      params.client.getLatestBlockhash(context),
    ]);
    return Object.freeze({
      kind: "transaction",
      transaction: compileUnsignedTransaction({
        feePayer: params.payer,
        lifetime,
        instructions: [instruction],
        computeUnitLimit: params.computeUnitLimit ?? RING_ENTRY_MUTATION_COMPUTE_UNIT_LIMIT,
        ...(params.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: params.priorityFeeLamports }),
      }),
      entry,
      change: live === undefined ? "claimed" : "moved",
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_LIST_WRITE", cause);
  }
}

/** Mirrors Rust `check_mutator`, refused before any indexer or prover call. */
function checkMutator(params: RingListWriteTransactionParams, authority: Address): void {
  const writer = listWriter(params.listId);
  const authorized =
    writer === "member"
      ? equalBytes(memberOfTag(addressBytes(params.payer, "payer")), params.member)
      : params.payer === authority;
  if (!authorized) {
    throw new RingError("RING_LIST_WRITER_UNAUTHORIZED", {
      details: { listId: params.listId, writer },
    });
  }
}
