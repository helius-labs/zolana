import type { Address } from "@solana/kit";

import type { IndexerReader } from "../client/ports.js";
import type { Bytes32, RequestContext } from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { ViewingKey } from "../keypair/viewing-key.js";
import type { AssetRegistry } from "../transaction/asset.js";
import type { OutputContext } from "../transaction/instructions/transact.js";
import { equal } from "../transaction/internal.js";
import { Utxo, type TreeId } from "../transaction/utxo.js";
import type { WalletUtxo } from "../transaction/wallet/state.js";
import { bytesKey } from "../wallet/internal.js";
import { auditRing, type RingAuditReader } from "./audit.js";
import { RingError } from "./error.js";
import type { TransactionOrigin } from "./origin.js";
import { memberOfTag } from "./policy.js";

export type RingRecoveryClient = RingAuditReader &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers">;

export interface RingRecoveryParams {
  readonly client: RingRecoveryClient;
  readonly ringProgramId: Address;
  readonly auditor: ViewingKey;
  readonly source: ShieldedAddress;
  readonly nullifierKey: NullifierKey;
  readonly assets: AssetRegistry;
  /** The raw id a note's leaf is committed under. */
  readonly resolveTreeId: (tree: Address) => TreeId | Promise<TreeId>;
  readonly origin?: TransactionOrigin;
  readonly pageSize?: number;
  readonly maxPages?: number;
}

export interface RecoveredRingNotes {
  readonly notes: readonly WalletUtxo[];
  /** Commitments no rebuilt opening reproduces. */
  readonly unopened: readonly Bytes32[];
}

interface Candidate {
  readonly utxo: Utxo;
  readonly outputContext: OutputContext;
  readonly nullifier: Bytes32;
}

/** Mirrors Rust `RingRecovery`, a merge publishes no auditor message and the indexer alone sees every spend. */
export async function recoverRingMemberNotes(
  input: RingRecoveryParams,
  context?: RequestContext,
): Promise<RecoveredRingNotes> {
  if (!equal(input.nullifierKey.publicKey(), input.source.nullifierPublicKey))
    throw new RingError("RING_NULLIFIER_KEY_MISMATCH");
  const sourceMember = memberOfTag(input.source.confidentialViewTag());
  const page = await auditRing(
    {
      client: input.client,
      auditor: input.auditor,
      ringProgramId: input.ringProgramId,
      assets: input.assets,
      ...(input.origin === undefined ? {} : { origin: input.origin }),
      ...(input.pageSize === undefined ? {} : { pageSize: input.pageSize }),
      ...(input.maxPages === undefined ? {} : { maxPages: input.maxPages }),
    },
    context,
  );
  if (page.nextCursor !== undefined) throw new RingError("RING_RECOVERY_INCOMPLETE");
  const candidates: Candidate[] = [];
  const unopened: Bytes32[] = [];
  const seen = new Set<string>();
  const treeIds = new Map<Address, TreeId>();
  for (const transaction of page.transactions) {
    for (const output of transaction.outputs) {
      if (
        !output.recipientViewingPublicKey.equals(input.source.viewingPublicKey) ||
        !equal(memberOfTag(output.ownerTag), sourceMember)
      )
        continue;
      const { outputContext } = output;
      const key = bytesKey(outputContext.hash);
      if (seen.has(key)) continue;
      seen.add(key);
      let treeId = treeIds.get(outputContext.tree);
      if (treeId === undefined) {
        treeId = await input.resolveTreeId(outputContext.tree);
        treeIds.set(outputContext.tree, treeId);
      }
      const utxo = new Utxo({
        owner: input.source.signingPublicKey,
        asset: output.asset,
        amount: output.amount,
        blinding: output.blinding,
        data: output.data,
        ...(output.ringProgramId === undefined ? {} : { ringProgramId: output.ringProgramId }),
      });
      // A hash match proves the rebuilt opening is the leaf on chain.
      if (!equal(utxo.hash(input.source.nullifierPublicKey, treeId), outputContext.hash)) {
        unopened.push(outputContext.hash);
        continue;
      }
      candidates.push({
        utxo,
        outputContext,
        nullifier: utxo.nullifier(outputContext.hash, input.nullifierKey),
      });
    }
  }
  const spent = await spentNullifiers(
    input.client,
    candidates.map((candidate) => candidate.nullifier),
    context,
  );
  const notes = candidates
    .filter((candidate) => !spent.has(bytesKey(candidate.nullifier)))
    .map((candidate) =>
      Object.freeze({
        utxo: candidate.utxo,
        outputContext: candidate.outputContext,
        nullifier: candidate.nullifier,
        spent: false,
      }),
    );
  return Object.freeze({ notes: Object.freeze(notes), unopened: Object.freeze(unopened) });
}

async function spentNullifiers(
  client: Pick<IndexerReader, "getShieldedTransactionsByNullifiers">,
  nullifiers: readonly Bytes32[],
  context?: RequestContext,
): Promise<ReadonlySet<string>> {
  const spent = new Set<string>();
  if (nullifiers.length === 0) return spent;
  let cursor: Uint8Array | undefined;
  for (;;) {
    const page = await client.getShieldedTransactionsByNullifiers(
      { nullifiers, ...(cursor === undefined ? {} : { cursor }) },
      undefined,
      context,
    );
    for (const transaction of page.transactions) {
      for (const nullifier of transaction.nullifiers) spent.add(bytesKey(nullifier));
    }
    // A terminal page still names a cursor, only `scannedThrough` ends the scan.
    if (page.scannedThrough !== undefined || page.nextCursor === undefined) return spent;
    if (cursor !== undefined && equal(cursor, page.nextCursor))
      throw new RingError("RING_RPC", {
        details: { reason: "nullifier scan cursor did not advance" },
      });
    cursor = page.nextCursor;
  }
}
