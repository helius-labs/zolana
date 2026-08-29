import { getAddressEncoder } from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { P256PublicKey, ShieldedPublicKey } from "../keypair/public-key.js";
import { ShieldedAddress, type ShieldedKeypair } from "../keypair/shielded.js";
import { Merge, type PreparedMerge } from "../transaction/instructions/builders.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { WalletAuthority, WalletSyncMaterial } from "../transaction/wallet/authority.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";

import { MERGE_INPUT_COUNT } from "../interface/constants.js";
import {
  isPlainUtxo,
  selectNotes,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "../flows/select.js";
import { reservedNoteKeys, unreserved } from "../flows/reserve.js";
import { checkIntentApproval, type TransactionIntent } from "../transaction/wallet/intent.js";
import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey, equalBytes, reserveWalletEntries } from "./internal.js";
import { internalMergeRecord, type MergeRecord } from "./registry.js";

const addressEncoder = getAddressEncoder();

/** @internal */
export interface MergeParams {
  readonly wallet: Wallet;
  readonly material: MergeMaterial;
  readonly asset: Address;
  readonly inputs?: readonly Bytes32[];
}

/** @internal */
export interface CreatedMerge {
  readonly prepared: PreparedMerge;
  readonly numInputs: number;
  readonly mergedAmount: bigint;
  readonly tree: Address;
  readonly reservationId: string;
}

const mergeSelectionErrors: SpendSelectionErrors = {
  insufficient: () => new WalletError("WALLET_NOTHING_TO_MERGE"),
  tooManyInputs: ({ eligible, max }) =>
    new WalletError("WALLET_TOO_MANY_INPUTS", { details: { got: eligible, max } }),
  overflow: ({ available }) =>
    new WalletError("WALLET_SELECTED_BALANCE_OVERFLOW", {
      details: { available: available.toString() },
    }),
  multipleTrees: () => new WalletError("WALLET_MULTIPLE_INPUT_TREES"),
  tooFewNotes: () => new WalletError("WALLET_NOTHING_TO_MERGE"),
};

function mergePolicy(reserved: ReadonlySet<string>): SpendPolicy {
  return {
    eligible: (entry) => isPlainUtxo(entry) && unreserved(reserved)(entry),
    ordering: "smallestFirst",
    maxInputs: MERGE_INPUT_COUNT,
    tree: { kind: "inferSingle" },
    errors: mergeSelectionErrors,
  };
}

/** @internal */
export function createMerge(params: MergeParams): CreatedMerge {
  const selected = selectMergeEntries(params);
  const tree = selected[0]?.outputContext.tree;
  if (tree === undefined) throw new WalletError("WALLET_NOTHING_TO_MERGE");
  if (selected.some((entry) => entry.outputContext.tree !== tree)) {
    throw new WalletError("WALLET_INPUT_UTXO_TREE_MISMATCH");
  }
  const reservation = reserveWalletEntries(params.wallet, selected);
  try {
    const nullifierKey = params.material.nullifierKey;
    const inputs = selected.map(
      (entry) =>
        new ProofInputUtxo({
          utxo: entry.utxo,
          nullifierKey,
          ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
          ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
        }),
    );
    const prepared = new Merge(
      {
        address: ShieldedAddress.fromPublicKeys(
          params.material.signingPublicKey,
          params.material.nullifierKey.publicKey(),
          params.material.viewingPublicKey,
        ),
        nullifierKey,
      },
      inputs,
    ).prepare();
    return Object.freeze({
      prepared,
      numInputs: selected.length,
      mergedAmount: prepared.output.amount,
      tree,
      reservationId: reservation.id,
    });
  } catch (cause) {
    params.wallet._releaseReservation(reservation.id);
    throw cause;
  }
}

function selectMergeEntries(params: MergeParams): readonly WalletUtxo[] {
  const hashes = params.inputs;
  if (hashes !== undefined) {
    const entries = params.wallet
      .utxos()
      .filter((entry) => !entry.spent && entry.utxo.asset === params.asset);
    if (hashes.length < 2) throw new WalletError("WALLET_NOTHING_TO_MERGE");
    if (hashes.length > MERGE_INPUT_COUNT) {
      throw new WalletError("WALLET_TOO_MANY_INPUTS", {
        details: { got: hashes.length, max: MERGE_INPUT_COUNT },
      });
    }
    const seen = new Set<string>();
    return hashes.map((hash) => {
      const key = bytesKey(hash);
      if (seen.has(key)) throw new WalletError("WALLET_DUPLICATE_INPUT_UTXO");
      seen.add(key);
      const entry = entries.find((candidate) => equalBytes(candidate.outputContext.hash, hash));
      if (entry === undefined) throw new WalletError("WALLET_INPUT_UTXO_UNAVAILABLE");
      return entry;
    });
  }
  return selectNotes({
    wallet: params.wallet,
    asset: params.asset,
    target: { kind: "consolidate", minInputs: 2 },
    policy: mergePolicy(reservedNoteKeys(params.wallet)),
  }).entries;
}

/** @internal */
export class MergeMaterial {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;
  readonly nullifierKey: NullifierKey;

  constructor(
    input: Readonly<{
      signingPublicKey: ShieldedPublicKey;
      viewingPublicKey: P256PublicKey;
      nullifierKey: NullifierKey;
    }>,
  ) {
    this.signingPublicKey = input.signingPublicKey;
    this.viewingPublicKey = input.viewingPublicKey;
    this.nullifierKey = input.nullifierKey;
  }

  static fromKeypair(keypair: ShieldedKeypair): MergeMaterial {
    return new MergeMaterial({
      signingPublicKey: keypair.signingPublicKey(),
      viewingPublicKey: keypair.viewingPublicKey(),
      nullifierKey: keypair.nullifierKey(),
    });
  }

  static fromSyncMaterial(material: WalletSyncMaterial): MergeMaterial {
    return new MergeMaterial({
      signingPublicKey: material.identity.signingPublicKey,
      viewingPublicKey: material.identity.viewingPublicKey,
      nullifierKey: material.nullifierKey,
    });
  }
}

export interface MergeTransactionParams {
  readonly client: ZolanaClient;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
  readonly asset?: Address;
  readonly inputs?: readonly Bytes32[];
}

export async function buildMergeTransaction(
  input: MergeTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const owner = input.authority.solanaPublicKey();
    return await input.authority.withSyncSession(async (keys) => {
      const material = MergeMaterial.fromSyncMaterial(await keys.syncMaterial());
      const created = createMerge({
        wallet: input.wallet,
        material,
        asset: input.asset ?? SOL_MINT,
        ...(input.inputs === undefined ? {} : { inputs: input.inputs }),
      });
      try {
        return await proveAndAssembleMerge(input, owner, material, created, context);
      } catch (cause) {
        input.wallet._releaseReservation(created.reservationId);
        throw cause;
      } finally {
        for (const proofInput of created.prepared.inputs) proofInput.destroy();
      }
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_MERGE", cause);
  }
}

async function proveAndAssembleMerge(
  input: MergeTransactionParams,
  owner: Address,
  material: MergeMaterial,
  created: ReturnType<typeof createMerge>,
  context: RequestContext | undefined,
): Promise<Transaction> {
  const intent: TransactionIntent = {
    kind: "merge",
    asset: input.asset ?? SOL_MINT,
    numInputs: created.numInputs,
    mergedAmount: created.mergedAmount,
  };
  const approval = await input.authority.requestUserApproval({
    solanaPublicKey: owner,
    intent,
    summary: `merge ${String(created.numInputs)} private inputs`,
  });
  checkIntentApproval(approval, intent, (field) => {
    return new WalletError("WALLET_INTENT_MISMATCH", { details: { field } });
  });
  const record = await internalMergeRecord({ rpc: input.client, owner }, context);
  validateMergeBuild(record, owner, material);
  if (input.client.tree !== created.tree) {
    throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
      details: { proofTree: input.client.tree, submitTree: created.tree },
    });
  }
  const proved = await input.client.proveMerge(
    {
      prepared: created.prepared,
      material,
      indexer: treeCheckedIndexer(input.client, created.tree),
    },
    context,
  );
  return input.client.assembleAuthorizedMergeTransaction(
    {
      proved,
      feePayer: input.feePayer,
      userRecord: record.recordAddress,
    },
    context,
  );
}

function validateMergeBuild(record: MergeRecord, owner: Address, material: MergeMaterial): void {
  if (!record.mergingEnabled) {
    throw new WalletError("WALLET_MERGE_DISABLED", { details: { owner } });
  }
  const signingPublicKey = material.signingPublicKey;
  if (signingPublicKey.signatureType() === "p256") {
    if (
      record.ownerP256 === undefined ||
      !equalBytes(record.ownerP256, signingPublicKey.p256().toBytes())
    ) {
      throw new WalletError("WALLET_MERGE_SIGNING_KEY_MISMATCH");
    }
  } else if (
    record.ownerP256 !== undefined ||
    !equalBytes(signingPublicKey.ed25519(), new Uint8Array(addressEncoder.encode(owner)))
  ) {
    throw new WalletError("WALLET_MERGE_SIGNING_KEY_MISMATCH");
  }
  if (!equalBytes(record.nullifierPublicKey, material.nullifierKey.publicKey())) {
    throw new WalletError("WALLET_MERGE_NULLIFIER_KEY_MISMATCH");
  }
  if (!equalBytes(record.viewingPublicKey, material.viewingPublicKey.toBytes())) {
    throw new WalletError("WALLET_MERGE_VIEWING_KEY_MISMATCH", { details: { owner } });
  }
}

function treeCheckedIndexer(
  indexer: Pick<ZolanaClient, "getInputMerkleProofs" | "getNonInclusionProofs">,
  submitTree: Address,
): Pick<ZolanaClient, "getInputMerkleProofs" | "getNonInclusionProofs"> {
  return {
    getInputMerkleProofs: async (commitments, config, context) => {
      const proofs = await indexer.getInputMerkleProofs(commitments, config, context);
      for (const proof of proofs) {
        for (const proofTree of [
          proof.state.merkleContext.tree,
          proof.nullifier.merkleContext.tree,
        ]) {
          if (proofTree !== submitTree) {
            throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
              details: { proofTree, submitTree },
            });
          }
        }
      }
      return proofs;
    },
    getNonInclusionProofs: async (tree, leaves, config, context) => {
      const response = await indexer.getNonInclusionProofs(tree, leaves, config, context);
      for (const proof of response.proofs) {
        if (proof.merkleContext.tree !== submitTree) {
          throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
            details: { proofTree: proof.merkleContext.tree, submitTree },
          });
        }
      }
      return response;
    },
  };
}
