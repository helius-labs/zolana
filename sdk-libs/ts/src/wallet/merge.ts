import { getAddressEncoder } from "@solana/kit";

import type {
  ChainReader,
  MergeAssembler,
  ProofReader,
  TreeContext,
  WalletKeys,
} from "../client/ports.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { Merge, PreparedMerge } from "../transaction/instructions/builders.js";
import type { ProofInputUtxo } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/asset.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";

import { initializePoseidon } from "../hasher/index.js";
import { MERGE_INPUT_COUNT } from "../interface/constants.js";
import {
  isPlainUtxo,
  selectUtxos,
  type SpendPolicy,
  type SpendSelectionErrors,
} from "../flows/select.js";
import { reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import {
  approveUnattended,
  checkIntentApproval,
  ownerSolanaAccount,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { WalletError, wrapWalletError } from "./error.js";
import { bytesKey, equalBytes, reserveWalletEntries } from "./internal.js";
import { proofInputFromEntry } from "./private-transaction.js";
import { internalMergeRecord, type MergeRecord } from "./registry.js";

const addressEncoder = getAddressEncoder();

/** @internal */
export interface MergeParams {
  readonly wallet: Wallet;
  readonly keys: ShieldedKeys;
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
  tooFewUtxos: () => new WalletError("WALLET_NOTHING_TO_MERGE"),
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
export async function createMerge(params: MergeParams): Promise<CreatedMerge> {
  const selected = selectMergeEntries(params);
  const tree = selected[0]?.outputContext.tree;
  if (tree === undefined) throw new WalletError("WALLET_NOTHING_TO_MERGE");
  if (selected.some((entry) => entry.outputContext.tree !== tree)) {
    throw new WalletError("WALLET_INPUT_UTXO_TREE_MISMATCH");
  }
  const reservation = reserveWalletEntries(params.wallet, selected);
  try {
    const address = params.keys.address();
    const inputs: readonly ProofInputUtxo[] = selected.map((entry) =>
      proofInputFromEntry(entry, address),
    );
    const firstNullifier = inputs[0]?.nullifier();
    if (firstNullifier === undefined) throw new WalletError("WALLET_NOTHING_TO_MERGE");
    const dummySlots = PreparedMerge.dummySlots(inputs.length);
    const [outputBlinding, ...dummyNullifiers] = await params.keys.derive([
      { kind: "mergeOutputBlinding", firstNullifier },
      ...dummySlots.map((slotIndex) => ({
        kind: "mergeDummyNullifier" as const,
        firstNullifier,
        slotIndex,
      })),
    ]);
    if (outputBlinding === undefined || dummyNullifiers.length !== dummySlots.length) {
      throw new WalletError("WALLET_KEYS_BATCH_MISMATCH");
    }
    const prepared = new Merge({ address, inputs, outputBlinding, dummyNullifiers }).prepare();
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
  return selectUtxos({
    wallet: params.wallet,
    asset: params.asset,
    target: { kind: "consolidate", minInputs: 2 },
    policy: mergePolicy(reservedUtxoKeys(params.wallet)),
  }).entries;
}

export type MergeClient = MergeAssembler &
  TreeContext &
  Pick<ChainReader, "getAccount"> &
  Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">;

export interface MergeTransactionParams {
  readonly client: MergeClient;
  readonly wallet: Wallet;
  readonly keys: WalletKeys;
  readonly feePayer: Address;
  readonly asset?: Address;
  readonly inputs?: readonly Bytes32[];
  readonly approve?: ApprovalHandler;
}

export async function buildMergeTransaction(
  input: MergeTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    await initializePoseidon();
    const address = input.keys.address();
    const owner = ownerSolanaAccount(address, input.feePayer);
    const created = await createMerge({
      wallet: input.wallet,
      keys: input.keys,
      asset: input.asset ?? SOL_MINT,
      ...(input.inputs === undefined ? {} : { inputs: input.inputs }),
    });
    try {
      return await proveAndAssembleMerge(input, owner, address, created, context);
    } catch (cause) {
      input.wallet._releaseReservation(created.reservationId);
      throw cause;
    }
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_MERGE", cause);
  }
}

async function proveAndAssembleMerge(
  input: MergeTransactionParams,
  owner: Address,
  address: ShieldedAddress,
  created: CreatedMerge,
  context: RequestContext | undefined,
): Promise<Transaction> {
  const intent: TransactionIntent = {
    kind: "merge",
    asset: input.asset ?? SOL_MINT,
    numInputs: created.numInputs,
    mergedAmount: created.mergedAmount,
  };
  const approval = await (input.approve ?? approveUnattended)({
    solanaPublicKey: owner,
    intent,
    summary: `merge ${String(created.numInputs)} private inputs`,
  });
  checkIntentApproval(approval, intent, (field) => {
    return new WalletError("WALLET_INTENT_MISMATCH", { details: { field } });
  });
  const record = await internalMergeRecord({ rpc: input.client, owner }, context);
  validateMergeBuild(record, owner, address);
  if (input.client.tree !== created.tree) {
    throw new WalletError("WALLET_MERGE_TREE_MISMATCH", {
      details: { proofTree: input.client.tree, submitTree: created.tree },
    });
  }
  const proved = await input.client.proveMerge(
    {
      prepared: created.prepared,
      keys: input.keys,
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

function validateMergeBuild(record: MergeRecord, owner: Address, address: ShieldedAddress): void {
  if (!record.mergingEnabled) {
    throw new WalletError("WALLET_MERGE_DISABLED", { details: { owner } });
  }
  const signingPublicKey = address.signingPublicKey;
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
  if (!equalBytes(record.nullifierPublicKey, address.nullifierPublicKey)) {
    throw new WalletError("WALLET_MERGE_NULLIFIER_KEY_MISMATCH");
  }
  if (!equalBytes(record.viewingPublicKey, address.viewingPublicKey.toBytes())) {
    throw new WalletError("WALLET_MERGE_VIEWING_KEY_MISMATCH", { details: { owner } });
  }
}

function treeCheckedIndexer(
  indexer: Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">,
  submitTree: Address,
): Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs"> {
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
