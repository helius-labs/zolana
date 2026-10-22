/** Delegate moves from a wallet, the configured delegate signs and the member does not. */
import { NullifierKeyProofAuthority } from "../client/keys.js";
import type {
  BlockhashProvider,
  KitRpcAccess,
  ProofAuthority,
  ProofService,
  WalletKeys,
} from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos } from "../flows/select.js";
import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import { RING_AUTHORITY_SHAPES } from "../interface/shape.js";
import type { Address, RequestContext, Transaction } from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { ZERO_32 } from "../transaction/internal.js";
import {
  approveUnattended,
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactionIntent,
  intentHash,
  ownerSolanaAccount,
  type ApprovalHandler,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { Wallet, type UtxoReservation, type WalletUtxo } from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchSplAssetRegistrations } from "../wallet/sync.js";

import { RingInstructionTag, ringComputeUnitLimit } from "./admin.js";
import { wrapRingError } from "./error.js";
import { boundState } from "./pipeline.js";
import {
  DelegateTransfer,
  type DelegateTransferClient,
  type RingTransferApproval,
} from "./rails.js";
import {
  provenWithinTransaction,
  ringIntentMismatch,
  ringProofInput,
  ringSelectionErrors,
} from "./selection.js";
import {
  RingTransactionSubmission,
  checkRetainedEntries,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import { checkDemandedCoSigner } from "./transfer.js";

export type RingDelegateTransferClient = DelegateTransferClient & BlockhashProvider & KitRpcAccess;

/** Builds a move authorized by the configured Solana delegate. */
export interface RingDelegateTransferParams {
  readonly client: RingDelegateTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** The source is not a required Solana signer. */
  readonly source: WalletKeys;
  readonly approve?: ApprovalHandler;
  readonly delegate: SignerAccount;
  readonly cosigner?: SignerAccount;
  readonly feePayer: Address;
  readonly outputs: readonly Readonly<{
    recipient: ShieldedAddress;
    asset: Address;
    amount: bigint;
  }>[];
  readonly priorityFeeLamports?: bigint;
}

/** The opened member key proves through the client's proof service. */
export type RingDelegateRecoveredClient = RingDelegateTransferClient &
  Readonly<{ proofService: ProofService }>;

/** Recovered openings still require the configured delegate's signature. */
export type RingDelegateRecoveredParams = Omit<
  RingDelegateTransferParams,
  "wallet" | "source" | "approve" | "client"
> &
  Readonly<{
    client: RingDelegateRecoveredClient;
    source: ShieldedAddress;
    nullifierKey: NullifierKey;
    notes: readonly WalletUtxo[];
  }>;

type DelegateMove = Omit<RingDelegateTransferParams, "wallet" | "source" | "approve">;

type DelegateSource =
  | Readonly<{ kind: "keys"; keys: WalletKeys; approve: ApprovalHandler }>
  | Readonly<{
      kind: "recovered";
      address: ShieldedAddress;
      nullifierKey: NullifierKey;
      proofs: ProofService;
    }>;

export function createRingDelegateSubmission(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const source = keysSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildDelegateTransaction(
          { move: input, wallet: input.wallet, source, retry },
          buildContext,
        ),
    },
    context,
  );
}

export async function buildRingDelegateTransferTransaction(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (
    await buildDelegateTransaction(
      { move: input, wallet: input.wallet, source: keysSource(input), retry: {} },
      context,
    )
  ).transaction;
}

export function createRingDelegateRecoveredSubmission(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const wallet = recoveredWallet(input);
  const source = recoveredSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet,
      registry: input.client,
      build: (retry, buildContext) =>
        buildDelegateTransaction({ move: input, wallet, source, retry }, buildContext),
    },
    context,
  );
}

export async function buildRingDelegateRecoveredTransaction(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<Transaction> {
  return (
    await buildDelegateTransaction(
      { move: input, wallet: recoveredWallet(input), source: recoveredSource(input), retry: {} },
      context,
    )
  ).transaction;
}

function keysSource(input: RingDelegateTransferParams): DelegateSource {
  return { kind: "keys", keys: input.source, approve: input.approve ?? approveUnattended };
}

function recoveredWallet(input: RingDelegateRecoveredParams): Wallet {
  const wallet = new Wallet({ identity: input.source });
  wallet._replace({ utxos: input.notes, transactions: [], nullifiers: new Set() });
  return wallet;
}

function recoveredSource(input: RingDelegateRecoveredParams): DelegateSource {
  return {
    kind: "recovered",
    address: input.source,
    nullifierKey: input.nullifierKey,
    proofs: input.client.proofService,
  };
}

/** The source's address and the authority completing its inputs, released when the attempt settles. */
function delegateProofs(
  source: DelegateSource,
): Readonly<{ address: ShieldedAddress; proofs: ProofAuthority; release(): void }> {
  if (source.kind === "keys")
    return { address: source.keys.address(), proofs: source.keys, release: () => {} };
  const proofs = new NullifierKeyProofAuthority(source.nullifierKey, source.proofs);
  return { address: source.address, proofs, release: () => proofs.destroy() };
}

async function buildDelegateTransaction(
  input: Readonly<{
    move: DelegateMove;
    wallet: Wallet;
    source: DelegateSource;
    retry: RingSubmissionBuildState;
  }>,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { move, wallet, source, retry } = input;
  const outputs = Object.freeze(move.outputs.map((output) => Object.freeze({ ...output })));
  const spender = delegateProofs(source);
  let reservation: UtxoReservation | undefined;
  try {
    const owner = spender.address;
    if (!equalBytes(owner.toBytes(), wallet.identity.toBytes())) throw ringIntentMismatch("source");
    const intent: TransactionIntent = Object.freeze({
      kind: "ringDelegate",
      ringProgramId: move.ringProgramId,
      delegate: signerAddress(move.delegate),
      ...(move.cosigner === undefined ? {} : { cosigner: signerAddress(move.cosigner) }),
      source: owner,
      outputs,
    });
    checkTransactionIntent(intent, ringIntentMismatch);
    const planned = intentHash(intent);
    if (retry.intent !== undefined && !equalBytes(retry.intent, planned))
      throw ringIntentMismatch("retryIntent");
    retry.intent = planned;
    const assets = wallet.registry.clone();
    for (const { assetId, mint } of await fetchSplAssetRegistrations(move.client, context))
      assets.register(assetId, mint);
    const amounts = new Map<Address, bigint>();
    for (const output of outputs) {
      assets.assetId(output.asset);
      amounts.set(output.asset, (amounts.get(output.asset) ?? 0n) + output.amount);
    }
    if (retry.entries !== undefined) checkRetainedEntries(wallet, retry.entries);
    const selected = retry.entries ?? selectSourceNotes(move, wallet, owner, amounts);
    reservation = retry.reservation ?? reserveEntries(wallet, selected, retry.lifetime);
    retry.entries = selected;
    retry.reservation = reservation;
    const transfer = DelegateTransfer.new({
      ringProgramId: move.ringProgramId,
      delegate: intent.delegate,
      payer: move.feePayer,
      source: owner,
      sourceProofs: spender.proofs,
      inputs: selected.map((entry) => ringProofInput(entry, owner, move.client)),
      outputs,
      assets,
      outputTreeId: move.client.treeId,
    });
    const approval: RingTransferApproval = {
      transaction:
        move.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: move.priorityFeeLamports },
      approve: async ({ prepared, coSigner }) => {
        checkDemandedCoSigner(move.ringProgramId, move.cosigner, coSigner);
        if (source.kind === "keys") {
          const approved = await source.approve({
            solanaPublicKey: ownerSolanaAccount(owner, move.feePayer),
            intent,
            summary: `Delegate ${intent.delegate} moves ${String(outputs.length)} ring payment(s), change stays with the source.`,
          });
          checkIntentApproval(approved, intent, ringIntentMismatch);
        }
        checkPreparedTransfer(prepared, intent, ringIntentMismatch);
      },
    };
    const proven = await provenWithinTransaction(selected.length, () =>
      transfer.proveApproved(move.client, approval, context),
    );
    const [instruction, lifetime] = await Promise.all([
      proven.instruction(),
      move.client.getLatestBlockhash(context),
    ]);
    const transaction = compileUnsignedTransaction({
      ...approval.transaction,
      feePayer: move.feePayer,
      lifetime,
      instructions: [instruction],
      computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.delegateTransact),
    });
    return Object.freeze({
      transaction,
      lastValidBlockHeight: lifetime.lastValidBlockHeight,
      intentHash: planned,
      ringInstructionIndex: 0,
      ...boundState(proven),
    });
  } catch (cause) {
    if (reservation !== undefined) wallet._releaseReservation(reservation.id);
    throw wrapRingError("RING_BUILD_TRANSFER", cause);
  } finally {
    spender.release();
  }
}

/** Plain ring notes of the source, one cover per mint inside the widest authority shape holding the outputs. */
function selectSourceNotes(
  move: DelegateMove,
  wallet: Wallet,
  owner: ShieldedAddress,
  amounts: ReadonlyMap<Address, bigint>,
): readonly WalletUtxo[] {
  // Every mint may return change.
  const outputs = move.outputs.length + amounts.size;
  const maxInputs = Math.max(
    0,
    ...RING_AUTHORITY_SHAPES.filter((shape) => shape.outputs >= outputs).map(
      (shape) => shape.inputs,
    ),
  );
  const reserved = reservedUtxoKeys(wallet);
  const selected: WalletUtxo[] = [];
  for (const [asset, amount] of amounts) {
    selected.push(
      ...selectUtxos({
        wallet,
        asset,
        target: { kind: "cover", amount },
        policy: {
          eligible: (entry) =>
            unreserved(reserved)(entry) &&
            entry.utxo.ringProgramId === move.ringProgramId &&
            entry.dataHash === undefined &&
            (entry.ringDataHash === undefined || equalBytes(entry.ringDataHash, ZERO_32)) &&
            entry.utxo.data.utxoData() === undefined &&
            entry.utxo.data.memo() === undefined &&
            (entry.utxo.data.ringData()?.length ?? 0) === 0 &&
            equalBytes(
              entry.utxo.owner.ownerProofInputHash(),
              owner.signingPublicKey.ownerProofInputHash(),
            ),
          ordering: "largestFirst",
          allowWideBalance: true,
          maxInputs: maxInputs - selected.length,
          tree: { kind: "fixed", tree: move.client.tree },
          errors: ringSelectionErrors,
        },
      }).entries,
    );
  }
  return selected;
}
