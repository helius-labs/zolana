import type { BlockhashProvider, KitRpcAccess } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos } from "../flows/select.js";
import { signerAddress, type SignerAccount } from "../interface/instructions/index.js";
import { RING_AUTHORITY_MAX_WIDTH } from "../interface/shape.js";
import type { Address, RequestContext, Transaction } from "../interface/types.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { prepareRingAuthorityTransfer } from "../transaction/instructions/transact.js";
import { ZERO_32 } from "../transaction/internal.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { SpendSession, WalletAuthority } from "../transaction/wallet/authority.js";
import { runSpendSession } from "../transaction/wallet/encrypt-rails.js";
import {
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  checkTransactionIntent,
  intentHash,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { Wallet, type UtxoReservation, type WalletUtxo } from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchSplAssetRegistrations } from "../wallet/sync.js";
import { fetchRingCoSigner, fetchRingDelegate } from "./config.js";
import { TRANSFER_DEMAND, checkRingCoSigner } from "./cosign.js";
import { RingError, wrapRingError } from "./error.js";
import { ringDelegateTransactInstruction } from "./instructions.js";
import {
  checkRetainedEntries,
  RingTransactionSubmission,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";
import {
  proveCustomRingDelegateTransfer,
  RING_TRANSACT_COMPUTE_UNIT_LIMIT,
  ringIntentMismatch,
  ringSelectionErrors,
  type RingDelegateProofClient,
} from "./transfer.js";

export type RingDelegateTransferClient = RingDelegateProofClient & BlockhashProvider & KitRpcAccess;

export interface RingDelegateTransferParams {
  readonly client: RingDelegateTransferClient;
  readonly ringProgramId: Address;
  readonly wallet: Wallet;
  /** The source is not a required Solana signer. */
  readonly source: WalletAuthority;
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

type DelegateMove = Omit<RingDelegateTransferParams, "wallet" | "source">;

/** The notes `recoverRingMemberNotes` returned stand in for the source's wallet, nobody approves. */
export type RingDelegateRecoveredParams = DelegateMove &
  Readonly<{
    source: ShieldedAddress;
    nullifierKey: NullifierKey;
    notes: readonly WalletUtxo[];
  }>;

type DelegateSource =
  | Readonly<{ kind: "authority"; authority: WalletAuthority }>
  | Readonly<{ kind: "recovered"; address: ShieldedAddress; nullifierKey: NullifierKey }>;

interface DelegateBuild {
  readonly move: DelegateMove;
  readonly wallet: Wallet;
  readonly source: DelegateSource;
  readonly retry: RingSubmissionBuildState;
}

export async function createRingDelegateSubmission(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const source: DelegateSource = { kind: "authority", authority: input.source };
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      build: (retry, context) =>
        buildDelegateTransaction({ move: input, wallet: input.wallet, source, retry }, context),
      windowChanged: async () => false,
    },
    context,
  );
}

export async function buildRingDelegateTransferTransaction(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<Transaction> {
  const source: DelegateSource = { kind: "authority", authority: input.source };
  return (
    await buildDelegateTransaction(
      { move: input, wallet: input.wallet, source, retry: {} },
      context,
    )
  ).transaction;
}

export async function createRingDelegateRecoveredSubmission(
  input: RingDelegateRecoveredParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const wallet = recoveredWallet(input);
  const source = recoveredSource(input);
  return RingTransactionSubmission.fromBuilder(
    {
      wallet,
      build: (retry, context) =>
        buildDelegateTransaction({ move: input, wallet, source, retry }, context),
      windowChanged: async () => false,
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

function recoveredWallet(input: RingDelegateRecoveredParams): Wallet {
  const wallet = new Wallet({ identity: input.source });
  wallet._replace({ utxos: input.notes, transactions: [], nullifiers: new Set() });
  return wallet;
}

function recoveredSource(input: RingDelegateRecoveredParams): DelegateSource {
  return { kind: "recovered", address: input.source, nullifierKey: input.nullifierKey };
}

function withDelegateSession<T>(
  source: DelegateSource,
  run: (session: SpendSession) => Promise<T>,
): Promise<T> {
  if (source.kind === "authority") return source.authority.withSpendSession(run);
  // A fresh viewing key seals the outputs, the source's own key is not held.
  const secret = source.nullifierKey.secretBytes();
  let nullifierKey: NullifierKey;
  try {
    nullifierKey = NullifierKey.fromSecret(secret);
  } finally {
    secret.fill(0);
  }
  return runSpendSession(ViewingKey.generate(), nullifierKey, run);
}

async function buildDelegateTransaction(
  input: DelegateBuild,
  context?: RequestContext,
): Promise<RingSubmissionAttempt> {
  const { move, wallet, source, retry } = input;
  const outputs = Object.freeze(move.outputs.map((output) => Object.freeze({ ...output })));
  const delegate = move.delegate;
  const cosigner = move.cosigner;
  return withDelegateSession(source, async (session) => {
    let reservation: UtxoReservation | undefined;
    const spends: ProofInputUtxo[] = [];
    try {
      const owner =
        source.kind === "authority" ? await source.authority.shieldedAddress() : source.address;
      if (!equalBytes(owner.toBytes(), wallet.identity.toBytes()))
        throw ringIntentMismatch("source");
      const intent: TransactionIntent = Object.freeze({
        kind: "ringDelegate",
        ringProgramId: move.ringProgramId,
        delegate: signerAddress(delegate),
        ...(cosigner === undefined ? {} : { cosigner: signerAddress(cosigner) }),
        source: owner,
        outputs,
      });
      checkTransactionIntent(intent, ringIntentMismatch);
      const hash = intentHash(intent);
      if (retry.intent !== undefined && !equalBytes(retry.intent, hash))
        throw ringIntentMismatch("retryIntent");
      retry.intent = hash;
      const [stored, coSigner] = await Promise.all([
        fetchRingDelegate(move.client, move.ringProgramId, context),
        fetchRingCoSigner(move.client, move.ringProgramId, context),
      ]);
      if (stored === undefined || stored.delegate !== signerAddress(delegate))
        throw new RingError("RING_DELEGATE_INVALID");
      checkRingCoSigner({
        ringProgramId: move.ringProgramId,
        configured: coSigner,
        supplied: cosigner,
        demand: TRANSFER_DEMAND,
        approvalRequired: false,
      });
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
      reservation = retry.reservation ?? reserveEntries(wallet, selected);
      retry.entries = selected;
      retry.reservation = reservation;
      for (const entry of selected)
        spends.push(
          new ProofInputUtxo({
            utxo: entry.utxo,
            treeId: move.client.treeId,
            nullifierKey: session.nullifierKey(),
            ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
            ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
          }),
        );
      const prepared = prepareRingAuthorityTransfer({
        owner,
        inputs: spends,
        outputs,
        payer: move.feePayer,
        ringProgramId: move.ringProgramId,
        outputTreeId: move.client.treeId,
      });
      if (source.kind === "authority") {
        const approval = await source.authority.requestUserApproval({
          solanaPublicKey: source.authority.solanaPublicKey(),
          intent,
          summary: `Delegate ${signerAddress(delegate)} moves ${String(outputs.length)} ring payment(s), change stays with the source.`,
        });
        checkIntentApproval(approval, intent, ringIntentMismatch);
      }
      checkPreparedTransfer(prepared, intent, ringIntentMismatch);
      const proven = await proveCustomRingDelegateTransfer(
        {
          client: move.client,
          ringProgramId: move.ringProgramId,
          prepared,
          session,
          assets,
          tree: move.client.tree,
        },
        context,
      );
      checkTransactData(proven.data, intent, ringIntentMismatch);
      if (
        signerAddress(delegate) !== intent.delegate ||
        (cosigner === undefined ? undefined : signerAddress(cosigner)) !== intent.cosigner
      )
        throw ringIntentMismatch("signers");
      const instruction = await ringDelegateTransactInstruction({
        ringProgramId: move.ringProgramId,
        payer: move.feePayer,
        inputTree: proven.tree,
        outputTree: proven.outputTree,
        hasPolicy: proven.hasPolicy,
        ...(proven.hasPolicy ? { entriesTree: proven.entriesTree } : {}),
        proof: proven.proof,
        stateRootIndex: proven.stateRootIndex,
        nullifierRootIndex: proven.nullifierRootIndex,
        data: proven.data,
        delegate,
        ...(cosigner === undefined ? {} : { cosigner }),
      });
      const lifetime = await move.client.getLatestBlockhash(context);
      const transaction = compileUnsignedTransaction({
        feePayer: move.feePayer,
        lifetime,
        instructions: [instruction],
        computeUnitLimit: RING_TRANSACT_COMPUTE_UNIT_LIMIT,
        ...(move.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: move.priorityFeeLamports }),
      });
      return Object.freeze({
        transaction,
        lastValidBlockHeight: lifetime.lastValidBlockHeight,
        intentHash: hash,
        ringInstructionIndex: 0,
      });
    } catch (cause) {
      if (reservation !== undefined) wallet._releaseReservation(reservation.id);
      throw wrapRingError("RING_BUILD_TRANSFER", cause);
    } finally {
      for (const spend of spends) spend.destroy();
    }
  });
}

/** Plain ring notes of the source, one cover per mint inside the authority width. */
function selectSourceNotes(
  move: DelegateMove,
  wallet: Wallet,
  owner: ShieldedAddress,
  amounts: ReadonlyMap<Address, bigint>,
): readonly WalletUtxo[] {
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
          maxInputs: RING_AUTHORITY_MAX_WIDTH - selected.length,
          tree: { kind: "fixed", tree: move.client.tree },
          errors: ringSelectionErrors,
        },
      }).entries,
    );
  }
  if (selected.length > RING_AUTHORITY_MAX_WIDTH) throw new RingError("RING_TOO_MANY_INPUTS");
  return selected;
}
