import type { BlockhashProvider, KitRpcAccess } from "../client/ports.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { reserveEntries, reservedUtxoKeys, unreserved } from "../flows/reserve.js";
import { selectUtxos, type SpendSelectionErrors } from "../flows/select.js";
import type { SignerAccount } from "../interface/instructions/index.js";
import type { Address, RequestContext, Transaction } from "../interface/types.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { prepareRingAuthorityTransfer } from "../transaction/instructions/transact.js";
import { ProofInputUtxo } from "../transaction/utxo.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";
import {
  checkIntentApproval,
  checkPreparedTransfer,
  checkTransactData,
  checkTransactionIntent,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
import { intentHash } from "../transaction/wallet/intent.js";
import type { UtxoReservation, Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import { equalBytes } from "../wallet/internal.js";
import { fetchSplAssetRegistrations } from "../wallet/sync.js";
import { RING_COSIGN_TRANSFERS } from "./codecs.js";
import { fetchRingCoSigner, fetchRingDelegate } from "./config.js";
import { RingError, wrapRingError } from "./error.js";
import { ringDelegateTransactInstruction } from "./instructions.js";
import {
  proveCustomRingDelegateTransfer,
  RING_TRANSACT_COMPUTE_UNIT_LIMIT,
  type RingDelegateProofClient,
} from "./transfer.js";
import { RingTransactionSubmission, type RingSubmissionAttempt } from "./submission.js";

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

const signerAddress = (signer: SignerAccount): Address =>
  typeof signer === "string" ? signer : signer.address;
const mismatch = (field: string) => new RingError("RING_INTENT_MISMATCH", { details: { field } });

interface DelegateBuildState {
  entries?: readonly WalletUtxo[];
  reservation?: UtxoReservation;
  intent?: Uint8Array;
  attempt?: RingSubmissionAttempt;
}

export async function createRingDelegateSubmission(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  const state: DelegateBuildState = {};
  const normalized = {
    ...input,
    outputs: Object.freeze(input.outputs.map((output) => Object.freeze({ ...output }))),
  };
  const build = async (context?: RequestContext) => {
    await buildDelegateTransaction(normalized, context, state);
    if (state.attempt === undefined) throw new RingError("RING_BUILD_TRANSFER");
    return state.attempt;
  };
  return new RingTransactionSubmission({
    first: await build(context),
    build,
    release: () => {
      if (state.reservation !== undefined) input.wallet._releaseReservation(state.reservation.id);
    },
    windowChanged: async () => false,
  });
}

export async function buildRingDelegateTransferTransaction(
  input: RingDelegateTransferParams,
  context?: RequestContext,
): Promise<Transaction> {
  return buildDelegateTransaction({ ...input }, context);
}

async function buildDelegateTransaction(
  input: RingDelegateTransferParams,
  context?: RequestContext,
  state?: DelegateBuildState,
): Promise<Transaction> {
  const outputs = Object.freeze(input.outputs.map((output) => Object.freeze({ ...output })));
  const delegate = input.delegate;
  const cosigner = input.cosigner;
  return input.source.withSpendSession(async (session) => {
    let reservation: UtxoReservation | undefined;
    const spends: ProofInputUtxo[] = [];
    try {
      const owner = await input.source.shieldedAddress();
      if (!equalBytes(owner.toBytes(), input.wallet.identity.toBytes())) throw mismatch("source");
      const intent: TransactionIntent = Object.freeze({
        kind: "ringDelegate",
        ringProgramId: input.ringProgramId,
        delegate: signerAddress(delegate),
        ...(cosigner === undefined ? {} : { cosigner: signerAddress(cosigner) }),
        source: owner,
        outputs,
      });
      checkTransactionIntent(intent, mismatch);
      const hash = intentHash(intent);
      if (state?.intent !== undefined && !equalBytes(state.intent, hash))
        throw mismatch("retryIntent");
      if (state !== undefined) state.intent = hash;
      const [stored, coSigner] = await Promise.all([
        fetchRingDelegate(input.client, input.ringProgramId, context),
        fetchRingCoSigner(input.client, input.ringProgramId, context),
      ]);
      if (stored === undefined || stored.delegate !== signerAddress(delegate))
        throw new RingError("RING_DELEGATE_INVALID");
      if (
        coSigner !== undefined &&
        (coSigner.scope & RING_COSIGN_TRANSFERS) !== 0 &&
        (cosigner === undefined || signerAddress(cosigner) !== coSigner.signer)
      )
        throw new RingError("RING_COSIGNER_REQUIRED");
      const assets = input.wallet.registry.clone();
      for (const { assetId, mint } of await fetchSplAssetRegistrations(input.client, context))
        assets.register(assetId, mint);
      const amounts = new Map<Address, bigint>();
      for (const output of outputs) {
        assets.assetId(output.asset);
        amounts.set(output.asset, (amounts.get(output.asset) ?? 0n) + output.amount);
      }
      const reserved = reservedUtxoKeys(input.wallet);
      const selected: WalletUtxo[] = [...(state?.entries ?? [])];
      for (const [asset, amount] of state?.entries === undefined ? amounts : []) {
        selected.push(
          ...selectUtxos({
            wallet: input.wallet,
            asset,
            target: { kind: "cover", amount },
            policy: {
              eligible: (entry) =>
                unreserved(reserved)(entry) &&
                entry.utxo.ringProgramId === input.ringProgramId &&
                entry.dataHash === undefined &&
                (entry.ringDataHash === undefined ||
                  entry.ringDataHash.every((byte) => byte === 0)) &&
                entry.utxo.data.utxoData() === undefined &&
                entry.utxo.data.memo() === undefined &&
                (entry.utxo.data.ringData()?.length ?? 0) === 0 &&
                equalBytes(
                  entry.utxo.owner.ownerProofInputHash(),
                  owner.signingPublicKey.ownerProofInputHash(),
                ),
              ordering: "largestFirst",
              allowWideBalance: true,
              maxInputs: 4 - selected.length,
              tree: { kind: "fixed", tree: input.client.tree },
              errors: selectionErrors,
            },
          }).entries,
        );
      }
      if (selected.length > 4) throw new RingError("RING_TOO_MANY_INPUTS");
      if (
        state?.entries !== undefined &&
        selected.some(
          (entry) =>
            !input.wallet
              .utxos()
              .some(
                (known) =>
                  !known.spent && equalBytes(known.outputContext.hash, entry.outputContext.hash),
              ),
        )
      )
        throw new RingError("RING_SPEND_RECORD_INVALID");
      if (state === undefined) reservation = reserveEntries(input.wallet, selected);
      else {
        const now = BigInt(Date.now());
        reservation =
          state.reservation ??
          input.wallet._reserveUtxos({
            utxoHashes: selected.map((entry) => entry.outputContext.hash),
            nowMs: now,
            ttlMs: 0xffff_ffff_ffff_ffffn - now,
          });
        state.reservation = reservation;
        state.entries = selected;
      }
      for (const entry of selected)
        spends.push(
          new ProofInputUtxo({
            utxo: entry.utxo,
            treeId: input.client.treeId,
            nullifierKey: session.nullifierKey(),
            ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
            ...(entry.ringDataHash === undefined ? {} : { ringDataHash: entry.ringDataHash }),
          }),
        );
      const prepared = prepareRingAuthorityTransfer({
        owner,
        inputs: spends,
        outputs,
        payer: input.feePayer,
        ringProgramId: input.ringProgramId,
        outputTreeId: input.client.treeId,
      });
      const approval = await input.source.requestUserApproval({
        solanaPublicKey: input.source.solanaPublicKey(),
        intent,
        summary: `Delegate ${signerAddress(delegate)} moves ${String(outputs.length)} ring payment(s); change stays with the source.`,
      });
      checkIntentApproval(approval, intent, mismatch);
      checkPreparedTransfer(prepared, intent, mismatch);
      const proven = await proveCustomRingDelegateTransfer(
        {
          client: input.client,
          ringProgramId: input.ringProgramId,
          prepared,
          session,
          assets,
          tree: input.client.tree,
        },
        context,
      );
      checkIntentApproval(approval, intent, mismatch);
      checkPreparedTransfer(prepared, intent, mismatch);
      checkTransactData(proven.data, intent, mismatch);
      if (
        signerAddress(delegate) !== intent.delegate ||
        (cosigner === undefined ? undefined : signerAddress(cosigner)) !== intent.cosigner
      )
        throw mismatch("signers");
      const instruction = await ringDelegateTransactInstruction({
        ringProgramId: input.ringProgramId,
        payer: input.feePayer,
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
      const transaction = compileUnsignedTransaction({
        feePayer: input.feePayer,
        lifetime: await input.client.getLatestBlockhash(context),
        instructions: [instruction],
        computeUnitLimit: RING_TRANSACT_COMPUTE_UNIT_LIMIT,
        ...(input.priorityFeeLamports === undefined
          ? {}
          : { priorityFeeLamports: input.priorityFeeLamports }),
      });
      if (state !== undefined)
        state.attempt = { transaction, intentHash: hash, ringInstructionIndex: 0 };
      return transaction;
    } catch (cause) {
      if (reservation !== undefined) input.wallet._releaseReservation(reservation.id);
      throw wrapRingError("RING_BUILD_TRANSFER", cause);
    } finally {
      for (const spend of spends) spend.destroy();
    }
  });
}

const selectionErrors: SpendSelectionErrors = {
  insufficient: ({ asset, requested, available }) =>
    new RingError("RING_INSUFFICIENT_BALANCE", { details: { asset, requested, available } }),
  tooManyInputs: ({ eligible, max }) =>
    new RingError("RING_TOO_MANY_INPUTS", { details: { eligible, max } }),
  overflow: ({ available }) =>
    new RingError("RING_SELECTED_BALANCE_OVERFLOW", { details: { available } }),
};
