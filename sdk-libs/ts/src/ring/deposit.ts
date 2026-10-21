import type { Instruction } from "@solana/kit";

import type { IndexerReader, Prover, RingRecordReader } from "../client/ports.js";
import type { DepositProofRequest } from "../client/prover/ring.js";
import { DEFAULT_INDEXER_RPC_CONFIG } from "../client/retry.js";
import { compileUnsignedTransaction } from "../flows/compile.js";
import { resolveDepositSettlement } from "../flows/settlement.js";
import { initializePoseidon } from "../hasher/index.js";
import { PAGE_LIMIT } from "../interface/indexer-limits.js";
import type { SignerAccount } from "../interface/instructions/index.js";
import { signerAddress } from "../interface/instructions/index.js";
import type {
  Address,
  Bytes32,
  RequestContext,
  RingAssetDeposit,
  Transaction,
} from "../interface/types.js";
import { randomBlinding, randomSalt } from "../keypair/bytes.js";
import { depositBlinding } from "../keypair/ring-domain.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import { SOL_MINT } from "../transaction/asset.js";
import { Data } from "../transaction/data.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import { ZERO_32 } from "../transaction/internal.js";
import { encodeRingDepositPlaintext } from "../transaction/serialization/ring-deposit.js";
import { Utxo, ownerUtxoHash } from "../transaction/utxo.js";
import { DEPOSIT_TAG_WINDOW } from "../transaction/wallet/anonymous-state.js";
import type { RingKeys } from "../transaction/wallet/keys.js";
import { collectProoflessDeposits } from "../wallet/collect.js";
import type { DepositClient } from "../wallet/deposit.js";
import { bytesKey } from "../wallet/internal.js";
import { resolveShieldedRecipient } from "../wallet/registry.js";

import { checkSignersHideOwner } from "./anonymous.js";
import type { RingProgramConfig } from "./codecs.js";
import { fetchRingProgramConfig } from "./config.js";
import { DEPOSIT_DEMAND, checkRingCoSigner } from "./cosign.js";
import { RING_DEPOSIT_AUDIT_SLOTS, type RingDepositCapsule } from "./deposit-capsule.js";
import {
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "./deposit-audit.js";
import { ringDepositInstruction, ringDepositSpp } from "./deposit-instruction.js";
import { RingError, wrapRingError } from "./error.js";
import type { BoundRoot } from "./policy-proof.js";
import { readRegisteredRecord } from "./registered-record.js";

/** Rust `compute_unit_limit(AuditedDeposit)`. */
export const RING_DEPOSIT_COMPUTE_UNIT_LIMIT = 1_400_000;

/** Who a deposit pays, Rust `DepositRecipient`. */
export type RingDepositRecipient =
  /** A confidential ring member, found under its viewing key's tag. */
  | Readonly<{ kind: "confidential"; address: Address | ShieldedAddress }>
  /** The depositor's own hidden identity on an anonymous ring, found on its deposit stream. */
  | Readonly<{ kind: "anonymous"; keys: RingKeys }>;

export type RingDepositClient = DepositClient &
  Pick<RingRecordReader, "getRingMemberRecord"> &
  Pick<IndexerReader, "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags"> &
  Pick<Prover, "proveRing">;

export interface RingDepositParams {
  readonly client: RingDepositClient;
  readonly ringProgramId: Address;
  readonly feePayer: Address;
  /** Funds the deposit, the fee payer when absent. */
  readonly depositor?: SignerAccount;
  readonly tree?: Address;
  readonly recipient: RingDepositRecipient;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
  /** Signs when the config's scope covers deposits. */
  readonly cosigner?: SignerAccount;
}

/** A proven deposit with the registry root its proof binds. */
export interface ProvenRingDeposit {
  readonly instruction: Instruction;
  /** The registry root an escrowing ring's proof binds by history slot. */
  readonly roots?: readonly BoundRoot[];
}

/** A deposit whose note and auditor ciphertext every proof reuses, Rust `PreparedRingDeposit`. */
export class PreparedRingDeposit {
  /** The note the deposit creates. */
  readonly utxo: Utxo;
  readonly #ringProgramId: Address;
  readonly #tree: Address;
  readonly #depositor: SignerAccount;
  readonly #cosigner: SignerAccount | undefined;
  readonly #deposit: RingAssetDeposit;
  readonly #capsule: RingDepositCapsule;
  readonly #contextHash: Bytes32;
  readonly #ownerPkHash: Bytes32;
  readonly #nullifierPk: Bytes32;
  /** The Ed25519 owner key an anonymous ring discloses, the proof binds it to the owner hash. */
  readonly #ownerKey: Bytes32 | undefined;
  readonly #auditor: X25519PublicKey;
  readonly #keyEscrow: boolean;
  readonly #blindingSecret: Bytes32;
  readonly #ephemeralSecret: Bytes32;

  private constructor(state: {
    utxo: Utxo;
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    cosigner: SignerAccount | undefined;
    deposit: RingAssetDeposit;
    capsule: RingDepositCapsule;
    contextHash: Bytes32;
    ownerPkHash: Bytes32;
    nullifierPk: Bytes32;
    ownerKey: Bytes32 | undefined;
    auditor: X25519PublicKey;
    keyEscrow: boolean;
    blindingSecret: Bytes32;
    ephemeralSecret: Bytes32;
  }) {
    this.utxo = state.utxo;
    this.#ringProgramId = state.ringProgramId;
    this.#tree = state.tree;
    this.#depositor = state.depositor;
    this.#cosigner = state.cosigner;
    this.#deposit = state.deposit;
    this.#capsule = state.capsule;
    this.#contextHash = state.contextHash;
    this.#ownerPkHash = state.ownerPkHash;
    this.#nullifierPk = state.nullifierPk;
    this.#ownerKey = state.ownerKey;
    this.#auditor = state.auditor;
    this.#keyEscrow = state.keyEscrow;
    this.#blindingSecret = state.blindingSecret;
    this.#ephemeralSecret = state.ephemeralSecret;
  }

  /** Fixes the note against the ring's mode, co-signer and auditor. */
  static async prepare(
    params: RingDepositParams,
    context?: RequestContext,
  ): Promise<PreparedRingDeposit> {
    try {
      await initializePoseidon();
      const config = await fetchRingProgramConfig(params.client, params.ringProgramId, context);
      const anonymous = config.mode === "anonymous";
      const depositor = params.depositor ?? params.feePayer;
      const recipient = await depositRecipient(params, anonymous, context);
      const ownerKey = anonymous ? recipient.address.signingPublicKey.ed25519() : undefined;
      if (ownerKey !== undefined)
        checkSignersHideOwner(
          ownerKey,
          [params.feePayer, depositor, params.cosigner].map((party) =>
            party === undefined ? undefined : signerAddress(party),
          ),
        );
      const cosigner = checkRingCoSigner({
        ringProgramId: params.ringProgramId,
        configured: config.coSigner,
        supplied: params.cosigner,
        demand: DEPOSIT_DEMAND,
        approvalRequired: false,
      });
      const asset = params.asset ?? SOL_MINT;
      const settlement = await resolveDepositSettlement(
        {
          asset,
          depositor: signerAddress(depositor),
          ...(params.splTokenAccount === undefined
            ? {}
            : { splTokenAccount: params.splTokenAccount }),
          ...(params.splTokenProgram === undefined
            ? {}
            : { splTokenProgram: params.splTokenProgram }),
        },
        () => new RingError("RING_BUILD_DEPOSIT", { details: { reason: "missing token account" } }),
      );
      return PreparedRingDeposit.#seal({
        params,
        config,
        depositor,
        cosigner,
        recipient,
        ownerKey,
        asset,
        settlement,
        tree: params.tree ?? params.client.tree,
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** A root below a raised floor is proved again over the same note under a fresh root. */
  async prove(client: RingDepositClient, context?: RequestContext): Promise<ProvenRingDeposit> {
    try {
      const escrow = this.#keyEscrow
        ? await readRegisteredRecord(
            {
              client,
              ringProgramId: this.#ringProgramId,
              member: this.#ownerPkHash,
              escrowed: this.#nullifierPk,
            },
            context,
          )
        : undefined;
      const anonymous = this.#ownerKey !== undefined;
      const commitment = this.#deposit.ownerUtxoHash;
      const first = <T>(value: T, padding: T): readonly T[] =>
        Array.from({ length: RING_DEPOSIT_AUDIT_SLOTS }, (_, index) =>
          index === 0 ? value : padding,
        );
      const request: DepositProofRequest = {
        kind: "deposit",
        publicInputHash: ringDepositPublicInputHash({
          contextHash: this.#contextHash,
          anonymous,
          ownerCommitments: [commitment],
          capsules: [this.#capsule],
          auditorPublicKey: this.#auditor,
          ...(escrow === undefined ? {} : { memberRegistryRoot: escrow.root }),
        }),
        contextHash: this.#contextHash,
        count: 1,
        anonymous,
        ownerPkHashes: first(this.#ownerPkHash, ZERO_32),
        ...(this.#ownerKey === undefined ? {} : { ownerKeys: first(this.#ownerKey, ZERO_32) }),
        nullifierPks: first(this.#nullifierPk, ZERO_32),
        blindingSecrets: first(this.#blindingSecret, ZERO_32),
        ctHashes: first(escrow?.ctHash ?? ZERO_32, ZERO_32),
        members: first(escrow?.record, undefined),
        ephSk: this.#ephemeralSecret,
        auditorPk: this.#auditor.u(),
        keyEscrow: escrow !== undefined,
        memberRegistryRoot: escrow?.root ?? ZERO_32,
      };
      const proof = await client.proveRing(request, context);
      return Object.freeze({
        instruction: await ringDepositInstruction({
          ringProgramId: this.#ringProgramId,
          tree: this.#tree,
          depositor: this.#depositor,
          deposits: [this.#deposit],
          proof,
          ...(escrow === undefined ? {} : { registryRootIndex: escrow.index }),
          ...(this.#cosigner === undefined ? {} : { cosigner: this.#cosigner }),
        }),
        ...(escrow === undefined
          ? {}
          : {
              roots: Object.freeze([
                Object.freeze({
                  ringProgramId: this.#ringProgramId,
                  rootIndex: escrow.index,
                  root: escrow.root,
                }),
              ]),
            }),
      });
    } catch (cause) {
      throw wrapRingError("RING_BUILD_DEPOSIT", cause);
    }
  }

  /** Wipes the blinding secret and the auditor sealing key. */
  destroy(): void {
    this.#blindingSecret.fill(0);
    this.#ephemeralSecret.fill(0);
  }

  /** The note, its recipient ciphertext and the auditor capsule, sealed under fresh secrets. */
  static async #seal(
    input: Readonly<{
      params: RingDepositParams;
      config: RingProgramConfig;
      depositor: SignerAccount;
      cosigner: SignerAccount | undefined;
      recipient: Readonly<{ address: ShieldedAddress; viewTag: Bytes32 }>;
      ownerKey: Bytes32 | undefined;
      asset: Address;
      settlement: RingAssetDeposit["asset"];
      tree: Address;
    }>,
  ): Promise<PreparedRingDeposit> {
    const { params, recipient } = input;
    const blindingSecret = randomBlinding();
    const blinding = depositBlinding(blindingSecret);
    const ownerHash = recipient.address.ownerHash();
    const envelope = ViewingKey.generate();
    const plaintext = encodeRingDepositPlaintext({
      blinding,
      ...(params.memo === undefined ? {} : { memo: params.memo }),
      ringData: new Uint8Array(),
    });
    let ephemeralSecret: Bytes32 | undefined;
    try {
      const salt = randomSalt();
      const sealed = sealRingDepositOpenings(
        [
          {
            ownerHash,
            blinding,
            ...(input.ownerKey === undefined ? {} : { ownerKey: input.ownerKey }),
            recipientCiphertext: envelope.encryptRingDeposit(
              recipient.address.viewingPublicKey,
              plaintext,
              salt,
            ),
          },
        ],
        input.config.auditorPublicKey,
      );
      ephemeralSecret = sealed.ephemeralSecret;
      const [capsule] = sealed.capsules;
      const [payload] = sealed.payloads;
      if (capsule === undefined || payload === undefined) throw new RingError("RING_BUILD_DEPOSIT");
      const deposit: RingAssetDeposit = Object.freeze({
        asset: input.settlement,
        viewTag: recipient.viewTag,
        ownerUtxoHash: ownerUtxoHash(ownerHash, blinding),
        amount: params.amount,
        ringDataHash: ZERO_32,
        encrypted: Object.freeze({
          txViewingPublicKey: envelope.publicKey().toBytes(),
          salt,
          ciphertext: payload,
        }),
      });
      const spp = await ringDepositSpp({
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        depositor: input.depositor,
        deposits: [deposit],
      });
      const prepared = new PreparedRingDeposit({
        utxo: new Utxo({
          owner: recipient.address.signingPublicKey,
          asset: input.asset,
          amount: params.amount,
          blinding,
          data: new Data(),
          ringProgramId: params.ringProgramId,
        }),
        ringProgramId: params.ringProgramId,
        tree: input.tree,
        depositor: input.depositor,
        cosigner: input.cosigner,
        deposit,
        capsule,
        contextHash: ringDepositContextHash(params.ringProgramId, input.tree, spp.data),
        ownerPkHash: recipient.address.signingPublicKey.ownerProofInputHash(),
        nullifierPk: recipient.address.nullifierPublicKey,
        ownerKey: input.ownerKey,
        auditor: input.config.auditorPublicKey,
        keyEscrow: input.config.keyEscrow,
        blindingSecret,
        ephemeralSecret,
      });
      ephemeralSecret = undefined;
      return prepared;
    } catch (cause) {
      blindingSecret.fill(0);
      throw cause;
    } finally {
      envelope.destroy();
      ownerHash.fill(0);
      plaintext.fill(0);
      ephemeralSecret?.fill(0);
    }
  }
}

/** Prepares, proves and compiles one audited deposit, Rust `RingDeposit::send`. */
export async function buildRingDepositTransaction(
  params: RingDepositParams,
  context?: RequestContext,
): Promise<Transaction> {
  const prepared = await PreparedRingDeposit.prepare(params, context);
  try {
    const { instruction } = await prepared.prove(params.client, context);
    return await compileUnsignedTransaction({
      feePayer: params.feePayer,
      lifetime: await params.client.getLatestBlockhash(context),
      computeUnitLimit: RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
      instructions: [instruction],
    });
  } catch (cause) {
    throw wrapRingError("RING_BUILD_DEPOSIT", cause);
  } finally {
    prepared.destroy();
  }
}

/** The recipient's address and the tag its scan reads, refused when the ring mode disagrees. */
async function depositRecipient(
  params: RingDepositParams,
  anonymous: boolean,
  context: RequestContext | undefined,
): Promise<Readonly<{ address: ShieldedAddress; viewTag: Bytes32 }>> {
  const recipient = params.recipient;
  if (recipient.kind === "confidential") {
    if (anonymous)
      throw new RingError("RING_ANONYMOUS_REFUSED", { details: { operation: "deposit" } });
    const address = await resolveShieldedRecipient(
      { rpc: params.client, recipient: recipient.address },
      (unregistered) =>
        new RingError("RING_BUILD_DEPOSIT", {
          details: { reason: "recipient not registered", recipient: unregistered },
        }),
      context,
    );
    return { address, viewTag: address.viewingPublicKey.u() };
  }
  if (!anonymous) throw new RingError("RING_NOT_ANONYMOUS", { details: { operation: "deposit" } });
  const address = recipient.keys.address();
  // An anonymous ring spends only through the hidden Ed25519 proof.
  if (address.signingPublicKey.signatureType() !== "ed25519")
    throw new RingError("RING_ANONYMOUS_RECIPIENT_CURVE");
  return { address, viewTag: await depositTag(params.client, recipient.keys, context) };
}

/** The lowest free counter of the deposit stream, the scanner stops at an empty window. */
async function depositTag(
  client: RingDepositClient,
  keys: RingKeys,
  context: RequestContext | undefined,
): Promise<Bytes32> {
  for (let start = 0n; ; start += DEPOSIT_TAG_WINDOW) {
    const counters = Array.from(
      { length: Number(DEPOSIT_TAG_WINDOW) },
      (_, at) => start + BigInt(at),
    );
    const tags = await keys.senderViewTags(counters, context);
    if (tags.length !== counters.length)
      throw new RingError("RING_BUILD_DEPOSIT", {
        details: { reason: "deposit tag count", expected: counters.length, actual: tags.length },
      });
    const found = new Map<string, IndexedShieldedTransaction>();
    await collectProoflessDeposits(
      {
        indexer: client,
        chunk: tags,
        pageLimit: Number(PAGE_LIMIT),
        nextRpcConfig: () => DEFAULT_INDEXER_RPC_CONFIG,
        out: found,
        from: undefined,
      },
      context,
    );
    const occupied = new Set(
      [...found.values()].flatMap((tx) => tx.outputSlots.map((slot) => bytesKey(slot.viewTag))),
    );
    const free = tags.find((tag) => !occupied.has(bytesKey(tag)));
    if (free !== undefined) return free;
  }
}
