import { getAddressEncoder, type Address, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import packed from "../../../test-vectors/audit-disclosure.json" with { type: "json" };
import anonymous from "../../../test-vectors/audit-disclosure-anonymous.json" with { type: "json" };
import delivered from "../../../test-vectors/audit-disclosure-delivered.json" with { type: "json" };
import { fieldAdd, initializePoseidon } from "../src/hasher/index.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../src/interface/custom-ring-proof.js";
import { encodeBase58 } from "../src/interface/internal.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import { StateDiscriminator } from "../src/interface/state.js";
import type { DisclosureLayout } from "../src/interface/ring-disclosure-layout.js";
import type { Bytes16, Bytes31, Bytes32, Bytes33 } from "../src/interface/types.js";
import {
  auditSharedSecret,
  auditorMessageData,
  openTransactionViewingSecret,
  sealTransactionViewingSecret,
} from "../src/keypair/audit.js";
import { mergeOutputBlinding, mergeOutputKey } from "../src/keypair/merge/index.js";
import { openRingDisclosure, sealRingDisclosure } from "../src/keypair/ring-disclosure.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import {
  auditRing,
  auditRingTransaction,
  type AuditedUtxo,
  type EscrowedKeys,
  type KnownUtxo,
  type KnownUtxos,
  type OutputOpening,
} from "../src/ring/audit.js";
import { sealRingDepositOpenings } from "../src/ring/deposit-audit.js";
import { sealRingMergeDisclosure } from "../src/ring/merge-disclosure.js";
import {
  ConfirmedDeposit,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "../src/ring/origin.js";
import { recoverRingMemberNotes } from "../src/ring/recover.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import { bigIntBytes, bytesToBigInt, equal, poseidon } from "../src/transaction/internal.js";
import type {
  IndexedShieldedTransaction,
  OutputSlot,
} from "../src/transaction/instructions/transact.js";
import {
  CONFIDENTIAL_DATA_FREE_BODY_LEN,
  EncryptedScheme,
  RING_PACKED_DATA_FREE_BODY_LEN,
  encodeOutputData,
} from "../src/transaction/serialization/codecs.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
import { Utxo, ownerUtxoHash } from "../src/transaction/utxo.js";
import { ringAuditReader, transactionsPage } from "./helpers/clients.js";
import { confirmedDepositTransaction, ringDepositPayload } from "./helpers/confirmed-deposits.js";

await initializePoseidon();

function hex<T extends Uint8Array>(value: string, length?: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (length !== undefined && decoded.length !== length)
    throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function field(value: string): Bytes32 {
  return hex<Bytes32>(value, 32);
}

type Layout = "packed" | "delivered" | "anonymous";
type Vector =
  | (typeof packed.cases)[number]
  | (typeof delivered.cases)[number]
  | (typeof anonymous.cases)[number];
type VectorSlot = Vector["slots"][number];
type VectorEntry = Readonly<{ layout: Layout; bound: DisclosureLayout; vector: Vector }>;

/** `exits | key_escrow << 1 | data_free << 2 | full_openings << 3`, the frame's layout element. */
function bound(layout: Layout, vector: Vector): DisclosureLayout {
  const value = vector.layout;
  const exits = (value & 1) !== 0;
  const keyEscrow = (value & 2) !== 0;
  const outputs = vector.slots.length;
  if (layout === "packed")
    return { kind: layout, outputs, exits, keyEscrow, dataFree: (value & 4) !== 0 };
  if (layout === "delivered") return { kind: layout, outputs, exits, keyEscrow };
  if (!("inputs" in vector)) throw new Error("anonymous vector without inputs");
  return {
    kind: layout,
    key: vector.key === "entry" ? { kind: "entry" } : { kind: "commitment", class: vector.class },
    inputs: vector.inputs.length,
    outputs,
    exits,
  };
}

const VECTORS: readonly VectorEntry[] = [
  ...packed.cases.map((vector) => ({ layout: "packed" as const, vector })),
  ...delivered.cases.map((vector) => ({ layout: "delivered" as const, vector })),
  ...anonymous.cases.map((vector) => ({ layout: "anonymous" as const, vector })),
].map((entry) => ({ ...entry, bound: bound(entry.layout, entry.vector) }));

const SIGNATURE = "1".repeat(64) as Signature;
/** A mint no default registry names, the exit of the packed vector settles it. */
const FOREIGN_MINT = encodeBase58(new Uint8Array(32).fill(0x0a));

function vectorOf(layout: Layout, name: string): VectorEntry {
  const found = VECTORS.find((entry) => entry.layout === layout && entry.vector.name === name);
  if (found === undefined) throw new Error(`no ${layout} ${name} vector`);
  return found;
}

/** The packed case with an exit and no escrow, every key and data hash published. */
const PACKED = vectorOf("packed", "exits");
const PACKED_LAYOUT = PACKED.bound;
const PACKED_VECTOR = PACKED.vector;

/** The slot's payload under the scheme its rail expands to, exits under scheme 3. */
function payload(layout: Layout, slot: VectorSlot): Uint8Array {
  if (slot.kind === "exit")
    return encodeOutputData(
      EncryptedScheme.confidential,
      new Uint8Array(CONFIDENTIAL_DATA_FREE_BODY_LEN),
    );
  if (layout === "packed")
    return encodeOutputData(
      EncryptedScheme.ringConfidentialPacked,
      new Uint8Array(RING_PACKED_DATA_FREE_BODY_LEN),
    );
  const body = "body" in slot ? slot.body : undefined;
  if (body === undefined) throw new Error("vector slot without a body");
  return encodeOutputData(
    layout === "delivered"
      ? EncryptedScheme.ringConfidentialDelivered
      : EncryptedScheme.ringAnonymous,
    hex(body, 40),
  );
}

/** The nullifier key each owner's escrow record holds, read from the vector's openings. */
function escrowRecords(vector: Vector): EscrowedKeys {
  const keys = new Map(
    vector.slots.flatMap((slot) =>
      slot.kind === "dummy"
        ? []
        : [[need(slot.owner_key, "owner_key"), field(need(slot.nullifier_pk, "nullifier_pk"))]],
    ),
  );
  return { nullifierPk: (ownerKey) => keys.get(Buffer.from(ownerKey).toString("hex")) };
}

/** The sender's earlier UTXOs an anonymous vector spends, by their hash. */
function spentUtxos(vector: Vector, assets: AssetRegistry): KnownUtxos {
  const inputs = "inputs" in vector ? vector.inputs : [];
  const sender = "sender_key" in vector ? vector.sender_key : undefined;
  const utxos = new Map(
    inputs.map((input) => {
      const asset = field(input.asset);
      const mint = assets.addressForField(asset);
      const utxo: KnownUtxo = {
        ownerKey: field(need(sender, "sender_key")),
        owner: {
          kind: "keyed",
          nullifierPk: field(
            need(
              "sender_nullifier_pk" in vector ? vector.sender_nullifier_pk : undefined,
              "sender_nullifier_pk",
            ),
          ),
        },
        asset,
        ...(mint === undefined ? {} : { mint }),
        amount: BigInt(input.amount),
        blinding: field(input.blinding),
        dataHash: new Uint8Array(32) as Bytes32,
        ringDataHash: new Uint8Array(32) as Bytes32,
        treeId: input.input_tree_id,
      };
      return [input.commitment, utxo] as const;
    }),
  );
  return { utxo: (commitment) => utxos.get(Buffer.from(commitment).toString("hex")) };
}

/** The confirmed transfer the vector describes, its tx secret sealed to `auditor`. */
function vectorTransaction(
  entry: Readonly<{ layout: Layout; vector: Vector }>,
  auditor: X25519PublicKey,
): IndexedShieldedTransaction {
  const { layout, vector } = entry;
  const envelope = sealTransactionViewingSecret(field(vector.tx_viewing_sk), auditor);
  const message = auditorMessageData(
    {
      ephemeralPublicKey: envelope.ephemeralPublicKey,
      sealed: envelope.sealed,
      disclosure: vector.published.map(field),
    },
    auditor,
  );
  const outputSlots: OutputSlot[] = vector.slots.map((slot, index) => ({
    viewTag: field(slot.owner_tag),
    outputContext: {
      hash: field(slot.output_hash),
      tree: treeAddress(vector.output_tree_id),
      treeId: vector.output_tree_id,
      leafIndex: BigInt(index),
    },
    payload: payload(layout, slot),
  }));
  const nullifiers =
    "inputs" in vector
      ? vector.inputs.map((input) => field(input.nullifier))
      : [field(vector.first_nullifier)];
  return {
    slot: 7n,
    txSignature: SIGNATURE,
    eventIndex: 0,
    txViewingPublicKey: X25519PublicKey.fromU(field(vector.tx_viewing_u)),
    salt: hex<Bytes16>(vector.salt, 16),
    outputSlots,
    messages: [message],
    nullifiers,
    proofless: false,
    ringProgramId: encodeBase58(field(vector.ring_program_id)),
  };
}

/** A vector field every opened slot carries. */
function need<T>(value: T | undefined, name: string): T {
  if (value === undefined) throw new Error(`vector slot without ${name}`);
  return value;
}

/** What the auditor must rebuild for `slot`, Rust `OutputOpening`. */
function expectedOpening(layout: Layout, slot: VectorSlot, assets: AssetRegistry): OutputOpening {
  if (slot.kind === "dummy") return { kind: "dummy" };
  const asset = field(need(slot.asset, "asset"));
  // A delivered or anonymous ring output names its raw mint in the body.
  const mint =
    layout !== "packed" && slot.kind === "ring"
      ? encodeBase58(hex(need(slot.asset_address, "asset_address"), 32))
      : assets.addressForField(asset);
  const utxo: AuditedUtxo = {
    ownerKey: field(need(slot.owner_key, "owner_key")),
    nullifierPk: field(need(slot.nullifier_pk, "nullifier_pk")),
    asset,
    ...(mint === undefined ? {} : { mint }),
    amount: BigInt(need(slot.amount, "amount")),
    blinding: field(slot.blinding),
    dataHash: field(need(slot.data_hash, "data_hash")),
    ringDataHash: field(need(slot.ring_data_hash, "ring_data_hash")),
  };
  if (slot.kind === "exit") return { kind: "exit", utxo };
  const tag = "tag" in slot && typeof slot.tag === "string" ? slot.tag : undefined;
  return {
    kind: "ring",
    utxo,
    recipientU: field(need(slot.recipient_u, "recipient_u")),
    ...(tag === undefined ? {} : { tag: hex<Bytes31>(tag, 31) }),
  };
}

function audit(
  entry: VectorEntry,
  options: Readonly<{
    auditor?: X25519Keypair;
    assets?: AssetRegistry;
    transaction?: (transaction: IndexedShieldedTransaction) => IndexedShieldedTransaction;
    inputTreeIds?: readonly (number | undefined)[];
    layout?: DisclosureLayout;
    escrowedKeys?: EscrowedKeys;
    knownUtxos?: KnownUtxos;
  }> = {},
) {
  const auditor = options.auditor ?? X25519Keypair.generate();
  const transaction = vectorTransaction(entry, auditor.publicKey());
  return auditRingTransaction({
    auditor,
    transaction: options.transaction?.(transaction) ?? transaction,
    assets: options.assets ?? new AssetRegistry(),
    layout: options.layout ?? entry.bound,
    ...(options.inputTreeIds === undefined ? {} : { inputTreeIds: options.inputTreeIds }),
    ...(options.escrowedKeys === undefined ? {} : { escrowedKeys: options.escrowedKeys }),
    ...(options.knownUtxos === undefined ? {} : { knownUtxos: options.knownUtxos }),
  });
}

function withSlot(
  index: number,
  change: (slot: OutputSlot) => OutputSlot,
): (transaction: IndexedShieldedTransaction) => IndexedShieldedTransaction {
  return (transaction) => ({
    ...transaction,
    outputSlots: transaction.outputSlots.map((slot, at) => (at === index ? change(slot) : slot)),
  });
}

function ringError(code: string, details?: Readonly<Record<string, unknown>>): unknown {
  return expect.objectContaining({
    code,
    ...(details === undefined ? {} : { details: expect.objectContaining(details) }),
  });
}

describe("auditor envelope", () => {
  // Pinned by prover/server/prover-test/ringaudit/kdf_test.go and custom-rings/client/src/encryption.rs.
  const auditor = X25519Keypair.fromBytes(
    hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c", 32),
  );
  const ephemeralPublicKey = X25519PublicKey.fromBytes(
    hex<Bytes33>("048ea960e4e1b72cdec9a6e7d86ae28cd04edb4b5c07266d3c32d9133c8ebaa966", 33),
  );

  it("matches the circuit vector", () => {
    expect(auditor.publicKey().toBytes()).toEqual(
      hex("04708c2645c705baaf44f2ab947574174f9280df58be6fc2f6f2e8881b78a3115a", 33),
    );
    const dh = auditor.ecdh(ephemeralPublicKey);
    expect(dh).toEqual(field("464b33b122dc1346a6012199742d7e14b2ee6436589c454a579fdda24feec92c"));
    expect(auditSharedSecret(dh, ephemeralPublicKey, auditor.publicKey())).toEqual(
      field("2590b2b949a2f87b9201e4d065167ea9282c4bd06a32e888e24e33c5bddae54f"),
    );
    const sealed = field("da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90");
    expect(openTransactionViewingSecret(auditor, { ephemeralPublicKey, sealed })).toEqual(
      field("001013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f4e"),
    );
  });
});

describe("auditRingTransaction over the shared disclosure vectors", () => {
  it.each(VECTORS)(
    "opens every slot of the $layout case to the Rust opening, an exit as a default-ring note",
    (entry) => {
      const assets = new AssetRegistry();
      const audited = audit(entry, {
        assets,
        escrowedKeys: escrowRecords(entry.vector),
        knownUtxos: spentUtxos(entry.vector, assets),
      });
      expect(audited.payloadErrors).toEqual([]);
      expect(audited.outputs.map((output) => output.slotIndex)).toEqual(
        entry.vector.slots.map((_, index) => index),
      );
      audited.outputs.forEach((output, index) => {
        const slot = entry.vector.slots[index]!;
        expect(output.outputContext.hash).toEqual(field(slot.output_hash));
        expect(output.opening).toEqual(expectedOpening(entry.layout, slot, assets));
      });
    },
  );

  it.each(VECTORS.filter((entry) => entry.bound.kind !== "anonymous" && entry.bound.keyEscrow))(
    "reports escrowUnknown for every slot of the $layout escrow case without escrow records",
    (entry) => {
      expect(audit(entry).payloadErrors).toEqual(
        entry.vector.slots.flatMap((slot, slotIndex) =>
          slot.kind === "dummy" ? [] : [{ slotIndex, kind: "escrowUnknown" }],
        ),
      );
    },
  );

  it("names a registered mint and leaves an unregistered one to a refresh", () => {
    const exit = (assets: AssetRegistry) =>
      audit(PACKED, { assets }).outputs.find((output) => output.opening.kind === "exit");
    const unknown = exit(new AssetRegistry())?.opening;
    expect(unknown?.kind === "exit" && unknown.utxo.mint).toBeUndefined();
    const known = exit(new AssetRegistry([[2n, FOREIGN_MINT]]))?.opening;
    expect(known?.kind === "exit" && known.utxo.mint).toBe(FOREIGN_MINT);
  });

  it("opens the hidden sender and every spent note of the commitment key by its hash", () => {
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const assets = new AssetRegistry();
    const audited = audit(entry, { assets, knownUtxos: spentUtxos(vector, assets) });
    expect(audited.sender).toEqual({
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    });
    expect(audited.inputs).toEqual(
      vector.inputs.map((input) => ({
        nullifier: field(input.nullifier),
        opening: {
          asset: field(input.asset),
          ...openedMint(assets, input.asset),
          amount: BigInt(input.amount),
          blinding: field(input.blinding),
          ring: { kind: "ring", commitment: field(input.commitment) },
        },
      })),
    );
    expect(() => audit(entry)).toThrow(
      ringError("RING_AUDIT_UNSEEN_INPUT", { commitment: vector.inputs[0]!.commitment }),
    );
  });

  it("names no sender nullifier key when spent note 0 is a deposit", () => {
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const assets = new AssetRegistry();
    const utxos = spentUtxos(vector, assets);
    const deposited = field(vector.inputs[0]!.commitment);
    const audited = audit(entry, {
      assets,
      knownUtxos: {
        utxo: (commitment) => {
          const utxo = utxos.utxo(commitment);
          if (utxo === undefined || !equal(commitment, deposited)) return utxo;
          return {
            ...utxo,
            owner: { kind: "deposited", ownerHash: new Uint8Array(32).fill(9) as Bytes32 },
          };
        },
      },
    });
    expect(audited.sender).toEqual({ ownerKey: field(vector.sender_key) });
    expect(audited.inputs[0]?.opening?.amount).toBe(BigInt(vector.inputs[0]!.amount));
  });

  it("opens every spent note of the entry key and resolves its ring against the known notes", () => {
    const entry = vectorOf("anonymous", "entry");
    const vector = anonymousCase("entry");
    const assets = new AssetRegistry();
    const trees = vector.inputs.map((input) => input.input_tree_id);
    const resolved = audit(entry, {
      assets,
      inputTreeIds: trees,
      knownUtxos: spentUtxos(vector, assets),
    });
    expect(resolved.sender).toEqual({
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    });
    expect(resolved.inputs).toEqual(
      vector.inputs.map((input) => ({
        nullifier: field(input.nullifier),
        opening: {
          asset: field(input.asset),
          ...openedMint(assets, input.asset),
          amount: BigInt(input.amount),
          blinding: field(input.blinding),
          ring: { kind: input.ring, commitment: field(input.commitment) },
        },
      })),
    );
    const unresolved = audit(entry, { inputTreeIds: trees });
    unresolved.inputs.forEach((input, index) => {
      const ring = input.opening?.ring;
      if (ring?.kind !== "unresolved") throw new Error("expected an unresolved input");
      const known = vector.inputs[index]!;
      expect(known.ring === "ring" ? ring.ring : ring.default).toEqual(field(known.commitment));
    });
    expect(audit(entry).inputs.every((input) => input.opening?.ring === undefined)).toBe(true);
  });

  it("records a disclosed field moved off its opening as that slot's commitment error", () => {
    const audited = audit(PACKED, {
      transaction: (transaction) => {
        const message = transaction.messages[0]!;
        const data = message.data.slice();
        // Field 1 is the first slot's masked nullifier key, one more stays a canonical field.
        const at = 65 + 32;
        data.set(bigIntBytes(fieldAdd(bytesToBigInt(data.slice(at, at + 32)), 1n)), at);
        return { ...transaction, messages: [{ viewTag: message.viewTag, data }] };
      },
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 0, kind: "commitment" }]);
    expect(audited.outputs.map((output) => output.slotIndex)).toEqual([1, 2, 3]);
  });

  it("refuses a delivered body under the anonymous scheme as a frame error", () => {
    const entry = vectorOf("delivered", "exits");
    const slot = entry.vector.slots[2]!;
    const body = "body" in slot ? slot.body : undefined;
    const audited = audit(entry, {
      transaction: withSlot(2, (published) => ({
        ...published,
        payload: encodeOutputData(EncryptedScheme.ringAnonymous, hex(need(body, "body"), 40)),
      })),
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 2, kind: "frame" }]);
  });

  it("refuses a recipient key without an X25519 agreement", () => {
    const audited = audit(vectorOf("delivered", "exits"), {
      transaction: withSlot(5, (slot) => ({ ...slot, viewTag: new Uint8Array(32) as Bytes32 })),
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 5, kind: "recipientKey" }]);
  });

  it("refuses an anonymous ring output whose owner tag carries no tag", () => {
    const entry = vectorOf("anonymous", "commitment");
    const assets = new AssetRegistry();
    const audited = audit(entry, {
      assets,
      knownUtxos: spentUtxos(entry.vector, assets),
      transaction: withSlot(0, (slot) => {
        const viewTag = slot.viewTag.slice() as Bytes32;
        viewTag[0] = 1;
        return { ...slot, viewTag };
      }),
    });
    expect(audited.payloadErrors).toEqual([{ slotIndex: 0, kind: "frame" }]);
  });

  it("refuses a message sealed to another auditor, a duplicate and one not last", () => {
    const entry = vectorOf("delivered", "exits");
    const auditor = X25519Keypair.generate();
    const sealed = vectorTransaction(entry, auditor.publicKey());
    const message = sealed.messages[0]!;
    const other = { viewTag: new Uint8Array(32).fill(3) as Bytes32, data: Uint8Array.of(1) };
    const refused = (messages: IndexedShieldedTransaction["messages"]) => () =>
      auditRingTransaction({
        auditor,
        transaction: { ...sealed, messages },
        assets: new AssetRegistry(),
        layout: entry.bound,
      });
    expect(() =>
      auditRingTransaction({
        auditor: X25519Keypair.generate(),
        transaction: sealed,
        assets: new AssetRegistry(),
        layout: entry.bound,
      }),
    ).toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "missing" }));
    expect(refused([message, message])).toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "duplicate" }),
    );
    expect(refused([message, other])).toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "not last" }),
    );
  });

  it("refuses a published key the envelope does not seal", () => {
    expect(() =>
      audit(PACKED, {
        transaction: (transaction) => ({
          ...transaction,
          txViewingPublicKey: X25519Keypair.generate().publicKey(),
        }),
      }),
    ).toThrow(ringError("RING_AUDIT_KEY_MISMATCH"));
  });

  it("refuses an unclamped alias of the sealed transaction secret", () => {
    const auditor = X25519Keypair.generate();
    const transaction = vectorTransaction(PACKED, auditor.publicKey());
    const alias = field(PACKED_VECTOR.tx_viewing_sk);
    alias[0] = (alias[0] ?? 0) | 1;
    const envelope = sealTransactionViewingSecret(alias, auditor.publicKey());
    const message = auditorMessageData(
      {
        ephemeralPublicKey: envelope.ephemeralPublicKey,
        sealed: envelope.sealed,
        disclosure: PACKED_VECTOR.published.map(field),
      },
      auditor.publicKey(),
    );
    expect(() =>
      auditRingTransaction({
        auditor,
        transaction: { ...transaction, messages: [message] },
        assets: new AssetRegistry(),
        layout: PACKED_LAYOUT,
      }),
    ).toThrow(ringError("RING_AUDIT_NONCANONICAL_KEY"));
  });

  it("audits under the layout the frame bound and refuses one off the published counts", () => {
    // The escrow layout leaves out every key, the field count no longer matches the message.
    expect(() =>
      audit(PACKED, {
        layout: { ...PACKED_LAYOUT, kind: "packed", keyEscrow: true, dataFree: false },
      }),
    ).toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "malformed" }));
    expect(() =>
      audit(PACKED, {
        layout: {
          kind: "packed",
          outputs: PACKED_VECTOR.slots.length - 1,
          exits: true,
          keyEscrow: false,
          dataFree: false,
        },
      }),
    ).toThrow(ringError("RING_AUDIT_MESSAGE", { reason: "layout" }));
    // The program sets the exits bit exactly when a published slot exits.
    expect(() => audit(PACKED, { layout: { ...PACKED_LAYOUT, exits: false } })).toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "layout" }),
    );
  });

  it("refuses a transfer without its salt and input trees of another count", () => {
    const auditor = X25519Keypair.generate();
    const transaction = vectorTransaction(PACKED, auditor.publicKey());
    const unsalted: IndexedShieldedTransaction = {
      slot: transaction.slot,
      txSignature: transaction.txSignature,
      outputSlots: transaction.outputSlots,
      messages: transaction.messages,
      nullifiers: transaction.nullifiers,
      proofless: false,
      ...(transaction.txViewingPublicKey === undefined
        ? {}
        : { txViewingPublicKey: transaction.txViewingPublicKey }),
      ...(transaction.ringProgramId === undefined
        ? {}
        : { ringProgramId: transaction.ringProgramId }),
    };
    expect(() =>
      auditRingTransaction({
        auditor,
        transaction: unsalted,
        assets: new AssetRegistry(),
        layout: PACKED_LAYOUT,
      }),
    ).toThrow(ringError("RING_AUDIT_UNSEALED", { reason: "salt" }));
    expect(() => audit(PACKED, { inputTreeIds: [9, 9] })).toThrow(
      ringError("RING_INVALID_LENGTH", { name: "inputTreeIds" }),
    );
  });
});

function anonymousCase(name: string): (typeof anonymous.cases)[number] {
  const found = anonymous.cases.find((vector) => vector.name === name);
  if (found === undefined) throw new Error(`no anonymous ${name} vector`);
  return found;
}

function openedMint(assets: AssetRegistry, asset: string): Readonly<{ mint?: Address }> {
  const mint = assets.addressForField(field(asset));
  return mint === undefined ? {} : { mint };
}

const RING = encodeBase58(field(PACKED_VECTOR.ring_program_id));

const TRANSFERS: TransactionOrigin = {
  confirmedTransaction: async (transaction) => ({
    kind: "transfer",
    transaction,
    inputTreeIds: transaction.nullifiers.map(() => undefined),
    layout: PACKED_LAYOUT,
  }),
};

describe("auditRing", () => {
  const ring = RING;
  const transfers = TRANSFERS;

  function scan(
    transactions: readonly IndexedShieldedTransaction[],
    origin: TransactionOrigin,
    extra: Readonly<{
      solanaRpc?: object;
      assets?: AssetRegistry;
      auditor: X25519Keypair;
      knownUtxos?: KnownUtxos;
    }>,
  ) {
    return auditRing({
      client: ringAuditReader({
        getShieldedTransactionsByTags: async () =>
          transactionsPage({ transactions: [...transactions], scannedThrough: Uint8Array.of(1) }),
        ...(extra.solanaRpc === undefined ? {} : { solanaRpc: extra.solanaRpc }),
      }),
      auditor: extra.auditor,
      ringProgramId: ring,
      assets: extra.assets ?? new AssetRegistry(),
      origin,
      ...(extra.knownUtxos === undefined ? {} : { knownUtxos: extra.knownUtxos }),
    });
  }

  it("opens a spend of a note an earlier call opened through the caller's known notes", async () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const transfer = vectorTransaction(entry, auditor.publicKey());
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction) => ({
        kind: "transfer",
        transaction,
        inputTreeIds: transaction.nullifiers.map(() => undefined),
        layout: entry.bound,
      }),
    };
    const assets = new AssetRegistry();
    await expect(scan([transfer], origin, { auditor, assets })).rejects.toThrow(
      ringError("RING_AUDIT_UNSEEN_INPUT"),
    );
    const page = await scan([transfer], origin, {
      auditor,
      assets,
      knownUtxos: spentUtxos(vector, assets),
      solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) },
    });
    expect(page.transactions[0]?.sender).toEqual({
      ownerKey: field(vector.sender_key),
      nullifierPk: field(vector.sender_nullifier_pk),
    });
  });

  it("audits the ring's confirmed transfers and skips every other event", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PACKED, auditor.publicKey());
    const deposit = { ...transfer, txSignature: "2".repeat(64) as Signature };
    const foreign = { ...transfer, txSignature: "3".repeat(64) as Signature };
    const origin: TransactionOrigin = {
      confirmedTransaction: async (transaction): Promise<ConfirmedRingTransaction | undefined> => {
        if (transaction.txSignature === foreign.txSignature) return undefined;
        if (transaction.txSignature === deposit.txSignature)
          return { kind: "deposit", transaction, deposits: [] };
        return transfers.confirmedTransaction(transaction, ring);
      },
    };
    const assets = new AssetRegistry([[2n, FOREIGN_MINT]]);
    const page = await scan([transfer, deposit, foreign], origin, { auditor, assets });
    expect(page.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(page.nextCursor).toBeUndefined();
  });

  it("refuses a confirmed transfer without its auditor message", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PACKED, auditor.publicKey());
    await expect(scan([{ ...transfer, messages: [] }], transfers, { auditor })).rejects.toThrow(
      ringError("RING_AUDIT_MESSAGE", { reason: "missing" }),
    );
  });

  it("refreshes the asset registry once for a mint the chain registers", async () => {
    const auditor = X25519Keypair.generate();
    const transfer = vectorTransaction(PACKED, auditor.publicKey());
    const registry = new Uint8Array(48);
    registry[0] = StateDiscriminator.splAssetRegistry;
    registry.set(new Uint8Array(getAddressEncoder().encode(FOREIGN_MINT as Address)), 8);
    new DataView(registry.buffer).setBigUint64(40, 2n, true);
    const getProgramAccounts = vi.fn(() => ({
      send: async () => [
        {
          account: {
            owner: SHIELDED_POOL_PROGRAM_ID,
            data: [Buffer.from(registry).toString("base64"), "base64"],
          },
        },
      ],
    }));
    const assets = new AssetRegistry();
    const page = await scan([transfer, transfer], transfers, {
      auditor,
      assets,
      solanaRpc: { getProgramAccounts },
    });
    expect(getProgramAccounts).toHaveBeenCalledTimes(1);
    for (const audited of page.transactions) {
      const exit = audited.outputs.find((output) => output.opening.kind === "exit")?.opening;
      expect(exit?.kind === "exit" && exit.utxo.mint).toBe(FOREIGN_MINT);
    }
  });

  it("follows the cursor to the page that states its frontier and stops at the page cap", async () => {
    const auditor = X25519Keypair.generate();
    const first = vectorTransaction(PACKED, auditor.publicKey());
    const second = { ...first, txSignature: "4".repeat(64) as Signature };
    const pages = [
      transactionsPage({ transactions: [first], nextCursor: Uint8Array.of(1) }),
      transactionsPage({ transactions: [second], scannedThrough: Uint8Array.of(2) }),
    ];
    const read = vi.fn(
      async (request: { cursor?: Uint8Array }) => pages[request.cursor?.[0] ?? 0]!,
    );
    const audit = (maxPages?: number) =>
      auditRing({
        client: ringAuditReader({ getShieldedTransactionsByTags: read }),
        auditor,
        ringProgramId: ring,
        assets: new AssetRegistry([[2n, FOREIGN_MINT]]),
        origin: transfers,
        ...(maxPages === undefined ? {} : { maxPages }),
      });
    const capped = await audit(1);
    expect(capped.transactions.map((audited) => audited.signature)).toEqual([SIGNATURE]);
    expect(capped.nextCursor).toEqual(Uint8Array.of(1));
    const complete = await audit();
    expect(complete.transactions.map((audited) => audited.signature)).toEqual([
      SIGNATURE,
      second.txSignature,
    ]);
    expect(complete.nextCursor).toBeUndefined();
    expect(read.mock.calls.map(([request]) => request.cursor)).toEqual([
      undefined,
      undefined,
      Uint8Array.of(1),
    ]);
  });

  it("refuses a page without a frontier, a cursor that does not advance and a zero limit", async () => {
    const auditor = X25519Keypair.generate();
    const audit = (
      pages: readonly ReturnType<typeof transactionsPage>[],
      limits: Readonly<{ pageSize?: number; maxPages?: number }> = {},
    ) => {
      const read = vi.fn(
        async (request: { cursor?: Uint8Array }) => pages[request.cursor?.[0] ?? 0]!,
      );
      return {
        read,
        result: auditRing({
          client: ringAuditReader({ getShieldedTransactionsByTags: read }),
          auditor,
          ringProgramId: ring,
          assets: new AssetRegistry(),
          origin: transfers,
          ...limits,
        }),
      };
    };
    await expect(audit([transactionsPage()]).result).rejects.toThrow(
      ringError("RING_SCAN_FRONTIER_MISSING"),
    );
    const stuck = [
      transactionsPage({ nextCursor: Uint8Array.of(1) }),
      transactionsPage({ nextCursor: Uint8Array.of(1) }),
    ];
    await expect(audit(stuck).result).rejects.toThrow(
      ringError("RING_RPC", { reason: "scan cursor did not advance" }),
    );
    for (const limits of [{ pageSize: 0 }, { maxPages: 0 }, { pageSize: 1.5 }]) {
      const { read, result } = audit(
        [transactionsPage({ scannedThrough: Uint8Array.of(1) })],
        limits,
      );
      await expect(result).rejects.toThrow(ringError("RING_RPC", { reason: "invalid scan limit" }));
      expect(read).not.toHaveBeenCalled();
    }
  });
});

describe("recoverRingMemberNotes", () => {
  const key = {
    txViewingSecret: field(PACKED_VECTOR.tx_viewing_sk),
    salt: hex<Bytes16>(PACKED_VECTOR.salt, 16),
  };
  const toHex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

  /** The packed `entry` with its first ring output paid to `owner`, the disclosure sealed again. */
  function ownedTransfer(owner: ShieldedKeypair, auditor: X25519PublicKey, entry = PACKED) {
    const address = owner.shieldedAddress();
    const ownerKey = address.signingPublicKey.ed25519();
    const opened = openRingDisclosure(key, {
      layout: entry.bound,
      fields: entry.vector.published.map(field),
      exits: entry.vector.slots.map((slot) => slot.kind === "exit"),
    });
    if (opened.kind !== "packed") throw new Error("packed vector");
    const slot = entry.vector.slots[0]!;
    const commitment = new Utxo({
      owner: address.signingPublicKey,
      asset: SOL_MINT,
      amount: BigInt(need(slot.amount, "amount")),
      blinding: field(slot.blinding),
      ringProgramId: RING,
    }).hash(address.nullifierPublicKey, entry.vector.output_tree_id);
    const nullifierPk = opened.layout.keyEscrow ? undefined : address.nullifierPublicKey;
    const vector: Vector = {
      ...entry.vector,
      published: sealRingDisclosure(key, {
        ...opened,
        outputs: opened.outputs.map((output, index) =>
          index === 0 && output !== undefined ? { ...output, ownerKey, nullifierPk } : output,
        ),
      }).map(toHex),
      slots: entry.vector.slots.map((vectorSlot, index) =>
        index === 0 ? { ...vectorSlot, output_hash: toHex(commitment) } : vectorSlot,
      ),
    };
    return {
      transaction: vectorTransaction({ layout: "packed", vector }, auditor),
      commitment,
    };
  }

  function recover(
    input: Readonly<{
      owner: ShieldedKeypair;
      auditor: X25519Keypair;
      transaction: IndexedShieldedTransaction;
      spends?: readonly IndexedShieldedTransaction[];
      nullifierKey?: ShieldedKeypair;
      tags?: () => ReturnType<typeof transactionsPage>;
      /** The ring's history, else the audited page. */
      history?: readonly IndexedShieldedTransaction[];
      origin?: TransactionOrigin;
    }>,
  ) {
    const page = () =>
      transactionsPage({ transactions: [input.transaction], scannedThrough: Uint8Array.of(1) });
    const { history } = input;
    return recoverRingMemberNotes({
      client: {
        ...ringAuditReader({
          getShieldedTransactionsByTags: async (request) =>
            request.tags.length === 0 && history !== undefined
              ? transactionsPage({ transactions: history, scannedThrough: Uint8Array.of(1) })
              : (input.tags ?? page)(),
        }),
        getShieldedTransactionsByNullifiers: async (request) =>
          transactionsPage({
            transactions: (input.spends ?? []).filter((spend) =>
              spend.nullifiers.some((nullifier) =>
                request.nullifiers.some((asked) => equal(asked, nullifier)),
              ),
            ),
            scannedThrough: Uint8Array.of(1),
          }),
      },
      ringProgramId: RING,
      auditor: input.auditor,
      source: input.owner.shieldedAddress(),
      nullifierKey: (input.nullifierKey ?? input.owner).nullifierKey(),
      assets: new AssetRegistry([[2n, FOREIGN_MINT]]),
      origin: input.origin ?? TRANSFERS,
    });
  }

  /** A ring merge spending `nullifier` first, its output encrypted for `owner`. */
  function mergeOf(owner: ShieldedKeypair, nullifier: Bytes32) {
    const key = owner.nullifierKey();
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const ringDataHash = new Uint8Array(32).fill(5) as Bytes32;
    const amount = 1000n;
    const blinding = mergeOutputBlinding(key, nullifier);
    const commitment = ownerUtxoHash({
      owner: poseidon([
        owner.shieldedAddress().signingPublicKey.ownerProofInputHash(),
        key.publicKey(),
      ]),
      asset: SOL_MINT,
      amount,
      blinding,
      treeId: PACKED_VECTOR.output_tree_id,
      ringDataHash,
      ringProgramId: RING,
    });
    const ciphertext = encryptMergeOutput(
      { amount, mint: SOL_MINT },
      mergeOutputKey(key, nullifier),
      salt,
    );
    const transaction: IndexedShieldedTransaction = {
      slot: 8n,
      txSignature: "6".repeat(64) as Signature,
      eventIndex: 0,
      proofless: false,
      ringProgramId: RING,
      nullifiers: [nullifier, new Uint8Array(32).fill(7) as Bytes32],
      messages: [],
      outputSlots: [
        {
          viewTag: nullifier,
          payload: encodeMergeOutputData({ salt, ciphertext, ringDataHash }),
          outputContext: {
            hash: commitment,
            tree: treeAddress(PACKED_VECTOR.output_tree_id),
            treeId: PACKED_VECTOR.output_tree_id,
            leafIndex: 9n,
          },
        },
      ],
    };
    return { transaction, commitment };
  }

  it("recovers the source's unspent ring note and drops it once a confirmed spend names its nullifier", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey());
    const recovered = await recover({ owner, auditor, transaction });
    expect(recovered.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
      [commitment, 1000n],
    ]);
    expect(recovered.unopened).toEqual([]);
    const nullifier = recovered.notes[0]!.nullifier;
    const spend = {
      ...transaction,
      txSignature: "5".repeat(64) as Signature,
      nullifiers: [nullifier],
    };
    const spent = await recover({ owner, auditor, transaction, spends: [spend] });
    expect(spent.notes).toEqual([]);
  });

  it("opens the source's escrowed note and passes over another owner's", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const escrow = vectorOf("packed", "escrow");
    const { transaction, commitment } = ownedTransfer(owner, auditor.publicKey(), escrow);
    const recovered = await recover({
      owner,
      auditor,
      transaction,
      origin: {
        confirmedTransaction: async (indexed) => ({
          kind: "transfer",
          transaction: indexed,
          inputTreeIds: indexed.nullifiers.map(() => undefined),
          layout: escrow.bound,
        }),
      },
    });
    expect(recovered.notes.map((note) => note.outputContext.hash)).toEqual([commitment]);
    expect(recovered.unopened).toEqual([]);
  });

  it("opens the deposit and merge notes an anonymous transfer spends under the commitment key", async () => {
    const auditor = X25519Keypair.generate();
    const entry = vectorOf("anonymous", "commitment");
    const vector = anonymousCase("commitment");
    const [deposited, merged] = vector.inputs;
    if (deposited === undefined || merged === undefined) throw new Error("two spent notes");
    const depositSignature = "2".repeat(87) as Signature;
    const mergeSignature = "3".repeat(87) as Signature;
    const leaf = (input: typeof deposited, leafIndex: bigint) => ({
      hash: field(input.commitment),
      tree: treeAddress(input.input_tree_id),
      treeId: input.input_tree_id,
      leafIndex,
    });
    const sealed = sealRingDepositOpenings(
      [
        {
          ownerHash: field(deposited.owner_hash),
          blinding: field(deposited.blinding),
          ownerKey: field(vector.sender_key),
          recipientCiphertext: Uint8Array.of(1),
        },
      ],
      auditor.publicKey(),
    );
    const salt = new Uint8Array(16).fill(4) as Bytes16;
    const disclosed = sealRingMergeDisclosure(
      {
        ownerKey: encodeBase58(field(vector.sender_key)),
        nullifierPublicKey: field(vector.sender_nullifier_pk),
        mint: encodeBase58(field(merged.asset_address)),
        amount: BigInt(merged.amount),
        outputBlinding: field(merged.blinding),
        inputCommitments: Array.from(
          { length: 8 },
          (_, index) => new Uint8Array(32).fill(index === 0 ? 1 : 0) as Bytes32,
        ),
      },
      salt,
      auditor.publicKey(),
    );
    try {
      const owner = ownerUtxoHash(field(deposited.owner_hash), field(deposited.blinding));
      const deposits = ConfirmedDeposit.fromTransaction(
        confirmedDepositTransaction(RING, depositSignature, sealed.capsules, [owner]),
        depositSignature,
        0,
        RING,
      );
      const deposit: IndexedShieldedTransaction = {
        slot: 5n,
        txSignature: depositSignature,
        eventIndex: 0,
        proofless: true,
        ringProgramId: RING,
        nullifiers: [],
        messages: [],
        outputSlots: [
          {
            viewTag: new Uint8Array(32) as Bytes32,
            outputContext: leaf(deposited, 0n),
            payload: ringDepositPayload({
              ring: RING,
              ownerCommitment: owner,
              asset: encodeBase58(field(deposited.asset_address)),
              amount: BigInt(deposited.amount),
              capsule: sealed.capsules[0]!,
            }),
          },
        ],
      };
      const firstNullifier = new Uint8Array(32).fill(0x21) as Bytes32;
      const merge: IndexedShieldedTransaction = {
        slot: 6n,
        txSignature: mergeSignature,
        eventIndex: 0,
        proofless: false,
        ringProgramId: RING,
        nullifiers: [firstNullifier, new Uint8Array(32).fill(0x22) as Bytes32],
        messages: [],
        outputSlots: [
          {
            viewTag: firstNullifier,
            outputContext: leaf(merged, 1n),
            payload: encodeMergeOutputData({
              salt,
              ciphertext: encryptMergeOutput(
                { amount: BigInt(merged.amount), mint: encodeBase58(field(merged.asset_address)) },
                mergeOutputKey(ShieldedKeypair.generate().nullifierKey(), firstNullifier),
                salt,
              ),
              ringDataHash: new Uint8Array(32) as Bytes32,
            }),
          },
        ],
      };
      const disclosure = {
        ...disclosed.disclosure,
        proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
      };
      const recovered = await recover({
        owner: ShieldedKeypair.generate(),
        auditor,
        transaction: vectorTransaction(entry, auditor.publicKey()),
        history: [deposit, merge],
        origin: {
          confirmedTransaction: async (indexed) => {
            if (indexed.txSignature === depositSignature)
              return { kind: "deposit", transaction: indexed, deposits };
            if (indexed.txSignature === mergeSignature)
              return { kind: "merge", transaction: indexed, disclosure };
            return {
              kind: "transfer",
              transaction: indexed,
              inputTreeIds: indexed.nullifiers.map(() => undefined),
              layout: entry.bound,
            };
          },
        },
      });
      expect(recovered).toEqual({
        notes: [],
        unopened: [],
        unsupportedDeposits: [],
        unknownMints: [],
      });
    } finally {
      sealed.ephemeralSecret.fill(0);
      disclosed.ephemeralSecret.fill(0);
      disclosed.disclosureKey.fill(0);
      auditor.destroy();
    }
  });

  it("follows a spend into the merge that folded the note and recovers the merged output", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    const unspent = await recover({ owner, auditor, transaction });
    const merge = mergeOf(owner, unspent.notes[0]!.nullifier);
    const origin: TransactionOrigin = {
      confirmedTransaction: async (indexed, ring) =>
        indexed.txSignature === merge.transaction.txSignature
          ? { kind: "merge", transaction: indexed }
          : TRANSFERS.confirmedTransaction(indexed, ring),
    };
    const merged = await recover({
      owner,
      auditor,
      transaction,
      spends: [merge.transaction],
      origin,
    });
    expect(merged.notes.map((note) => [note.outputContext.hash, note.utxo.amount])).toEqual([
      [merge.commitment, 1000n],
    ]);
    expect(merged.unopened).toEqual([]);
  });

  it("refuses another nullifier key, an output the auditor cannot open and a scan the page cap cuts", async () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const { transaction } = ownedTransfer(owner, auditor.publicKey());
    await expect(
      recover({ owner, auditor, transaction, nullifierKey: ShieldedKeypair.generate() }),
    ).rejects.toThrow(ringError("RING_NULLIFIER_KEY_MISMATCH"));
    const moved = withSlot(3, (slot) => ({
      ...slot,
      outputContext: { ...slot.outputContext, hash: field(PACKED_VECTOR.slots[0]!.output_hash) },
    }))(transaction);
    await expect(recover({ owner, auditor, transaction: moved })).rejects.toThrow(
      ringError("RING_AUDIT_OUTPUT_MISMATCH", { reason: "unopened", slotIndex: 3 }),
    );
    let page = 0;
    const endless = () => transactionsPage({ nextCursor: Uint8Array.of(++page) });
    await expect(recover({ owner, auditor, transaction, tags: endless })).rejects.toThrow(
      ringError("RING_RECOVERY_INCOMPLETE"),
    );
  });
});
