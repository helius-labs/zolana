/** The audit half of a ring transfer, the auditor envelope, the masked disclosure and the audit request, Rust `pipeline::audit`. */
import {
  EMPTY_RING_OPENING,
  ringInputOpening,
  ringOutputOpening,
} from "../client/prover/assembly.js";
import type {
  AnonymousAuditProofRequest,
  AnonymousSlotProofInputs,
  AnonymousStreamPosition,
  DeliveredAuditProofRequest,
  DeliveredSlotProofInputs,
  FirstContactAnchor,
  PackedAuditProofRequest,
} from "../client/prover/ring.js";
import { addressBytes } from "../interface/internal.js";
import {
  anonymousKeyClass,
  type AuditLayout,
  type DisclosureLayout,
} from "../interface/ring-disclosure-layout.js";
import type { Bytes32, MessageData } from "../interface/types.js";
import { auditorMessageData, sealTransactionViewingSecret } from "../keypair/audit.js";
import {
  anonymousCommitments,
  sealRingDisclosure,
  type AnonymousInputs,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
  type PackedOutputOpening,
  type RingDisclosure,
} from "../keypair/ring-disclosure.js";
import { BODY_LEN, ringTagField } from "../keypair/ring-stream.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import type { X25519PublicKey } from "../keypair/x25519.js";
import { assetField, type SppProofInputs } from "../transaction/instructions/transact.js";
import type { ProofOutputUtxo } from "../transaction/utxo.js";

import { RingError } from "./error.js";
import type { PublishedSlot, RingOutputRail } from "./rail.js";

/** The envelope and the masked disclosure every audit statement binds, Rust `SealedAudit`. */
export interface SealedAudit {
  /** The statement's layout element. */
  readonly audit: AuditLayout;
  readonly layout: DisclosureLayout;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly sealed: Bytes32;
  /** The audit proof's witness, the caller wipes it once the proof returns. */
  readonly ephemeralSecret: Bytes32;
  /** The published fields. */
  readonly fields: readonly Bytes32[];
  readonly seedOut: Bytes32;
}

/** The anonymous audit statement's values beside the envelope, Rust `AnonymousStatement`. */
export interface AnonymousAuditValues {
  readonly privateTxHash: Bytes32;
  readonly privateTxBlinding: Bytes32;
  /** Zero outside a policy ring. */
  readonly senderCommitment: Bytes32;
  readonly epoch: bigint;
  /** Zero without a pair-anchored slot. */
  readonly firstContactRoot: Bytes32;
  readonly anchor?: FirstContactAnchor;
}

/** The values a disclosure opens beside the published slots, Rust `AuditSeal::seal`. */
export function sealAudit(
  input: Readonly<{
    rail: RingOutputRail;
    audit: AuditLayout;
    layout: DisclosureLayout;
    published: readonly PublishedSlot[];
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
    auditor: X25519PublicKey;
  }>,
): SealedAudit {
  const seedOut = input.proofInputs.outputBlindingSeed();
  const disclosure = auditDisclosure(input, seedOut);
  const txViewingSecret = input.rail.txViewingKey.secretBytes();
  try {
    const fields = sealRingDisclosure({ txViewingSecret, salt: input.rail.salt }, disclosure);
    // The ephemeral secret comes last, a refusal before it leaves no copy to wipe.
    const envelope = sealTransactionViewingSecret(txViewingSecret, input.auditor);
    return Object.freeze({
      audit: input.audit,
      layout: input.layout,
      ephemeralPublicKey: envelope.ephemeralPublicKey,
      sealed: envelope.sealed,
      ephemeralSecret: envelope.ephemeralSecret,
      fields,
      seedOut,
    });
  } finally {
    txViewingSecret.fill(0);
  }
}

/** The message the program expands under the auditor's view tag, Rust `SealedAudit::message`. */
export function sealedAuditMessage(sealed: SealedAudit, auditor: X25519PublicKey): MessageData {
  return auditorMessageData(
    {
      ephemeralPublicKey: sealed.ephemeralPublicKey,
      sealed: sealed.sealed,
      disclosure: sealed.fields,
    },
    auditor,
  );
}

export type AuditProofRequest =
  | PackedAuditProofRequest
  | DeliveredAuditProofRequest
  | AnonymousAuditProofRequest;

/** The audit proof's request, one layout per rail, Rust `AuditProving::prove`. */
export function auditProofRequest(
  input: Readonly<{
    rail: RingOutputRail;
    sealed: SealedAudit;
    published: readonly PublishedSlot[];
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
    auditor: X25519PublicKey;
    ringId: Bytes32;
    publicInputHash: Bytes32;
    /** Present exactly on the anonymous rail. */
    anonymous?: AnonymousAuditValues;
  }>,
): AuditProofRequest {
  const { sealed, proofInputs, published } = input;
  const tree = proofInputs.outputTreeId;
  const capacity = proofInputs.outputs.length;
  const shared = {
    firstNullifier: proofInputs.firstNullifier(),
    ringId: input.ringId,
    ephSk: sealed.ephemeralSecret,
    auditorPk: input.auditor.u(),
    salt: input.rail.salt,
    seedOut: sealed.seedOut,
    layout: sealed.audit,
    publicInputHash: input.publicInputHash,
  };
  // The secret is copied last, a refusal before it leaves no copy to wipe.
  const envelope = () => ({
    ...shared,
    txViewingSk: input.rail.txViewingKey.secretBytes(),
  });
  switch (sealed.layout.kind) {
    case "packed": {
      const outputs = Array.from({ length: capacity }, (_, index) => {
        const slot = published[index];
        return slot === undefined ? EMPTY_RING_OPENING : ringOutputOpening(slot.output, tree);
      });
      const ownerKeys = Array.from({ length: capacity }, (_, index) => {
        const output = published[index]?.output;
        return output === undefined ? zeroField() : slotOwnerKey(output);
      });
      return Object.freeze({
        kind: "packedAudit",
        nOut: sealed.layout.outputs,
        outputs,
        ownerKeys,
        ...envelope(),
      });
    }
    case "delivered": {
      const outputs = published.map((slot) => deliveredSlot(slot, tree));
      return Object.freeze({ kind: "deliveredAudit", outputs, ...envelope() });
    }
    case "anonymous": {
      const statement = input.anonymous;
      if (statement === undefined)
        throw new RingError("RING_ANONYMOUS_SIGNER_REQUIRED", { details: { reason: "audit" } });
      const openings = proofInputs.inputUtxos
        .filter((spent) => !spent.isCompact())
        .map(ringInputOpening);
      const slots = {
        outputs: published.map((slot) => anonymousSlot(slot, tree)),
        privateTxHash: statement.privateTxHash,
        privateTxBlinding: statement.privateTxBlinding,
        ...(sealed.layout.key.kind === "entry"
          ? { senderKey: input.sender.signingPublicKey.confidentialViewTag() }
          : {}),
        inputCount: sealed.layout.inputs,
        inputs: [
          ...openings,
          ...Array.from(
            { length: anonymousKeyClass(sealed.layout.key) - openings.length },
            () => EMPTY_RING_OPENING,
          ),
        ],
        senderCommitment: statement.senderCommitment,
        epoch: statement.epoch,
        firstContactRoot: statement.firstContactRoot,
        ...(statement.anchor === undefined ? {} : { anchor: statement.anchor }),
      };
      return Object.freeze({ kind: "anonymousAudit", ...slots, ...envelope() });
    }
  }
}

/** Rust `AuditSeal::disclosure`, the plaintext the CROD pad masks, `SeedOut` only beside an exit. */
function auditDisclosure(
  input: Readonly<{
    layout: DisclosureLayout;
    published: readonly PublishedSlot[];
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
  }>,
  seedOut: Bytes32,
): RingDisclosure {
  const { layout, published } = input;
  const disclosedSeed = layout.exits ? seedOut : undefined;
  switch (layout.kind) {
    case "packed":
      return {
        kind: "packed",
        layout,
        seedOut: disclosedSeed,
        outputs: published.map((slot) => packedOpening(slot, layout.keyEscrow)),
      };
    case "delivered":
      return {
        kind: "delivered",
        layout,
        seedOut: disclosedSeed,
        outputs: published.map((slot) => deliveredOpening(slot, layout.keyEscrow)),
      };
    case "anonymous":
      return {
        kind: "anonymous",
        layout,
        seedOut: disclosedSeed,
        outputs: published.map(anonymousOpening),
        inputs: anonymousInputs(layout.key.kind, input.proofInputs, input.sender),
      };
  }
}

function anonymousInputs(
  key: "commitment" | "entry",
  proofInputs: SppProofInputs,
  sender: ShieldedAddress,
): AnonymousInputs {
  const spent = proofInputs.inputUtxos.filter((input) => !input.isCompact());
  if (key === "commitment")
    return anonymousCommitments(spent.map((input) => (input.isDummy() ? undefined : input.hash())));
  return {
    kind: "openings",
    senderKey: sender.signingPublicKey.confidentialViewTag(),
    senderNullifierPk: sender.nullifierPublicKey,
    inputs: spent.map((input, index) => {
      if (input.isDummy()) return undefined;
      // The entry key opens a spent UTXO with no data.
      if (input.dataHash !== undefined || input.ringDataHash !== undefined)
        throw new RingError("RING_ENTRY_INPUT_DATA", { details: { index } });
      return {
        asset: assetField(input.utxo.asset),
        amount: input.utxo.amount,
        blinding: input.utxo.blinding,
      };
    }),
  };
}

/** `undefined` for a dummy, the nullifier key left to the owner's escrow record under key escrow. */
function packedOpening(slot: PublishedSlot, keyEscrow: boolean): PackedOutputOpening | undefined {
  const { output } = slot;
  const owner = output.ownerAddress;
  if (owner === undefined) return undefined;
  return {
    ownerKey: owner.signingPublicKey.confidentialViewTag(),
    nullifierPk: keyEscrow ? undefined : owner.nullifierPublicKey,
    asset: assetField(output.asset),
    amount: output.amount,
    dataHash: output.dataHash ?? zeroField(),
    ringDataHash: output.ringDataHash ?? zeroField(),
  };
}

function deliveredOpening(slot: PublishedSlot, keyEscrow: boolean): DeliveredOutputOpening {
  const { output } = slot;
  const owner = output.ownerAddress;
  if (owner === undefined) return { kind: "dummy" };
  const nullifierPk = keyEscrow ? undefined : owner.nullifierPublicKey;
  return slot.wire.kind === "exit"
    ? { kind: "exit", nullifierPk, asset: assetField(output.asset), amount: output.amount }
    : { kind: "ring", nullifierPk, ownerKey: owner.signingPublicKey.confidentialViewTag() };
}

function anonymousOpening(slot: PublishedSlot): AnonymousOutputOpening {
  const { output } = slot;
  const owner = output.ownerAddress;
  if (owner === undefined) return { kind: "dummy" };
  if (slot.wire.kind === "exit")
    return {
      kind: "exit",
      nullifierPk: owner.nullifierPublicKey,
      asset: assetField(output.asset),
      amount: output.amount,
    };
  if (slot.recipient === undefined)
    throw new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex: slot.slotIndex } });
  return {
    kind: "ring",
    nullifierPk: owner.nullifierPublicKey,
    ownerKey: owner.signingPublicKey.confidentialViewTag(),
    recipientU: slot.recipient.u(),
  };
}

/** A ring output opens its body for its recipient, padding binds its published key and body. */
function deliveredSlot(slot: PublishedSlot, tree: number): DeliveredSlotProofInputs {
  const { output, wire } = slot;
  const zero = zeroField();
  const [recipientKey, body] =
    wire.kind === "delivered"
      ? [wire.u, wire.body]
      : wire.kind === "anonymous"
        ? [slot.recipient?.u() ?? zero, wire.body]
        : [zero, new Uint8Array(BODY_LEN)];
  const ring = !output.isDummy() && wire.kind !== "exit";
  return Object.freeze({
    output: ringOutputOpening(output, tree),
    assetAddress: addressBytes(output.asset, "asset") as Bytes32,
    recipientKey,
    ownerKey: ring ? slotOwnerKey(output) : zero,
    body,
  });
}

function anonymousSlot(slot: PublishedSlot, tree: number): AnonymousSlotProofInputs {
  return Object.freeze({ ...deliveredSlot(slot, tree), stream: streamPosition(slot) });
}

/** Rust `Stream`, a ring output takes exactly one of the inbox, pair and change streams. */
function streamPosition(slot: PublishedSlot): AnonymousStreamPosition {
  const anonymous = slot.anonymous;
  const none = { tag: zeroField(), inbox: false, pair: false, self: false, index: 0 };
  switch (anonymous?.kind) {
    case "payment": {
      const inbox = anonymous.payment.position.kind === "inbox";
      return {
        ...none,
        tag: ringTagField(anonymous.payment.tag),
        inbox,
        pair: !inbox,
        index: anonymous.payment.position.index,
      };
    }
    case "change":
      return { ...none, tag: ringTagField(anonymous.tag), self: true };
    case "dummy":
      return { ...none, tag: ringTagField(anonymous.tag) };
    case "exit":
    case undefined:
      return none;
  }
}

/** The owner's Solana key a slot discloses, zero for padding, Rust `slot_owner_key`. */
function slotOwnerKey(output: ProofOutputUtxo): Bytes32 {
  return output.ownerAddress?.signingPublicKey.confidentialViewTag() ?? zeroField();
}

function zeroField(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}
