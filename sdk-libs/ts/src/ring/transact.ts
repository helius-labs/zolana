import { decompressG2 } from "../client/prover/proof.js";
import { hashBytes, packBytesBe } from "../hasher/index.js";
import {
  encodeTransactInstructionData,
  readInterfaceTransfer,
  readTreeContext,
  writeInterfaceTransfer,
  writeTreeContext,
} from "../interface/codecs/index.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { InterfaceError } from "../interface/errors.js";
import { externalDataHash, type SettlementAccounts } from "../interface/external-data-hash.js";
import { Reader, Writer } from "../interface/internal.js";
import { InstructionTag } from "../interface/program.js";
import { N_PUBLIC_SLOTS, RING_AUTHORITY_SHAPES, SPP_SUPPORTED_SHAPES } from "../interface/shape.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  Bytes128,
  CircuitId,
  InterfaceTransfer,
  TransactInstructionData,
  TransactOutput,
  TreeContext,
} from "../interface/types.js";
import {
  DELIVERED_AUDIT_CAPACITIES,
  PACKED_AUDIT_CAPACITIES,
  anonymousAuditKey,
  disclosureFieldCount,
  type AuditLayout,
  type DisclosureLayout,
} from "../interface/ring-disclosure-layout.js";
import { BODY_LEN, TAG_LEN, ringTagField, tagEpoch } from "../keypair/ring-stream.js";
import {
  CONFIDENTIAL_DATA_FREE_BODY_LEN,
  EncryptedScheme,
  RECIPIENT_KEY_LEN,
  RING_PACKED_DATA_FREE_BODY_LEN,
  encodeOutputData,
} from "../transaction/serialization/codecs.js";

import { RingInstructionTag } from "./admin.js";
import type { RingMode } from "./codecs.js";
import { RingError } from "./error.js";

/** The program rail the data serves, fixed by the instruction and the ring mode. */
export type RingRail = "confidential" | "anonymous" | "delegate";

/** The policy proof and the roots it binds. */
export interface PolicyProof {
  readonly proof: Uint8Array;
  readonly ownRootIndex: number;
  /** Set exactly when a source names the curator registry. */
  readonly curatorRootIndex?: number;
  /** Set exactly on the anonymous rail. */
  readonly senderCommitment?: Bytes32;
}

/** The SPP state tree root a pair-anchored slot's first contact opens under. */
export interface AnchorRoot {
  /** Index into the instruction's accounts. */
  readonly tree: number;
  /** Index into the tree's UTXO root history. */
  readonly rootIndex: number;
}

/** The anonymous SPP rail's BSB22 commitment and its hidden owner's default-ring key. */
export interface AnonymousProofData {
  readonly commitment: Bytes32;
  readonly commitmentPok: Bytes32;
  readonly defaultOwnerTag?: Bytes32;
}

export type InputTrees =
  | Readonly<{ kind: "one"; context: TreeContext }>
  | Readonly<{
      kind: "two";
      first: TreeContext;
      second: TreeContext;
      /** Bit `i` spends input `i` from `second`. */
      secondInputs: bigint;
    }>;

/** One published output slot without its SPP framing, Rust `RingOutput`. */
export type RingOutput =
  | Readonly<{ kind: "packed"; hash: Bytes32; u: Bytes32; ciphertext: Uint8Array }>
  | Readonly<{ kind: "delivered"; hash: Bytes32; u: Bytes32; body: Uint8Array }>
  | Readonly<{ kind: "anonymous"; hash: Bytes32; tag: Bytes16; body: Uint8Array }>
  | Readonly<{ kind: "exit"; hash: Bytes32; ownerTag: Bytes32; payload: Uint8Array }>;

/** The data of `Transact` and `DelegateTransact`, Rust `RingTransactData`. */
export interface RingTransactData {
  readonly rail: RingRail;
  /** SPP shape inputs. */
  readonly nIn: number;
  /** SPP shape outputs. */
  readonly nOut: number;
  readonly auditProof: Uint8Array;
  /** Present exactly on a policy ring. */
  readonly policy?: PolicyProof;
  readonly approvalRequired: boolean;
  /** The anonymous rail's statement epoch is the one before the landing slot's. */
  readonly previousEpoch: boolean;
  readonly anchor?: AnchorRoot;
  readonly expiryUnixTs: number;
  readonly txViewingU: Bytes32;
  /** Random per attempt, a resend under the same first nullifier reuses no pad or keystream. */
  readonly salt: Bytes16;
  readonly interfaceTransfers: readonly InterfaceTransfer[];
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
  /** No output carries data, packed ciphertexts and exit payloads take their data-free lengths. */
  readonly dataFree: boolean;
  /** The policy proof escrows every output nullifier key, the ring mode's. */
  readonly keyEscrow: boolean;
  /** The anonymous entry key, every spent UTXO opens in full. */
  readonly fullOpenings: boolean;
  /** Published order. */
  readonly outputs: readonly RingOutput[];
  readonly ephU: Bytes32;
  readonly sealed: Bytes32;
  /** Exactly the fields the disclosure layout publishes. */
  readonly disclosure: readonly Bytes32[];
  readonly privateTxHash: Bytes32;
  /** Present exactly on the anonymous rail. */
  readonly anonymous?: AnonymousProofData;
  /** `a ‖ b ‖ c` with `b` compressed. */
  readonly sppProof: Uint8Array;
  /** One per spent input slot SPP publishes. */
  readonly nullifiers: readonly Bytes32[];
  readonly inputTrees: InputTrees;
}

/** The ring config values the program expands the data with. */
export interface RingTransactConfig {
  /** `0x04 ‖ u`. */
  readonly auditorPubkey: Bytes33;
  /** Zero without a co-signer, appended to the SPP data on the anonymous rail. */
  readonly coSigner: Bytes32;
}

/** The rail of the ring instruction `tag` under `mode`, Rust `RingRail::of`. */
export function ringRailOf(tag: number, mode: RingMode): RingRail {
  if (tag === RingInstructionTag.transact)
    return mode === "anonymous" ? "anonymous" : "confidential";
  if (tag !== RingInstructionTag.delegateTransact) throw invalid("InvalidInstructionData");
  if (mode === "anonymous") throw invalid("AnonymousRingRefused");
  return "delegate";
}

/** Rust `RingRail::new`, the delegate rail needs the delegate only `SetDelegate` writes. */
export function ringRail(
  tag: number,
  config: Readonly<{ mode: RingMode; delegate?: Address }>,
): RingRail {
  const rail = ringRailOf(tag, config.mode);
  if (rail === "delegate" && config.delegate === undefined) throw invalid("DelegateDisabled");
  return rail;
}

export function railSppTag(rail: RingRail): number {
  return rail === "delegate" ? InstructionTag.ringAuthorityTransact : InstructionTag.ringTransact;
}

/** `hash_bytes(body)` of a delivered or anonymous slot, zero for any other. */
export function outputBodyHash(output: RingOutput): Bytes32 {
  return output.kind === "delivered" || output.kind === "anonymous"
    ? (hashBytes(checkedBody(output.body)) as Bytes32)
    : ZERO;
}

/** `pack_be(u)` of a delivered slot, zeros for any other. */
export function outputRecipientKeyFields(output: RingOutput): readonly Bytes32[] {
  return output.kind === "delivered"
    ? (packBytesBe(checkedField(output.u, "u")) as Bytes32[])
    : [ZERO, ZERO];
}

/** `0^16 ‖ tag` of an anonymous slot, zero for any other. */
export function outputTagField(output: RingOutput): Bytes32 {
  return output.kind === "anonymous" ? ringTagField(output.tag) : ZERO;
}

/** SPP's input slots and tree contexts, the nullifier accounts the instruction names follow them. */
export function ringSppInputs(
  data: Pick<RingTransactData, "nullifiers" | "inputTrees">,
): Pick<TransactInstructionData, "inputs" | "treeContexts"> {
  return Object.freeze({
    inputs: data.nullifiers.map((nullifierHash, input) =>
      Object.freeze({ nullifierHash, treeIndex: treeIndex(data.inputTrees, input) }),
    ),
    treeContexts:
      data.inputTrees.kind === "one"
        ? [data.inputTrees.context]
        : [data.inputTrees.first, data.inputTrees.second],
  });
}

/** Whether the slot frames at its data-free length, packed ciphertexts and exit payloads have one. */
export function isDataFreeOutput(output: RingOutput): boolean {
  switch (output.kind) {
    case "packed":
      return output.ciphertext.length === DATA_FREE_PACKED_CIPHERTEXT_LEN;
    case "exit":
      return output.payload.length === CONFIDENTIAL_DATA_FREE_BODY_LEN;
    case "delivered":
    case "anonymous":
      return true;
  }
}

/** The layout the audit key of a shape publishes, `inputs` and `outputs` the published counts. */
export function ringDisclosureLayout(
  shape: Readonly<{
    rail: RingRail;
    nIn: number;
    nOut: number;
    inputs: number;
    outputs: number;
    layout: AuditLayout;
  }>,
): DisclosureLayout {
  const { keyEscrow, dataFree, fullOpenings } = shape.layout;
  const flags: FrameFlags = { defaultOwnerTag: false, dataFree, keyEscrow, fullOpenings };
  checkFrameFlags(flags, shape.rail);
  return auditShape(shape.rail, {
    nIn: shape.nIn,
    nOut: shape.nOut,
    inputCount: shape.inputs,
    flags,
  }).layout(shape.outputs, shape.layout);
}

/** `0x04 ‖ u`, the tagged key the statements pack and SPP carries. */
export function taggedX25519(u: Bytes32): Bytes33 {
  const key = new Uint8Array(33);
  key[0] = VIEWING_PUBKEY_TAG;
  key.set(checkedField(u, "u"), 1);
  return key as Bytes33;
}

export const RingTransactData = Object.freeze({
  /** Every length fixed by the flags, the shape and the counts, trailing bytes refused. */
  parse(data: Uint8Array, rail: RingRail): RingTransactData {
    const bytes = new Reader(data);
    try {
      return readCompact(bytes, rail);
    } catch (error) {
      throw shortRead(error, "RingTransactLength");
    }
  },

  /** The bytes `parse` reads back, refusing what it refuses. */
  encode(data: RingTransactData): Uint8Array {
    try {
      return writeCompact(data);
    } catch (error) {
      throw shortRead(error, "InvalidInstructionData");
    }
  },

  /** The statement's layout element, the exits flag read from the outputs. */
  auditLayout(data: RingTransactData): AuditLayout {
    return Object.freeze({
      exits: data.outputs.some((output) => output.kind === "exit"),
      keyEscrow: data.keyEscrow,
      dataFree: data.dataFree,
      fullOpenings: data.fullOpenings,
    });
  },

  disclosureLayout(data: RingTransactData): DisclosureLayout {
    return ringDisclosureLayout({
      rail: data.rail,
      nIn: data.nIn,
      nOut: data.nOut,
      inputs: data.nullifiers.length,
      outputs: data.outputs.length,
      layout: RingTransactData.auditLayout(data),
    });
  },

  /** The SPP selector of the data's shape and rail. */
  circuit(data: RingTransactData): CircuitId {
    return circuitId(data.rail, data.nIn, data.nOut, data.anonymous);
  },

  firstNullifier(data: RingTransactData): Bytes32 {
    const first = data.nullifiers[0];
    if (first === undefined) throw invalid("RingTransactLength");
    return first;
  },

  /** The statement epoch of a transfer landing at `slot`. */
  epoch(data: RingTransactData, slot: bigint): bigint {
    const epoch = tagEpoch(slot) - (data.previousEpoch ? 1n : 0n);
    if (epoch < 0n) throw invalid("EpochUnderflow");
    return epoch;
  },

  /** The SPP data the program forwards, `b` decompressed for SPP's verifier. */
  expand(data: RingTransactData, config: RingTransactConfig): TransactInstructionData {
    let b: Bytes128;
    try {
      b = decompressG2(data.sppProof.slice(32, 96) as Bytes64);
    } catch (cause) {
      throw new RingError("RING_TRANSACT_DATA_INVALID", {
        details: { reason: "InvalidSppProofPoint" },
        cause,
      });
    }
    return transactIxData(data, config, {
      a: data.sppProof.slice(0, 32) as Bytes32,
      b,
      c: data.sppProof.slice(96, 128) as Bytes32,
    });
  },

  /** `tag ‖ TransactIxData`, on the anonymous rail followed by the configured co-signer. */
  sppInstructionData(data: RingTransactData, config: RingTransactConfig): Uint8Array {
    const expanded = encodeTransactInstructionData(RingTransactData.expand(data, config));
    const coSigner =
      data.rail === "anonymous" ? checkedField(config.coSigner, "coSigner") : ZERO_BYTES;
    const out = new Uint8Array(1 + expanded.length + coSigner.length);
    out[0] = railSppTag(data.rail);
    out.set(expanded, 1);
    out.set(coSigner, 1 + expanded.length);
    return out;
  },

  /** The external data hash the SPP proof binds, computable before either proof exists. */
  externalDataHash(
    data: RingTransactData,
    config: RingTransactConfig,
    settlements: readonly SettlementAccounts[],
  ): Bytes32 {
    const expanded = transactIxData(data, config, ZERO_PROOF);
    return externalDataHash({
      ...expanded,
      instructionDiscriminator: railSppTag(data.rail),
      settlementAccounts: settlements,
      resolvedOwnerTags: expanded.outputs.map((output) =>
        output.ownerTag.kind === "inline" ? output.ownerTag.value : ZERO,
      ),
    });
  },
});

/** Byte 0 of the compact data. */
const Flag = Object.freeze({
  policy: 1 << 0,
  curator: 1 << 1,
  approvalRequired: 1 << 2,
  previousEpoch: 1 << 3,
  anchor: 1 << 4,
  secondTree: 1 << 5,
  dataHash: 1 << 6,
  ringDataHash: 1 << 7,
});

/** Bytes 1 and 2 of the compact data, the SPP shape's index and the input count below their flags. */
const FrameByte = Object.freeze({
  low: 0b0011_1111,
  bit6: 1 << 6,
  bit7: 1 << 7,
});

/** The flags of frame bytes 1 and 2, Rust `FrameFlags`. */
interface FrameFlags {
  /** Shape byte bit 6, the anonymous rail's default owner tag follows the commitment pok. */
  readonly defaultOwnerTag: boolean;
  /** Shape byte bit 7. */
  readonly dataFree: boolean;
  /** Input byte bit 6. */
  readonly keyEscrow: boolean;
  /** Input byte bit 7, the anonymous entry key. */
  readonly fullOpenings: boolean;
}

interface FrameHeader {
  readonly nIn: number;
  readonly nOut: number;
  readonly inputCount: number;
  readonly flags: FrameFlags;
}

/** The scheme 11 ciphertext after the recipient key of an output with no data. */
const DATA_FREE_PACKED_CIPHERTEXT_LEN = RING_PACKED_DATA_FREE_BODY_LEN - RECIPIENT_KEY_LEN;

/** `a ‖ b ‖ c` with `b` compressed, Rust `PlainGroth16Proof::SIZE`. */
export const PLAIN_GROTH16_PROOF_LENGTH = 128;
const VIEWING_PUBKEY_TAG = 4;
const ZERO = new Uint8Array(32) as Bytes32;
const ZERO_BYTES = new Uint8Array(0);
const ZERO_PROOF = Object.freeze({
  a: new Uint8Array(32) as Bytes32,
  b: new Uint8Array(128) as Bytes128,
  c: new Uint8Array(32) as Bytes32,
});

type AuditShape = Readonly<{
  /** Every delivered and anonymous slot is published, a packed transfer publishes a prefix. */
  fixedOutputs: number | undefined;
  layout(published: number, flags: AuditLayout): DisclosureLayout;
}>;

/** The audit key the header names, before the output count is read, Rust `RingRail::audit_shape`. */
function auditShape(rail: RingRail, header: FrameHeader): AuditShape {
  const { nIn, nOut, inputCount: inputs } = header;
  const keyed = rail === "delegate" ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
  const supported = keyed.some((shape) => shape.inputs === nIn && shape.outputs === nOut);
  let shape: AuditShape | undefined;
  if (rail !== "anonymous" && PACKED_AUDIT_CAPACITIES.includes(nOut)) {
    shape = {
      fixedOutputs: undefined,
      layout: (published, flags) => {
        if (!Number.isInteger(published) || published < 1 || published > nOut)
          throw invalid("RingTransactLength");
        return Object.freeze({
          kind: "packed",
          outputs: published,
          exits: flags.exits,
          keyEscrow: flags.keyEscrow,
          dataFree: flags.dataFree,
        });
      },
    };
  } else if (rail !== "anonymous" && DELIVERED_AUDIT_CAPACITIES.includes(nOut)) {
    shape = {
      fixedOutputs: nOut,
      layout: (published, flags) =>
        exactly(published, nOut, {
          kind: "delivered",
          outputs: nOut,
          exits: flags.exits,
          keyEscrow: flags.keyEscrow,
        }),
    };
  } else if (rail === "anonymous") {
    const key = anonymousAuditKey({
      inputs,
      outputs: nOut,
      spendsDefaultRing: header.flags.fullOpenings,
    });
    if (key !== undefined)
      shape = {
        fixedOutputs: nOut,
        layout: (published, flags) =>
          exactly(published, nOut, {
            kind: "anonymous",
            key,
            inputs,
            outputs: nOut,
            exits: flags.exits,
          }),
      };
  }
  if (shape === undefined || !supported) throw invalid("RingShapeUnkeyed");
  if (inputs === 0 || inputs > nIn) throw invalid("RingTransactLength");
  return shape;
}

/** Every delivered and anonymous slot is published. */
function exactly(published: number, outputs: number, layout: DisclosureLayout): DisclosureLayout {
  if (published !== outputs) throw invalid("RingTransactLength");
  return Object.freeze(layout);
}

function readCompact(bytes: Reader, rail: RingRail): RingTransactData {
  const flags = bytes.u8("flags");
  checkFlags(flags, rail);
  const header = readHeader(bytes, rail);
  const { nIn, nOut, inputCount } = header;
  const shape = auditShape(rail, header);
  const auditProof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "auditProof");
  const policy = has(flags, Flag.policy)
    ? readPolicy(bytes, has(flags, Flag.curator), rail === "anonymous")
    : undefined;
  const anchor = has(flags, Flag.anchor)
    ? Object.freeze({ tree: bytes.u8("anchor.tree"), rootIndex: bytes.u16("anchor.rootIndex") })
    : undefined;
  const expiryUnixTs = bytes.u32("expiryUnixTs");
  const txViewingU = field32(bytes, "txViewingU");
  const salt = bytes.bytes(16, "salt") as Bytes16;
  const interfaceTransfers = within("InvalidInstructionData", () =>
    Array.from({ length: bytes.u8("interfaceTransfers.length") }, () =>
      readInterfaceTransfer(bytes),
    ),
  );
  const dataHash = has(flags, Flag.dataHash) ? field32(bytes, "dataHash") : undefined;
  const ringDataHash = has(flags, Flag.ringDataHash) ? field32(bytes, "ringDataHash") : undefined;
  const outputCount = shape.fixedOutputs ?? bytes.u8("outputCount");
  const exits = readBitmap(bytes, outputCount);
  if (rail === "delegate" && exits !== 0n) throw invalid("FlagNotAllowed");
  const layout = shape.layout(outputCount, auditLayoutOf(header.flags, exits !== 0n));
  const frame: SlotFrame = { layout, dataFree: header.flags.dataFree };
  const outputs = Array.from({ length: outputCount }, (_, slot) =>
    readOutput(bytes, frame, ((exits >> BigInt(slot)) & 1n) === 1n),
  );
  const ephU = field32(bytes, "ephU");
  const sealed = field32(bytes, "sealed");
  const disclosure = Array.from({ length: disclosureFieldCount(layout) }, () =>
    field32(bytes, "disclosure"),
  );
  const privateTxHash = field32(bytes, "privateTxHash");
  const anonymous =
    rail === "anonymous" ? readAnonymous(bytes, header.flags.defaultOwnerTag) : undefined;
  const sppProof = bytes.bytes(PLAIN_GROTH16_PROOF_LENGTH, "sppProof");
  const nullifiers = Array.from({ length: inputCount }, () => field32(bytes, "nullifier"));
  const inputTrees: InputTrees = has(flags, Flag.secondTree)
    ? (() => {
        const secondInputs = readBitmap(bytes, inputCount);
        return Object.freeze({
          kind: "two" as const,
          first: readTreeContext(bytes),
          second: readTreeContext(bytes),
          secondInputs,
        });
      })()
    : Object.freeze({ kind: "one" as const, context: readTreeContext(bytes) });
  bytes.done();
  return Object.freeze({
    rail,
    nIn,
    nOut,
    auditProof,
    ...(policy === undefined ? {} : { policy }),
    approvalRequired: has(flags, Flag.approvalRequired),
    previousEpoch: has(flags, Flag.previousEpoch),
    ...(anchor === undefined ? {} : { anchor }),
    expiryUnixTs,
    txViewingU,
    salt,
    interfaceTransfers: Object.freeze(interfaceTransfers),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    dataFree: header.flags.dataFree,
    keyEscrow: header.flags.keyEscrow,
    fullOpenings: header.flags.fullOpenings,
    outputs: Object.freeze(outputs),
    ephU,
    sealed,
    disclosure: Object.freeze(disclosure),
    privateTxHash,
    ...(anonymous === undefined ? {} : { anonymous }),
    sppProof,
    nullifiers: Object.freeze(nullifiers),
    inputTrees,
  });
}

function readPolicy(bytes: Reader, curator: boolean, anonymous: boolean): PolicyProof {
  const proof = bytes.bytes(CUSTOM_RING_PROOF_LENGTH, "policy.proof");
  const ownRootIndex = bytes.u8("policy.ownRootIndex");
  const curatorRootIndex = curator ? bytes.u8("policy.curatorRootIndex") : undefined;
  const senderCommitment = anonymous ? field32(bytes, "policy.senderCommitment") : undefined;
  return Object.freeze({
    proof,
    ownRootIndex,
    ...(curatorRootIndex === undefined ? {} : { curatorRootIndex }),
    ...(senderCommitment === undefined ? {} : { senderCommitment }),
  });
}

function readAnonymous(bytes: Reader, tagged: boolean): AnonymousProofData {
  const commitment = field32(bytes, "anonymous.commitment");
  const commitmentPok = field32(bytes, "anonymous.commitmentPok");
  const defaultOwnerTag = tagged ? field32(bytes, "anonymous.defaultOwnerTag") : undefined;
  return Object.freeze({
    commitment,
    commitmentPok,
    ...(defaultOwnerTag === undefined ? {} : { defaultOwnerTag }),
  });
}

/** How every slot of one transfer is framed in the compact data, Rust `SlotFrame`. */
type SlotFrame = Readonly<{ layout: DisclosureLayout; dataFree: boolean }>;

function readOutput(bytes: Reader, frame: SlotFrame, exit: boolean): RingOutput {
  const hash = field32(bytes, "output.hash");
  if (exit) {
    const ownerTag = field32(bytes, "output.ownerTag");
    return Object.freeze({
      kind: "exit",
      hash,
      ownerTag,
      payload: readBody(bytes, frame, CONFIDENTIAL_DATA_FREE_BODY_LEN, "output.payload"),
    });
  }
  switch (frame.layout.kind) {
    case "packed": {
      const u = field32(bytes, "output.u");
      return Object.freeze({
        kind: "packed",
        hash,
        u,
        ciphertext: readBody(bytes, frame, DATA_FREE_PACKED_CIPHERTEXT_LEN, "output.ciphertext"),
      });
    }
    case "delivered": {
      const u = field32(bytes, "output.u");
      return Object.freeze({
        kind: "delivered",
        hash,
        u,
        body: bytes.bytes(BODY_LEN, "output.body"),
      });
    }
    case "anonymous": {
      const tag = bytes.bytes(TAG_LEN, "output.tag") as Bytes16;
      return Object.freeze({
        kind: "anonymous",
        hash,
        tag,
        body: bytes.bytes(BODY_LEN, "output.body"),
      });
    }
  }
}

/** A data-free body takes its fixed length, any other `len u16 ‖ bytes`. */
function readBody(
  bytes: Reader,
  frame: SlotFrame,
  dataFreeLength: number,
  name: string,
): Uint8Array {
  return frame.dataFree
    ? bytes.bytes(dataFreeLength, name)
    : bytes.bytes(bytes.u16(`${name}.length`), name);
}

/** `ceil(len / 8)` bytes, bit `i` at byte `i / 8` bit `i % 8`, no bit set past `len`. */
function readBitmap(bytes: Reader, length: number): bigint {
  const raw = bytes.bytes(Math.ceil(length / 8), "bitmap");
  const bits = raw.reduce((value, byte, index) => value | (BigInt(byte) << BigInt(8 * index)), 0n);
  if (bits >> BigInt(length) !== 0n) throw invalid("InvalidInstructionData");
  return bits;
}

function writeCompact(data: RingTransactData): Uint8Array {
  const flags = compactFlags(data);
  checkFlags(flags, data.rail);
  if ([data.dataFree, data.keyEscrow, data.fullOpenings].some((flag) => typeof flag !== "boolean"))
    throw invalid("InvalidInstructionData");
  const header = headerOf(data);
  const shape = auditShape(data.rail, header);
  const layout = shape.layout(data.outputs.length, RingTransactData.auditLayout(data));
  const anonymousRail = data.rail === "anonymous";
  const commitmentFits =
    data.policy === undefined || (data.policy.senderCommitment !== undefined) === anonymousRail;
  if (
    !commitmentFits ||
    (data.anonymous !== undefined) !== anonymousRail ||
    data.disclosure.length !== disclosureFieldCount(layout) ||
    !data.outputs.every((output) => fits(output, layout))
  )
    throw invalid("RingTransactLength");
  if (data.rail === "delegate" && data.outputs.some((output) => output.kind === "exit"))
    throw invalid("FlagNotAllowed");
  const [shapeByte, inputByte] = headerBytes(header);
  const out = new Writer()
    .u8(flags, "flags")
    .u8(shapeByte, "shapeByte")
    .u8(inputByte, "inputByte")
    .bytes(data.auditProof, CUSTOM_RING_PROOF_LENGTH, "auditProof");
  if (data.policy !== undefined) {
    out.bytes(data.policy.proof, CUSTOM_RING_PROOF_LENGTH, "policy.proof");
    out.u8(data.policy.ownRootIndex, "policy.ownRootIndex");
    if (data.policy.curatorRootIndex !== undefined)
      out.u8(data.policy.curatorRootIndex, "policy.curatorRootIndex");
    if (data.policy.senderCommitment !== undefined)
      out.bytes(data.policy.senderCommitment, 32, "policy.senderCommitment");
  }
  if (data.anchor !== undefined)
    out.u8(data.anchor.tree, "anchor.tree").u16(data.anchor.rootIndex, "anchor.rootIndex");
  out
    .u32(data.expiryUnixTs, "expiryUnixTs")
    .bytes(data.txViewingU, 32, "txViewingU")
    .bytes(data.salt, 16, "salt")
    .u8(data.interfaceTransfers.length, "interfaceTransfers.length");
  for (const transfer of data.interfaceTransfers) writeInterfaceTransfer(out, transfer);
  for (const hash of [data.dataHash, data.ringDataHash])
    if (hash !== undefined) out.bytes(hash, 32, "hash");
  if (shape.fixedOutputs === undefined) out.u8(data.outputs.length, "outputCount");
  writeBitmap(
    out,
    data.outputs.map((output) => output.kind === "exit"),
  );
  const frame: SlotFrame = { layout, dataFree: data.dataFree };
  for (const output of data.outputs) writeOutput(out, frame, output);
  out.bytes(data.ephU, 32, "ephU").bytes(data.sealed, 32, "sealed");
  for (const field of data.disclosure) out.bytes(field, 32, "disclosure");
  out.bytes(data.privateTxHash, 32, "privateTxHash");
  if (data.anonymous !== undefined) {
    out
      .bytes(data.anonymous.commitment, 32, "anonymous.commitment")
      .bytes(data.anonymous.commitmentPok, 32, "anonymous.commitmentPok");
    if (data.anonymous.defaultOwnerTag !== undefined)
      out.bytes(data.anonymous.defaultOwnerTag, 32, "anonymous.defaultOwnerTag");
  }
  out.bytes(data.sppProof, PLAIN_GROTH16_PROOF_LENGTH, "sppProof");
  for (const nullifier of data.nullifiers) out.bytes(nullifier, 32, "nullifier");
  if (data.inputTrees.kind === "one") {
    writeTreeContext(out, data.inputTrees.context);
  } else {
    const { secondInputs } = data.inputTrees;
    if (
      typeof secondInputs !== "bigint" ||
      secondInputs < 0n ||
      secondInputs >> BigInt(header.inputCount) !== 0n
    )
      throw invalid("InvalidInstructionData");
    writeBitmap(
      out,
      data.nullifiers.map((_, input) => ((secondInputs >> BigInt(input)) & 1n) === 1n),
    );
    writeTreeContext(out, data.inputTrees.first);
    writeTreeContext(out, data.inputTrees.second);
  }
  return out.finish();
}

function writeOutput(out: Writer, frame: SlotFrame, output: RingOutput): void {
  out.bytes(output.hash, 32, "output.hash");
  switch (output.kind) {
    case "packed":
      out.bytes(output.u, 32, "output.u");
      writeBody(out, frame, output.ciphertext, DATA_FREE_PACKED_CIPHERTEXT_LEN);
      return;
    case "delivered":
      out.bytes(output.u, 32, "output.u").bytes(output.body, BODY_LEN, "output.body");
      return;
    case "anonymous":
      out.bytes(output.tag, TAG_LEN, "output.tag").bytes(output.body, BODY_LEN, "output.body");
      return;
    case "exit":
      out.bytes(output.ownerTag, 32, "output.ownerTag");
      writeBody(out, frame, output.payload, CONFIDENTIAL_DATA_FREE_BODY_LEN);
      return;
  }
}

function writeBody(out: Writer, frame: SlotFrame, body: Uint8Array, dataFreeLength: number): void {
  if (frame.dataFree) {
    if (body.length !== dataFreeLength) throw invalid("DataFreeBodyLength");
    out.bytes(body);
    return;
  }
  if (body.length > 0xffff) throw invalid("RingTransactLength");
  out.u16(body.length, "length").bytes(body);
}

function writeBitmap(out: Writer, bits: readonly boolean[]): void {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((set, index) => {
    if (set) bytes[index >> 3] = (bytes[index >> 3] ?? 0) | (1 << (index & 7));
  });
  out.bytes(bytes);
}

/** Whether the slot uses the output encoding `layout` gives ring outputs. */
function fits(output: RingOutput, layout: DisclosureLayout): boolean {
  return output.kind === "exit" || output.kind === layout.kind;
}

function compactFlags(data: RingTransactData): number {
  const bits: readonly (readonly [boolean, number])[] = [
    [data.policy !== undefined, Flag.policy],
    [data.policy?.curatorRootIndex !== undefined, Flag.curator],
    [data.approvalRequired, Flag.approvalRequired],
    [data.previousEpoch, Flag.previousEpoch],
    [data.anchor !== undefined, Flag.anchor],
    [data.inputTrees.kind === "two", Flag.secondTree],
    [data.dataHash !== undefined, Flag.dataHash],
    [data.ringDataHash !== undefined, Flag.ringDataHash],
  ];
  return bits.reduce((flags, [set, bit]) => (set ? flags | bit : flags), 0);
}

/** The curator and approval flags need a policy, the epoch and anchor flags an anonymous ring. */
function checkFlags(flags: number, rail: RingRail): void {
  const needsPolicy = has(flags, Flag.curator) || has(flags, Flag.approvalRequired);
  const needsAnonymous = has(flags, Flag.previousEpoch) || has(flags, Flag.anchor);
  if ((needsPolicy && !has(flags, Flag.policy)) || (needsAnonymous && rail !== "anonymous"))
    throw invalid("FlagNotAllowed");
}

function has(flags: number, bit: number): boolean {
  return (flags & bit) !== 0;
}

function readHeader(bytes: Reader, rail: RingRail): FrameHeader {
  const shapeByte = bytes.u8("shapeByte");
  const inputByte = bytes.u8("inputByte");
  const shape = SPP_SUPPORTED_SHAPES[shapeByte & FrameByte.low];
  if (shape === undefined) throw invalid("RingShapeUnkeyed");
  const flags: FrameFlags = {
    defaultOwnerTag: has(shapeByte, FrameByte.bit6),
    dataFree: has(shapeByte, FrameByte.bit7),
    keyEscrow: has(inputByte, FrameByte.bit6),
    fullOpenings: has(inputByte, FrameByte.bit7),
  };
  checkFrameFlags(flags, rail);
  return { nIn: shape.inputs, nOut: shape.outputs, inputCount: inputByte & FrameByte.low, flags };
}

function headerOf(data: RingTransactData): FrameHeader {
  const flags: FrameFlags = {
    defaultOwnerTag: data.anonymous?.defaultOwnerTag !== undefined,
    dataFree: data.dataFree,
    keyEscrow: data.keyEscrow,
    fullOpenings: data.fullOpenings,
  };
  checkFrameFlags(flags, data.rail);
  return { nIn: data.nIn, nOut: data.nOut, inputCount: data.nullifiers.length, flags };
}

function headerBytes(header: FrameHeader): readonly [number, number] {
  const index = SPP_SUPPORTED_SHAPES.findIndex(
    (shape) => shape.inputs === header.nIn && shape.outputs === header.nOut,
  );
  if (index < 0) throw invalid("RingShapeUnkeyed");
  if (header.inputCount > FrameByte.low) throw invalid("RingTransactLength");
  const { flags } = header;
  const bit = (set: boolean, value: number) => (set ? value : 0);
  return [
    index | bit(flags.defaultOwnerTag, FrameByte.bit6) | bit(flags.dataFree, FrameByte.bit7),
    header.inputCount |
      bit(flags.keyEscrow, FrameByte.bit6) |
      bit(flags.fullOpenings, FrameByte.bit7),
  ];
}

/** The anonymous rail alone takes a default owner tag and the entry key and never escrows, the delegate rail always escrows. */
function checkFrameFlags(flags: FrameFlags, rail: RingRail): void {
  const anonymousOnly = flags.defaultOwnerTag || flags.fullOpenings;
  const refused =
    rail === "anonymous"
      ? flags.keyEscrow
      : rail === "confidential"
        ? anonymousOnly
        : anonymousOnly || !flags.keyEscrow;
  if (refused) throw invalid("FlagNotAllowed");
}

/** The audit statement's layout element, Rust `FrameFlags::audit_layout`. */
function auditLayoutOf(flags: FrameFlags, exits: boolean): AuditLayout {
  return Object.freeze({
    exits,
    keyEscrow: flags.keyEscrow,
    dataFree: flags.dataFree,
    fullOpenings: flags.fullOpenings,
  });
}

function circuitId(
  rail: RingRail,
  inputs: number,
  outputs: number,
  anonymous: AnonymousProofData | undefined,
): CircuitId {
  const shape = { inputs, outputs, publicAssetSlots: N_PUBLIC_SLOTS };
  switch (rail) {
    case "confidential":
      return Object.freeze({ kind: "confidentialRingEddsa", ...shape });
    case "delegate":
      return Object.freeze({ kind: "ringAuthority", ...shape });
    case "anonymous":
      if (anonymous === undefined) throw invalid("RingTransactLength");
      return Object.freeze({
        kind: "anonymousRingEddsa",
        ...shape,
        proofData: Object.freeze({
          bsb22Commitment: Object.freeze({
            commitment: anonymous.commitment,
            commitmentPok: anonymous.commitmentPok,
          }),
          ...(anonymous.defaultOwnerTag === undefined
            ? {}
            : { defaultOwnerTag: anonymous.defaultOwnerTag }),
        }),
      });
  }
}

function transactIxData(
  data: RingTransactData,
  config: RingTransactConfig,
  proof: TransactInstructionData["proof"],
): TransactInstructionData {
  const auditor = config.auditorPubkey;
  if (!(auditor instanceof Uint8Array) || auditor.length !== 33)
    throw invalid("InvalidAuditorPubkey");
  return Object.freeze({
    expiryUnixTs: BigInt(data.expiryUnixTs),
    txViewingPk: taggedX25519(data.txViewingU),
    salt: data.salt,
    interfaceTransfers: data.interfaceTransfers,
    ...(data.dataHash === undefined ? {} : { dataHash: data.dataHash }),
    ...(data.ringDataHash === undefined ? {} : { ringDataHash: data.ringDataHash }),
    outputs: data.outputs.map(ringTransactOutput),
    messages: [
      Object.freeze({
        viewTag: auditor.slice(1) as Bytes32,
        data: concat([
          taggedX25519(data.ephU),
          checkedField(data.sealed, "sealed"),
          ...data.disclosure,
        ]),
      }),
    ],
    privateTxHash: data.privateTxHash,
    circuit: RingTransactData.circuit(data),
    proof,
    ...ringSppInputs(data),
  });
}

/** The SPP output, the owner tag and the scheme framing rebuilt from the slot, Rust `RingOutput::transact_output`. */
export function ringTransactOutput(output: RingOutput): TransactOutput {
  const [ownerTag, scheme, payload] = ((): readonly [Bytes32, EncryptedScheme, Uint8Array] => {
    switch (output.kind) {
      case "packed":
        return [
          output.u,
          EncryptedScheme.ringConfidentialPacked,
          concat([taggedX25519(output.u), output.ciphertext]),
        ];
      case "delivered":
        return [output.u, EncryptedScheme.ringConfidentialDelivered, checkedBody(output.body)];
      case "anonymous":
        return [ringTagField(output.tag), EncryptedScheme.ringAnonymous, checkedBody(output.body)];
      case "exit":
        return [output.ownerTag, EncryptedScheme.confidential, output.payload];
    }
  })();
  return Object.freeze({
    utxoHash: output.hash,
    ownerTag: Object.freeze({ kind: "inline", value: checkedField(ownerTag, "ownerTag") }),
    data: encodeOutputData(scheme, payload),
  });
}

function treeIndex(trees: InputTrees, input: number): number {
  return trees.kind === "one" ? 0 : Number((trees.secondInputs >> BigInt(input)) & 1n);
}

function field32(bytes: Reader, name: string): Bytes32 {
  return bytes.bytes(32, name) as Bytes32;
}

function checkedField(value: Uint8Array, name: string): Bytes32 {
  if (!(value instanceof Uint8Array) || value.length !== 32)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "InvalidInstructionData", name },
    });
  return value as Bytes32;
}

function checkedBody(body: Uint8Array): Uint8Array {
  if (!(body instanceof Uint8Array) || body.length !== BODY_LEN)
    throw invalid("RingTransactLength");
  return body;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** An interface codec failure inside `run` reads as `reason`. */
function within<T>(reason: string, run: () => T): T {
  try {
    return run();
  } catch (error) {
    throw shortRead(error, reason);
  }
}

/** A short read or a codec refusal is the program's `reason`, a ring refusal passes through. */
function shortRead(error: unknown, reason: string): unknown {
  return error instanceof InterfaceError
    ? new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason }, cause: error })
    : error;
}

/** `reason` names the `CustomRingError` the program raises. */
function invalid(reason: string): RingError {
  return new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason } });
}
