import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import keyedShapes from "../../../test-vectors/ring_keyed_shapes.json" with { type: "json" };
import policyRules from "../../../test-vectors/ring-policy-rules.json" with { type: "json" };
import records from "../../../test-vectors/ring-records.json" with { type: "json" };
import counts from "../../../test-vectors/ring-disclosure-counts.json" with { type: "json" };
import statements from "../../../test-vectors/ring-statements.json" with { type: "json" };
import expansion from "../../../test-vectors/ring-transact-expansion.json" with { type: "json" };
import { solanaOwnerIdentity } from "../src/hasher/index.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import {
  RING_AUTHORITY_MAX_INPUTS,
  RING_AUTHORITY_SHAPES,
  SPP_SUPPORTED_SHAPES,
  ringAuthorityShape,
} from "../src/interface/shape.js";
import { encodeBase58 } from "../src/interface/internal.js";
import type { Address, Bytes16, Bytes32, Bytes33, Bytes96 } from "../src/interface/types.js";
import { packDisclosure, unpackDisclosure } from "../src/keypair/audit.js";
import {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  anonymousAuditKey,
  anonymousKeyClass,
  disclosureFieldCount,
  packedFields,
  deliveredFields,
  anonymousFields,
  type AnonymousAuditKey,
  type AuditLayout,
} from "../src/interface/ring-disclosure-layout.js";
import { decodeDisclosure } from "../src/keypair/ring-disclosure.js";
import {
  APPLY_BATCH,
  QUAD_HEIGHT,
  type MemberRecord,
  type QuadPath,
  type QueueEntry,
  type RecordWriteProofInput,
} from "../src/interface/member-registry.js";
import {
  applyRecordsStatement,
  escrowEntry,
  queueChain,
  queueEntryHash,
  replayRecordWrites,
  verifyRecordOpening,
} from "../src/ring/member-registry.js";
import {
  admitTransfer,
  buildRuleTable,
  decodeRule,
  decodeRuleTable,
  policyTableFields,
  policyTableHash,
  type RecordLists,
  type RuleRefusal,
} from "../src/ring/policy.js";
import {
  applyRecordsStatementElements,
  applyRecordsStatementHash,
  auditStatementElements,
  auditStatementHash,
  policyStatementElements,
  policyStatementHash,
  registerKeyStatementElements,
  registerKeyStatementHash,
  type AuditKind,
} from "../src/ring/statement.js";
import { depositStatementElements, ringDepositContextHash } from "../src/ring/deposit-audit.js";
import { RingInstructionTag } from "../src/ring/admin.js";
import {
  RingTransactData,
  ringRail,
  ringRailOf,
  type RingOutput,
  type RingRail,
} from "../src/ring/transact.js";
import { TAG_LEN, ringTagField, ringTagFromOwnerTag } from "../src/keypair/ring-stream.js";
import { hashChain } from "../src/transaction/internal.js";

function bytes<T extends Uint8Array>(value: string, length?: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (length !== undefined && decoded.length !== length)
    throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function hexes(values: readonly Uint8Array[]): string[] {
  return values.map(hex);
}

function field(value: string): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

/** The last byte flipped, still below the modulus for every vector field. */
function flipped(value: Uint8Array): Bytes32 {
  const copy = Uint8Array.from(value);
  copy[31] = (copy[31] ?? 0) ^ 1;
  return field(hex(copy));
}

function railOf(name: string): RingRail {
  if (name !== "confidential" && name !== "anonymous" && name !== "delegate")
    throw new Error(`unknown rail ${name}`);
  return name;
}

function ringError(reason: string): unknown {
  return expect.objectContaining({ code: "RING_TRANSACT_DATA_INVALID", details: { reason } });
}

describe("ring-records.json", () => {
  type VectorPath = (typeof records.openings)[number]["path"];
  type VectorRecord = (typeof records.openings)[number]["record"];
  interface QueuedWrite {
    readonly kind: string;
    readonly signer: string | null;
    readonly member: string;
    readonly mask: number;
    readonly value: number;
    readonly nullifier_pk: string | null;
    readonly ciphertext: string | null;
    readonly escrow_key: string;
  }

  const path = (vector: VectorPath): QuadPath => ({
    index: vector.index,
    siblings: vector.siblings.map((level) => level.map(field)),
  });
  const record = (vector: VectorRecord): MemberRecord => ({
    member: field(vector.member),
    next: field(vector.next),
    lists: BigInt(vector.lists),
    escrowKey: field(vector.escrow_key),
  });
  const entry = (queued: QueuedWrite): QueueEntry => {
    if (queued.kind === "register_key") {
      const { signer, nullifier_pk: nullifierPk, ciphertext } = queued;
      if (signer === null || nullifierPk === null || ciphertext === null)
        throw new Error("register key write without its key");
      return escrowEntry(solanaOwnerIdentity(field(signer)) as Bytes32, {
        nullifierPk: field(nullifierPk),
        ciphertext: field(ciphertext),
      });
    }
    const member =
      queued.signer === null
        ? field(queued.member)
        : (solanaOwnerIdentity(field(queued.signer)) as Bytes32);
    return {
      member,
      mask: BigInt(queued.mask),
      value: BigInt(queued.value),
      escrowKey: field(queued.escrow_key),
    };
  };

  it("hashes every queued write and chains it from its position", () => {
    let chain = new Uint8Array(32) as Bytes32;
    for (const application of records.applications) {
      for (const queued of [...application.pending, ...application.authority_writes]) {
        const queuedEntry = entry(queued);
        expect(hex(queuedEntry.member)).toBe(queued.member);
        expect(hex(queuedEntry.escrowKey)).toBe(queued.escrow_key);
        expect(hex(queueEntryHash(queuedEntry))).toBe(queued.entry_hash);
        chain = queueChain(chain, queuedEntry);
        expect(hex(chain)).toBe(queued.chain);
      }
    }
  });

  it("replays every application to the root, next index and statement the apply proof binds", () => {
    for (const application of records.applications) {
      const writes: RecordWriteProofInput[] = application.writes.map((write) => ({
        entry: {
          member: field(write.member),
          mask: BigInt(write.mask),
          value: BigInt(write.value),
          escrowKey: field(write.escrow_key),
        },
        exists: write.exists,
        oldNext: field(write.old_next),
        oldLists: BigInt(write.old_lists),
        oldEscrow: field(write.old_escrow),
        slot: path(write.slot),
        low: record(write.low),
        lowPath: path(write.low_path),
      }));
      expect(writes.length).toBeLessThanOrEqual(APPLY_BATCH);
      const inputs = replayRecordWrites({
        oldRoot: field(application.old_root),
        oldNextIndex: application.old_next_index,
        chainStart: field(application.chain_start),
        writes,
      });
      expect(hex(inputs.newRoot)).toBe(application.new_root);
      expect(inputs.newNextIndex).toBe(application.new_next_index);
      expect(hex(inputs.chainEnd)).toBe(application.chain_end);
      const statement = applyRecordsStatement(inputs);
      expect(statement.count).toBe(BigInt(application.count));
      expect(hex(applyRecordsStatementHash(statement))).toBe(application.statement_hash);
    }
  });

  it("verifies a present member and an absent member's low record under the root", () => {
    for (const opening of records.openings) {
      const member = field(opening.member);
      const opened = verifyRecordOpening(
        opening.present
          ? { kind: "present", record: record(opening.record), path: path(opening.path) }
          : { kind: "absent", low: record(opening.record), path: path(opening.path) },
        field(opening.root),
        member,
      );
      expect(opened === undefined).toBe(!opening.present);
      expect(path(opening.path).siblings).toHaveLength(QUAD_HEIGHT);
    }
  });

  it("refuses an opening whose path folds to another root", () => {
    const opening = records.openings[0];
    if (opening === undefined) throw new Error("vector has no opening");
    const honest = path(opening.path);
    const siblings = honest.siblings.map((entries, level) =>
      entries.map((sibling, at) => (level === 3 && at === 1 ? flipped(sibling) : sibling)),
    );
    expect(() =>
      verifyRecordOpening(
        { kind: "present", record: record(opening.record), path: { ...honest, siblings } },
        field(opening.root),
        field(opening.member),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "RING_MEMBER_REGISTRY_INVALID",
        details: { reason: "RootMismatch" },
      }),
    );
  });

  it("refuses a write whose value leaves its mask before the first write", () => {
    const application = records.applications[0];
    const write = application?.writes[0];
    if (application === undefined || write === undefined) throw new Error("vector has no write");
    expect(() =>
      replayRecordWrites({
        oldRoot: field(application.old_root),
        oldNextIndex: application.old_next_index,
        chainStart: field(application.chain_start),
        writes: [
          {
            entry: {
              member: field(write.member),
              mask: BigInt(write.mask),
              value: BigInt(write.value) | (1n << 7n),
              escrowKey: field(write.escrow_key),
            },
            exists: write.exists,
            oldNext: field(write.old_next),
            oldLists: BigInt(write.old_lists),
            oldEscrow: field(write.old_escrow),
            slot: path(write.slot),
            low: record(write.low),
            lowPath: path(write.low_path),
          },
        ],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "RING_MEMBER_REGISTRY_INVALID",
        details: { reason: "ValueOutsideMask" },
      }),
    );
  });
});

describe("ring-policy-table.json", () => {
  interface PolicyCase {
    readonly name: string;
    readonly sources: readonly Readonly<{ listId: number; registry: Bytes32 }>[];
    readonly rules: readonly Bytes32[];
    readonly inlineAssets: readonly Bytes32[];
    readonly inlineLimits: readonly bigint[];
    readonly limits: readonly Readonly<{ asset: Bytes32; cap: bigint; cosignAbove: bigint }>[];
    readonly fields: readonly string[];
    readonly policyHash: string;
  }

  /** u64 limits exceed the doubles `JSON.parse` returns, the reviver reads their source text. */
  function policyCases(): readonly PolicyCase[] {
    const text = readFileSync(
      new URL("../../../test-vectors/ring-policy-table.json", import.meta.url),
      "utf8",
    );
    const parsed: unknown = JSON.parse(
      text,
      (_key, value: unknown, context?: { source?: string }) =>
        typeof value === "number" && context?.source !== undefined ? BigInt(context.source) : value,
    );
    const object = (value: unknown): Record<string, unknown> => {
      if (typeof value !== "object" || value === null) throw new Error("vector object");
      return value as Record<string, unknown>;
    };
    const list = (value: unknown): readonly unknown[] => {
      if (!Array.isArray(value)) throw new Error("vector array");
      return value;
    };
    const text32 = (value: unknown): string => {
      if (typeof value !== "string") throw new Error("vector string");
      return value;
    };
    const integer = (value: unknown): bigint => {
      if (typeof value !== "bigint") throw new Error("vector integer");
      return value;
    };
    return list(object(parsed)["cases"]).map((entry) => {
      const item = object(entry);
      return {
        name: text32(item["name"]),
        sources: list(item["sources"]).map((source) => ({
          listId: Number(integer(object(source)["list_id"])),
          registry: field(text32(object(source)["registry"])),
        })),
        rules: list(item["rules"]).map((row) => field(text32(row))),
        inlineAssets: list(item["inline_assets"]).map((asset) => field(text32(asset))),
        inlineLimits: list(item["inline_limits"]).map(integer),
        limits: list(item["limits"]).map((limit) => ({
          asset: field(text32(object(limit)["asset"])),
          cap: integer(object(limit)["cap"]),
          cosignAbove: integer(object(limit)["cosign_above"]),
        })),
        fields: list(item["fields"]).map(text32),
        policyHash: text32(item["policy_hash"]),
      };
    });
  }

  it("reproduces the 77 fields and the hash of every table", () => {
    const cases = policyCases();
    expect(cases.length).toBeGreaterThan(2);
    for (const vector of cases) {
      const table = buildRuleTable({
        rules: vector.rules.map(decodeRule),
        inlineAssets: vector.inlineAssets,
        inlineLimits: vector.inlineLimits,
        limits: vector.limits,
      });
      const fields = policyTableFields(table, vector.sources);
      expect(fields).toHaveLength(77);
      expect(hexes(fields), vector.name).toEqual(vector.fields);
      expect(hex(policyTableHash(table, vector.sources)), vector.name).toBe(vector.policyHash);
    }
  });
});

describe("ring-statements.json", () => {
  type AuditCase = (typeof statements.audit)[number];

  const output = (vector: AuditCase["outputs"][number]): RingOutput => {
    const hash = field(vector.hash);
    switch (vector.kind) {
      case "packed":
        return { kind: "packed", hash, u: field(vector.u ?? ""), ciphertext: new Uint8Array() };
      case "delivered":
        return {
          kind: "delivered",
          hash,
          u: field(vector.u ?? ""),
          body: bytes(vector.body ?? "", 40),
        };
      case "anonymous":
        return {
          kind: "anonymous",
          hash,
          tag: bytes<Bytes16>(vector.tag ?? "", 16),
          body: bytes(vector.body ?? "", 40),
        };
      default:
        return {
          kind: "exit",
          hash,
          ownerTag: new Uint8Array(32) as Bytes32,
          payload: new Uint8Array(),
        };
    }
  };
  /** `exits | key_escrow << 1 | data_free << 2 | full_openings << 3`. */
  const layout = (value: number): AuditLayout => ({
    exits: (value & 1) !== 0,
    keyEscrow: (value & 2) !== 0,
    dataFree: (value & 4) !== 0,
    fullOpenings: (value & 8) !== 0,
  });
  const kind = (vector: AuditCase): AuditKind =>
    vector.kind === "anonymous"
      ? {
          kind: "anonymous",
          privateTxHash: field(vector.private_tx_hash ?? ""),
          epoch: BigInt(vector.epoch ?? 0),
          firstContactRoot: field(vector.first_contact_root ?? ""),
          senderCommitment: field(vector.sender_commitment ?? ""),
        }
      : { kind: vector.kind === "packed" ? "packed" : "delivered" };

  it("rebuilds every audit statement and its public input", () => {
    for (const vector of statements.audit) {
      const statement = {
        head: {
          firstNullifier: field(vector.first_nullifier),
          ringId: field(vector.ring_id),
          txViewingU: field(vector.tx_viewing_u),
          auditorPubkey: bytes<Bytes33>(vector.auditor_pubkey, 33),
          ephU: field(vector.eph_u),
          sealed: field(vector.sealed),
          salt: bytes<Bytes16>(vector.salt, 16),
          layout: layout(vector.layout),
        },
        outputs: vector.outputs.map(output),
        disclosure: vector.disclosure.map(field),
        kind: kind(vector),
      };
      expect(hexes(auditStatementElements(statement)), vector.kind).toEqual(vector.elements);
      expect(hex(auditStatementHash(statement))).toBe(vector.public_input_hash);
    }
  });

  it("rebuilds the member and delegate policy statements", () => {
    for (const vector of statements.policy) {
      const statement = {
        key:
          vector.key === "member"
            ? { kind: "member" as const, anonymous: vector.anonymous === true }
            : { kind: "delegate" as const },
        privateTxHash: field(vector.private_tx_hash),
        policyHash: field(vector.policy_hash),
        ringId: field(vector.ring_id),
        approvalRequired: vector.approval_required,
        keyEscrow: vector.key_escrow,
        ownRoot: field(vector.own_root),
        curatorRoot: field(vector.curator_root),
        sender: field(vector.sender),
        publicAssets: vector.public_assets.map(field),
        publicAmounts: vector.public_amounts.map(field),
      };
      expect(hexes(policyStatementElements(statement))).toEqual(vector.elements);
      expect(hex(policyStatementHash(statement))).toBe(vector.public_input_hash);
    }
  });

  it("rebuilds the apply records and register key statements", () => {
    const apply = statements.apply_records;
    const applyStatement = {
      oldRoot: field(apply.old_root),
      newRoot: field(apply.new_root),
      oldNextIndex: apply.old_next_index,
      newNextIndex: apply.new_next_index,
      chainStart: field(apply.chain_start),
      chainEnd: field(apply.chain_end),
      count: BigInt(apply.count),
    };
    expect(hexes(applyRecordsStatementElements(applyStatement))).toEqual(apply.elements);
    expect(hex(applyRecordsStatementHash(applyStatement))).toBe(apply.public_input_hash);
    const register = statements.register_key;
    const registerStatement = {
      member: field(register.member),
      nullifierPk: field(register.nullifier_pk),
      auditorPubkey: bytes<Bytes33>(register.auditor_pubkey, 33),
      ephU: field(register.eph_u),
      ciphertext: field(register.ciphertext),
    };
    expect(hexes(registerKeyStatementElements(registerStatement))).toEqual(register.elements);
    expect(hex(registerKeyStatementHash(registerStatement))).toBe(register.public_input_hash);
  });

  it("rebuilds the deposit statement over the context of its SPP data", () => {
    const deposit = statements.deposit;
    const contextHash = ringDepositContextHash(
      encodeBase58(bytes(deposit.program_id, 32)) as Address,
      encodeBase58(bytes(deposit.tree, 32)) as Address,
      bytes(deposit.spp_data),
    );
    expect(hex(contextHash)).toBe(deposit.context_hash);
    const elements = depositStatementElements({
      contextHash,
      anonymous: deposit.anonymous,
      ownerUtxoHashes: deposit.owner_utxo_hashes.map(field),
      ciphertexts: deposit.ciphertexts.map((value) => bytes<Bytes96>(value, 96)),
      auditorPk: bytes<Bytes33>(deposit.auditor_pubkey, 33),
      ephPk: bytes<Bytes33>(deposit.eph_pk, 33),
      memberRegistryRoot: field(deposit.member_registry_root),
    });
    expect(hexes(elements)).toEqual(deposit.elements);
    expect(hex(hashChain(elements))).toBe(deposit.public_input_hash);
  });
});

describe("ring-transact-expansion.json", () => {
  const config = {
    auditorPubkey: bytes<Bytes33>(expansion.auditor_pubkey, 33),
    coSigner: field(expansion.co_signer),
  };

  it.each(expansion.cases)("$name expands to the SPP data and hash Rust forwards", (vector) => {
    const compact = bytes(vector.compact);
    const data = RingTransactData.parse(compact, railOf(vector.rail));
    expect(hex(RingTransactData.encode(data))).toBe(vector.compact);
    expect(hex(encodeTransactInstructionData(RingTransactData.expand(data, config)))).toBe(
      vector.transact_ix_data,
    );
    expect(hex(RingTransactData.sppInstructionData(data, config))).toBe(
      vector.spp_instruction_data,
    );
    const settlements = vector.settlements.map(([asset = "", user = ""]) => ({
      asset: encodeBase58(bytes(asset, 32)),
      user: encodeBase58(bytes(user, 32)),
    }));
    expect(hex(RingTransactData.externalDataHash(data, config, settlements))).toBe(
      vector.external_data_hash,
    );
  });

  it("refuses a trailing byte and a missing byte", () => {
    for (const vector of expansion.cases) {
      const compact = bytes(vector.compact);
      const rail = railOf(vector.rail);
      expect(() => RingTransactData.parse(Uint8Array.of(...compact, 0), rail)).toThrow(
        ringError("RingTransactLength"),
      );
      expect(() => RingTransactData.parse(compact.subarray(0, compact.length - 1), rail)).toThrow(
        ringError("RingTransactLength"),
      );
    }
  });

  it("refuses a frame byte the rail or the shape does not admit", () => {
    const named = (name: string) => {
      const vector = expansion.cases.find((entry) => entry.name === name);
      if (vector === undefined) throw new Error(`vector has no ${name} case`);
      return { compact: bytes(vector.compact), rail: railOf(vector.rail) };
    };
    const refused = (name: string, at: number, set: (byte: number) => number) => {
      const { compact, rail } = named(name);
      const changed = compact.slice();
      changed[at] = set(changed[at] ?? 0);
      return () => RingTransactData.parse(changed, rail);
    };
    expect(refused("confidential_delivered_audit_only", 2, () => 16)).toThrow(
      ringError("RingTransactLength"),
    );
    expect(refused("confidential_delivered_audit_only", 1, (byte) => byte | (1 << 6))).toThrow(
      ringError("FlagNotAllowed"),
    );
    expect(refused("confidential_delivered_audit_only", 1, () => 63)).toThrow(
      ringError("RingShapeUnkeyed"),
    );
    expect(refused("confidential_delivered_audit_only", 0, (byte) => byte | (1 << 4))).toThrow(
      ringError("FlagNotAllowed"),
    );
    const wide = SPP_SUPPORTED_SHAPES.findIndex(
      (shape) => shape.inputs > RING_AUTHORITY_MAX_INPUTS,
    );
    expect(refused("delegate_move", 1, () => wide)).toThrow(ringError("RingShapeUnkeyed"));
  });

  it("frames a data-free packed slot at its fixed length and refuses another", () => {
    const vector = expansion.cases.find((entry) => entry.name === "delegate_move");
    if (vector === undefined) throw new Error("vector has no delegate move");
    const data = RingTransactData.parse(bytes(vector.compact), railOf(vector.rail));
    expect(data.dataFree).toBe(true);
    const [first, ...rest] = data.outputs;
    if (first?.kind !== "packed") throw new Error("delegate move without a packed slot");
    expect(first.ciphertext).toHaveLength(49);
    const longer = { ...first, ciphertext: Uint8Array.of(...first.ciphertext, 0) };
    expect(() => RingTransactData.encode({ ...data, outputs: [longer, ...rest] })).toThrow(
      ringError("DataFreeBodyLength"),
    );
    // The data-free flag moves the packed slot fields, the sealed disclosure no longer fits.
    expect(() => RingTransactData.encode({ ...data, dataFree: false })).toThrow(
      ringError("RingTransactLength"),
    );
  });

  it("refuses an SPP point off the curve at expansion", () => {
    const vector = expansion.cases[0];
    if (vector === undefined) throw new Error("vector has no case");
    const data = RingTransactData.parse(bytes(vector.compact), railOf(vector.rail));
    const sppProof = data.sppProof.slice();
    sppProof.fill(0xff, 32, 96);
    sppProof[32] = 0x1f;
    expect(() => RingTransactData.expand({ ...data, sppProof }, config)).toThrow(
      ringError("InvalidSppProofPoint"),
    );
  });
});

describe("ring_keyed_shapes.json", () => {
  it("lists the delegate rail's shapes in cost order", () => {
    expect(RING_AUTHORITY_SHAPES.map((shape) => [shape.inputs, shape.outputs])).toEqual(
      keyedShapes.ring_authority,
    );
    expect(ringAuthorityShape(3, 9)).toEqual({ inputs: 4, outputs: 16 });
    expect(ringAuthorityShape(41, 2)).toBeUndefined();
  });

  it("keys the anonymous classes and exactly the anonymous shapes a commitment class serves", () => {
    expect(ANONYMOUS_AUDIT_CLASSES).toEqual(keyedShapes.anonymous_audit_classes);
    expect({ class: ANONYMOUS_ENTRY_CLASS, outputs: ANONYMOUS_ENTRY_OUTPUTS }).toEqual(
      keyedShapes.anonymous_entry,
    );
    expect(
      SPP_SUPPORTED_SHAPES.filter(
        (shape) =>
          anonymousAuditKey({
            inputs: shape.inputs,
            outputs: shape.outputs,
            spendsDefaultRing: false,
          }) !== undefined,
      ).map((shape) => [shape.inputs, shape.outputs]),
    ).toEqual(keyedShapes.anonymous_ring);
  });
});

describe("ring rails", () => {
  it("picks the rail of a ring instruction under the mode and the delegate like Rust `RingRail::new`", () => {
    const { transact, delegateTransact, merge } = RingInstructionTag;
    const delegate = encodeBase58(new Uint8Array(32).fill(7));
    expect(ringRail(transact, { mode: "off" })).toBe("confidential");
    expect(ringRail(transact, { mode: "anonymous" })).toBe("anonymous");
    expect(ringRail(delegateTransact, { mode: "registry", delegate })).toBe("delegate");
    expect(() => ringRail(delegateTransact, { mode: "anonymous", delegate })).toThrow(
      ringError("AnonymousRingRefused"),
    );
    expect(() => ringRail(delegateTransact, { mode: "off" })).toThrow(
      ringError("DelegateDisabled"),
    );
    expect(ringRailOf(delegateTransact, "off")).toBe("delegate");
    expect(() => ringRailOf(merge, "off")).toThrow(ringError("InvalidInstructionData"));
  });

  it("reads the tag of an owner tag only behind sixteen zero bytes like Rust `RingTag::from_owner_tag`", () => {
    const tag = new Uint8Array(TAG_LEN).fill(9) as Bytes16;
    const ownerTag = ringTagField(tag);
    expect(ringTagFromOwnerTag(ownerTag)).toEqual(tag);
    for (let index = 0; index < 32 - TAG_LEN; index++) {
      const marked = Uint8Array.from(ownerTag) as Bytes32;
      marked[index] = 1;
      expect(ringTagFromOwnerTag(marked)).toBeUndefined();
    }
  });
});

describe("disclosure packing", () => {
  it("left-aligns a short tail chunk and zero pads it", () => {
    const plaintext = Uint8Array.from({ length: 40 }, (_, index) => index + 1);
    const fields = packDisclosure(plaintext);
    expect(fields).toHaveLength(2);
    expect(hex(fields[0] ?? new Uint8Array())).toBe(`00${hex(plaintext.subarray(0, 31))}`);
    expect(hex(fields[1] ?? new Uint8Array())).toBe(
      `00${hex(plaintext.subarray(31))}${"00".repeat(22)}`,
    );
    expect(unpackDisclosure(fields, 40)).toEqual(plaintext);
    const padded = fields.map((entry, index) => (index === 1 ? flipped(entry) : entry));
    expect(() => unpackDisclosure(padded, 40)).toThrow("KEYPAIR_DISCLOSURE_PADDING");
  });

  it("counts the fields of every layout as the solved Go host disclosure the vector records", () => {
    const layouts = [
      ...counts.packed.map((record) => ({
        record,
        layout: {
          kind: "packed",
          outputs: record.outputs,
          exits: record.exits,
          keyEscrow: record.key_escrow,
          dataFree: record.data_free,
        } as const,
      })),
      ...counts.delivered.map((record) => ({
        record,
        layout: {
          kind: "delivered",
          outputs: record.outputs,
          exits: record.exits,
          keyEscrow: record.key_escrow,
        } as const,
      })),
      ...counts.anonymous.map((record) => {
        const key: AnonymousAuditKey =
          record.key === "entry" ? { kind: "entry" } : { kind: "commitment", class: record.class };
        expect(anonymousKeyClass(key)).toBe(record.class);
        return {
          record,
          layout: {
            kind: "anonymous",
            key,
            inputs: record.inputs,
            outputs: record.outputs,
            exits: record.exits,
          } as const,
        };
      }),
    ];
    for (const { record, layout } of layouts)
      expect(disclosureFieldCount(layout), JSON.stringify(record)).toBe(record.fields);
  });

  it("places every field the flags keep and skips every field they leave out", () => {
    expect(packedFields({ outputs: 2, exits: true, keyEscrow: false, dataFree: false })).toEqual({
      seedOut: 0,
      firstSlot: 1,
      slotWidth: 6,
      nullifierPk: 0,
      asset: 1,
      dataHashes: 2,
      ownerAndAmount: 4,
      fieldCount: 13,
    });
    expect(packedFields({ outputs: 2, exits: false, keyEscrow: true, dataFree: true })).toEqual({
      seedOut: undefined,
      firstSlot: 0,
      slotWidth: 3,
      nullifierPk: undefined,
      asset: 0,
      dataHashes: undefined,
      ownerAndAmount: 1,
      fieldCount: 6,
    });
    const dense = deliveredFields({ outputs: 8, exits: false, keyEscrow: false });
    expect([dense.seedOut, dense.nullifierPks, dense.slots, dense.slotBytes]).toEqual([
      undefined,
      { start: 0, end: 8 },
      { start: 8, end: 17 },
      32,
    ]);
    const entry = anonymousFields({ key: { kind: "entry" }, inputs: 3, outputs: 2, exits: true });
    expect([entry.seedOut, entry.nullifierPks, entry.slots, entry.slotBytes]).toEqual([
      0,
      { start: 2, end: 4 },
      { start: 4, end: 10 },
      160,
    ]);
    expect(entry.inputs).toEqual({
      kind: "openings",
      senderNullifierPk: 1,
      amounts: { start: 10, end: 13 },
      openings: { start: 13, end: 19 },
    });
    const commitment = anonymousFields({
      key: { kind: "commitment", class: 4 },
      inputs: 3,
      outputs: 2,
      exits: true,
    });
    expect([commitment.nullifierPks, commitment.slots, commitment.slotBytes]).toEqual([
      { start: 1, end: 3 },
      { start: 3, end: 8 },
      128,
    ]);
    expect(commitment.inputs).toEqual({
      kind: "commitments",
      first: 8,
      prefixPairs: { start: 9, end: 10 },
    });
  });

  it("refuses a layout no audit key serves", () => {
    const decode = (layout: Parameters<typeof decodeDisclosure>[0]["layout"]) => () =>
      decodeDisclosure(
        { layout, exits: Array.from({ length: layout.outputs }, () => false) },
        Array.from({ length: disclosureFieldCount(layout) }, () => new Uint8Array(32) as Bytes32),
      );
    const commitment = (inputClass: number, inputs: number, outputs: number) =>
      decode({
        kind: "anonymous",
        key: { kind: "commitment", class: inputClass },
        inputs,
        outputs,
        exits: false,
      });
    expect(commitment(24, 2, 8)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(commitment(28, 2, 2)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(commitment(4, 5, 2)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(commitment(1, 2, 16)).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(
      decode({ kind: "anonymous", key: { kind: "entry" }, inputs: 9, outputs: 2, exits: false }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(
      decode({ kind: "anonymous", key: { kind: "entry" }, inputs: 2, outputs: 16, exits: false }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
    expect(
      decode({ kind: "packed", outputs: 5, exits: false, keyEscrow: false, dataFree: false }),
    ).toThrow("KEYPAIR_DISCLOSURE_SHAPE");
  });
});

describe("ring-policy-rules.json", () => {
  type Case = (typeof policyRules.cases)[number];

  /** The refusal the vector names, `pass` none. */
  function outcome(expected: Case["outcome"]): RuleRefusal | undefined {
    const rule = expected.rule ?? -1;
    const output = expected.output ?? -1;
    switch (expected.kind) {
      case "pass":
        return undefined;
      case "lists":
        return {
          kind: "lists",
          rule,
          subject:
            expected.subject === "sender"
              ? { kind: "sender" }
              : { kind: expected.subject === "owner" ? "owner" : "asset", output },
        };
      case "no_asset_limit":
        return { kind: "noAssetLimit", rule, output };
      default:
        return { kind: "mixedAssets", rule, output };
    }
  }

  it.each(policyRules.cases.map((vector) => [vector.name, vector] as const))(
    "%s",
    (_name, vector) => {
      const table = decodeRuleTable({
        rules: vector.rules.map((row) => field(row)),
        inlineAssets: vector.inline_assets.map((asset) => field(asset)),
        inlineLimits: vector.inline_limits.map(BigInt),
        limits: [],
      });
      const lookup = (list: readonly { member: string; lists: number }[], member: string): bigint =>
        BigInt(list.find((record) => record.member === member)?.lists ?? 0);
      const lists = (member: string): RecordLists => ({
        own: lookup(vector.own_records, member),
        curator: lookup(vector.curator_records, member),
      });
      const refusal = admitTransfer(
        table,
        vector.sources.map((source) => ({
          listId: source.list_id,
          registry: field(source.registry),
        })),
        {
          sender: lists(vector.sender),
          outputs: vector.outputs.map((output) => ({
            owner: field(output.owner),
            asset: field(output.asset),
            amount: BigInt(output.amount),
            ownerLists: lists(output.owner),
            assetLists: lists(output.asset),
          })),
        },
      );
      expect(refusal).toEqual(outcome(vector.outcome));
    },
  );
});
