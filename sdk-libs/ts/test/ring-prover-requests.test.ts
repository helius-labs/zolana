import { readFileSync, readdirSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  ringProofCircuit,
  ringProofRequestBody,
  type AnonymousSlotProofInputs,
  type AuditEnvelopeProofInputs,
  type DeliveredSlotProofInputs,
  type FirstContactAnchor,
  type PolicyProofInputs,
  type PolicySubjectEntry,
  type RingProofRequest,
  type RingSlotOpening,
} from "../src/client/prover/ring.js";
import type { PresentRecordOpening } from "../src/client/prover/types.js";
import { solanaOwnerIdentity } from "../src/hasher/index.js";
import type {
  MemberRecord,
  QuadPath,
  RecordOpening,
  RecordWriteProofInput,
} from "../src/interface/member-registry.js";
import { UTXO_DOMAIN } from "../src/interface/program.js";
import {
  PROVING_KEY_SHA256S,
  RING_KEYS,
  ringCircuitType,
  ringProvingKey,
} from "../src/interface/proving-keys.js";
import type { Bytes16, Bytes31, Bytes32, Bytes33 } from "../src/interface/types.js";
import { auditSharedSecret, symmetricAuditApply } from "../src/keypair/audit.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { poseidon } from "../src/keypair/poseidon.js";
import type { AuditLayout } from "../src/interface/ring-disclosure-layout.js";
import {
  sealRingDisclosure,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
  type PackedOutputOpening,
} from "../src/keypair/ring-disclosure.js";
import {
  anonymousRingSecret,
  confidentialRingSecret,
  deliveredSlotSecret,
  inboxKey,
  inboxTag,
  packedSlotSecret,
  pairKey,
  pairTag,
  sealDeliveredBody,
  senderCommitment,
  tagIndex,
} from "../src/keypair/ring-stream.js";
import { ringOutputBlinding, transactOutputBlinding } from "../src/keypair/transact/index.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import {
  applyRecordsStatement,
  replayRecordWrites,
  verifyRecordOpening,
} from "../src/ring/member-registry.js";
import { buildRuleTable, decodeRule, policyTableHash } from "../src/ring/policy.js";
import { sealNullifierKeyWith } from "../src/ring/register-key.js";
import {
  applyRecordsStatementHash,
  auditStatementHash,
  policyStatementHash,
  registerKeyStatementHash,
  type AuditHead,
} from "../src/ring/statement.js";
import type { RingOutput } from "../src/ring/transact.js";
import { privateTxHash } from "../src/transaction/instructions/transact.js";

const GOLDENS = new URL("../../../prover/server/prover/custom_ring/testdata/", import.meta.url);
const ZERO = new Uint8Array(32) as Bytes32;

type Json = Readonly<Record<string, unknown>>;

function golden(circuitType: string): Json {
  return record(JSON.parse(readFileSync(new URL(`${circuitType}.json`, GOLDENS), "utf8")));
}

function record(value: unknown): Json {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("golden object");
  return value as Json;
}

function list(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error("golden list");
  return value;
}

function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("golden string");
  return value;
}

function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error("golden integer");
  return value;
}

function flag(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("golden boolean");
  return value;
}

function bytes<T extends Uint8Array>(value: unknown, length: number): T {
  const hex = text(value);
  if (!hex.startsWith("0x") || hex.length !== 2 + 2 * length) throw new Error("golden hex");
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex")) as T;
}

function field(value: unknown): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

function fields(value: unknown): readonly Bytes32[] {
  return list(value).map(field);
}

function hex(value: Uint8Array): string {
  return `0x${Buffer.from(value).toString("hex")}`;
}

function amountOf(value: Bytes32): bigint {
  return BigInt(hex(value));
}

function opening(value: unknown): RingSlotOpening {
  const item = record(value);
  return {
    domain: field(item["domain"]),
    treeId: field(item["treeId"]),
    ownerPkHash: field(item["ownerPkHash"]),
    nullifierPk: field(item["nullifierPk"]),
    asset: field(item["asset"]),
    amount: field(item["amount"]),
    blinding: field(item["blinding"]),
    dataHash: field(item["dataHash"]),
    ringDataHash: field(item["ringDataHash"]),
    ringProgramId: field(item["ringProgramId"]),
  };
}

function quadPath(index: unknown, flat: unknown): QuadPath {
  const siblings = fields(flat);
  return {
    index: count(index),
    siblings: Array.from({ length: siblings.length / 3 }, (_, level) =>
      siblings.slice(3 * level, 3 * level + 3),
    ),
  };
}

/** Go `RecordOpening` carries no member, the test names the subject it opens. */
function presentRecord(value: unknown, member: Bytes32): PresentRecordOpening {
  const item = record(value);
  return {
    kind: "present",
    record: {
      member,
      next: field(item["next"]),
      lists: BigInt(count(item["lists"])),
      escrowKey: field(item["escrowKey"]),
    },
    path: quadPath(item["index"], item["path"]),
  };
}

function memberOpening(value: unknown, member: Bytes32): RecordOpening | undefined {
  if (value === null) return undefined;
  const item = record(value);
  if (flag(item["present"])) return presentRecord(item, member);
  return {
    kind: "absent",
    low: {
      member: field(item["lowMember"]),
      next: field(item["lowNext"]),
      lists: BigInt(count(item["lowLists"])),
      escrowKey: field(item["lowEscrow"]),
    },
    path: quadPath(item["index"], item["path"]),
  };
}

function entry(value: unknown, member: Bytes32): PolicySubjectEntry {
  const item = record(value);
  return {
    own: memberOpening(item["own"], member),
    curator: memberOpening(item["curator"], member),
  };
}

/** `exits | key_escrow << 1 | data_free << 2 | full_openings << 3`. */
function layout(value: unknown): AuditLayout {
  const flags = count(value);
  return {
    exits: (flags & 1) !== 0,
    keyEscrow: (flags & 2) !== 0,
    dataFree: (flags & 4) !== 0,
    fullOpenings: (flags & 8) !== 0,
  };
}

function envelope(item: Json): AuditEnvelopeProofInputs {
  return {
    firstNullifier: field(item["firstNullifier"]),
    ringId: field(item["ringId"]),
    txViewingSk: bytes<Bytes32>(item["txViewingSk"], 32),
    ephSk: bytes<Bytes32>(item["ephSk"], 32),
    auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    salt: bytes<Bytes16>(item["salt"], 16),
    seedOut: field(item["seedOut"]),
    layout: layout(item["layout"]),
  };
}

function delivered(value: unknown): DeliveredSlotProofInputs {
  const item = record(value);
  return {
    output: opening(item["output"]),
    assetAddress: bytes<Bytes32>(item["assetAddress"], 32),
    recipientKey: bytes<Bytes32>(item["recipientKey"], 32),
    ownerKey: bytes<Bytes32>(item["ownerKey"], 32),
    body: bytes(item["body"], 40),
  };
}

function anonymousSlot(value: unknown): AnonymousSlotProofInputs {
  const item = record(value);
  const stream = record(item["stream"]);
  return {
    ...delivered(item),
    stream: {
      tag: field(stream["tag"]),
      inbox: flag(stream["inbox"]),
      pair: flag(stream["pair"]),
      self: flag(stream["self"]),
      index: count(stream["index"]),
    },
  };
}

function anchor(value: unknown): FirstContactAnchor {
  const item = record(value);
  return {
    treeId: field(item["treeId"]),
    asset: field(item["asset"]),
    amount: field(item["amount"]),
    slotSecret: field(item["slotSecret"]),
    firstNullifier: field(item["firstNullifier"]),
    slotIndex: count(item["slotIndex"]),
    epoch: BigInt(count(item["epoch"])),
    index: count(item["index"]),
    pathIndex: BigInt(count(item["pathIndex"])),
    path: fields(item["path"]),
  };
}

function policy(item: Json): PolicyProofInputs {
  const outputs = list(item["outputs"]).map((value) => {
    const output = record(value);
    return {
      ...opening(output),
      ...(output["ctHash"] === undefined ? {} : { ctHash: field(output["ctHash"]) }),
    };
  });
  const senderPkHash = field(item["senderPkHash"]);
  return {
    privateTxHash: field(item["privateTxHash"]),
    policyHash: field(item["policyHash"]),
    ringId: field(item["ringId"]),
    ownRoot: field(item["ownRoot"]),
    curatorRoot: field(item["curatorRoot"]),
    publicAssets: fields(item["publicAssets"]),
    publicAmounts: fields(item["publicAmounts"]),
    sources: list(item["sources"]).map((value) => {
      const source = record(value);
      return { listId: count(source["listId"]), registry: field(source["registry"]) };
    }),
    policyLen: count(item["policyLen"]),
    rules: fields(item["rules"]),
    inlineAssets: fields(item["inlineAssets"]),
    inlineLimits: fields(item["inlineLimits"]),
    inlineCount: count(item["inlineCount"]),
    limits: list(item["limits"]).map((value) => {
      const limit = record(value);
      return {
        asset: field(limit["asset"]),
        cap: field(limit["cap"]),
        cosignAbove: field(limit["cosignAbove"]),
      };
    }),
    limitCount: count(item["limitCount"]),
    addressChain: field(item["addressChain"]),
    privateTxBlinding: field(item["privateTxBlinding"]),
    outputs,
    senderPkHash,
    senderEntry: entry(item["senderEntry"], senderPkHash),
    ownerEntries: list(item["ownerEntries"]).map((value, i) =>
      entry(value, outputs[i]?.ownerPkHash ?? ZERO),
    ),
    assetEntries: list(item["assetEntries"]).map((value, i) =>
      entry(value, outputs[i]?.asset ?? ZERO),
    ),
  };
}

function write(value: unknown): RecordWriteProofInput {
  const item = record(value);
  const queued = record(item["entry"]);
  return {
    entry: {
      member: field(queued["member"]),
      mask: BigInt(count(queued["mask"])),
      value: BigInt(count(queued["value"])),
      escrowKey: field(queued["escrowKey"]),
    },
    exists: flag(item["exists"]),
    oldNext: field(item["oldNext"]),
    oldLists: BigInt(count(item["oldLists"])),
    oldEscrow: field(item["oldEscrow"]),
    slot: quadPath(item["index"], item["path"]),
    low: {
      member: field(item["lowMember"]),
      next: field(item["lowNext"]),
      lists: BigInt(count(item["lowLists"])),
      escrowKey: field(item["lowEscrow"]),
    },
    lowPath: quadPath(item["lowIndex"], item["lowPath"]),
  };
}

/** The typed request a golden file holds, built field by field. */
function request(item: Json): RingProofRequest {
  const circuitType = text(item["circuitType"]);
  const publicInputHash = field(item["publicInputHash"]);
  if (circuitType.startsWith("custom-ring-audit-packed-"))
    return {
      kind: "packedAudit",
      publicInputHash,
      ...envelope(item),
      nOut: count(item["nOut"]),
      outputs: list(item["outputs"]).map(opening),
      ownerKeys: list(item["ownerKeys"]).map((key) => bytes<Bytes32>(key, 32)),
    };
  if (circuitType.startsWith("custom-ring-audit-delivered-"))
    return {
      kind: "deliveredAudit",
      publicInputHash,
      ...envelope(item),
      outputs: list(item["outputs"]).map(delivered),
    };
  if (circuitType.startsWith("custom-ring-audit-anonymous-"))
    return {
      kind: "anonymousAudit",
      publicInputHash,
      ...envelope(item),
      outputs: list(item["outputs"]).map(anonymousSlot),
      privateTxHash: field(item["privateTxHash"]),
      privateTxBlinding: field(item["privateTxBlinding"]),
      senderKey: bytes<Bytes32>(item["senderKey"], 32),
      inputCount: count(item["inputCount"]),
      inputs: list(item["inputs"]).map(opening),
      senderCommitment: field(item["senderCommitment"]),
      epoch: BigInt(count(item["epoch"])),
      firstContactRoot: field(item["firstContactRoot"]),
      ...(item["anchor"] === undefined ? {} : { anchor: anchor(item["anchor"]) }),
    };
  if (circuitType.startsWith("custom-ring-policy-member-"))
    return {
      kind: "memberPolicy",
      publicInputHash,
      anonymous: flag(item["anonymous"]),
      approvalRequired: flag(item["approvalRequired"]),
      keyEscrow: flag(item["keyEscrow"]),
      sender: field(item["sender"]),
      inputChain: field(item["inputChain"]),
      ...policy(item),
    };
  if (circuitType.startsWith("custom-ring-policy-delegate-"))
    return {
      kind: "delegatePolicy",
      publicInputHash,
      inputs: list(item["inputs"]).map(opening),
      ...policy(item),
    };
  if (circuitType.startsWith("custom-ring-apply-records-"))
    return {
      kind: "applyRecords",
      publicInputHash,
      oldRoot: field(item["oldRoot"]),
      newRoot: field(item["newRoot"]),
      oldNextIndex: count(item["oldNextIndex"]),
      newNextIndex: count(item["newNextIndex"]),
      chainStart: field(item["chainStart"]),
      chainEnd: field(item["chainEnd"]),
      writes: list(item["writes"]).slice(0, count(item["count"])).map(write),
    };
  if (circuitType === "custom-ring-register-key")
    return {
      kind: "registerKey",
      publicInputHash,
      member: field(item["member"]),
      nullifierSecret: bytes<Bytes32>(item["nullifierSecret"], 32),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
    };
  if (circuitType === "custom-ring-deposit") {
    const ownerPkHashes = fields(item["ownerPkHashes"]);
    return {
      kind: "deposit",
      publicInputHash,
      contextHash: field(item["contextHash"]),
      count: count(item["count"]),
      anonymous: item["anonymous"] === undefined ? false : flag(item["anonymous"]),
      ownerPkHashes,
      ...(item["ownerKeys"] === undefined
        ? {}
        : { ownerKeys: list(item["ownerKeys"]).map((key) => bytes<Bytes32>(key, 32)) }),
      nullifierPks: fields(item["nullifierPks"]),
      blindingSecrets: fields(item["blindingSecrets"]),
      ctHashes: fields(item["ctHashes"]),
      members: list(item["members"]).map((member, i) =>
        member === null ? undefined : presentRecord(member, ownerPkHashes[i] ?? ZERO),
      ),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      keyEscrow: flag(item["keyEscrow"]),
      memberRegistryRoot: field(item["memberRegistryRoot"]),
    };
  }
  if (circuitType.startsWith("custom-ring-merge-anonymous-")) {
    const ownerKey = bytes<Bytes32>(item["ownerKey"], 32);
    return {
      kind: "anonymousMerge",
      publicInputHash,
      privateTxHash: field(item["privateTxHash"]),
      outputUtxoHash: field(item["outputUtxoHash"]),
      firstNullifier: field(item["firstNullifier"]),
      ringProgramId: field(item["ringProgramId"]),
      auditorPk: bytes<Bytes32>(item["auditorPk"], 32),
      salt: field(item["salt"]),
      ephSk: bytes<Bytes32>(item["ephSk"], 32),
      disclosureKey: bytes<Bytes32>(item["disclosureKey"], 32),
      ownerKey,
      nullifierSecret: field(item["nullifierSecret"]),
      mintChunks: fields(item["mintChunks"]),
      inputs: list(item["inputs"]).map((value) => {
        const input = record(value);
        return {
          domain: field(input["domain"]),
          treeId: field(input["treeId"]),
          amount: field(input["amount"]),
          blinding: field(input["blinding"]),
          ringDataHash: field(input["ringDataHash"]),
        };
      }),
      outputTreeId: field(item["outputTreeId"]),
      outputRingDataHash: field(item["outputRingDataHash"]),
    };
  }
  throw new Error(`no request for ${circuitType}`);
}

function tagged(u: Uint8Array): Bytes33 {
  return Uint8Array.from([4, ...u]) as Bytes33;
}

function publicKeyOf(secret: Uint8Array): X25519PublicKey {
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.publicKey();
  } finally {
    keypair.destroy();
  }
}

function agreement(secret: Uint8Array, peer: X25519PublicKey): Bytes32 {
  const keypair = X25519Keypair.fromBytes(secret);
  try {
    return keypair.ecdh(peer);
  } finally {
    keypair.destroy();
  }
}

/** The envelope the circuit seals, rebuilt from the request's secrets. */
function auditHead(envelope: AuditEnvelopeProofInputs): AuditHead {
  const auditor = X25519PublicKey.fromBytes(tagged(envelope.auditorPk));
  const eph = publicKeyOf(envelope.ephSk);
  const shared = auditSharedSecret(agreement(envelope.ephSk, auditor), eph, auditor);
  return {
    firstNullifier: envelope.firstNullifier,
    ringId: envelope.ringId,
    txViewingU: publicKeyOf(envelope.txViewingSk).u(),
    auditorPubkey: tagged(envelope.auditorPk),
    ephU: eph.u(),
    sealed: symmetricAuditApply(shared, envelope.txViewingSk) as Bytes32,
    salt: envelope.salt,
    layout: envelope.layout,
  };
}

/** Go `UtxoHashCircuit`, a dummy's owner is zero. */
function openingHash(slot: RingSlotOpening): Bytes32 {
  const owner = isUtxo(slot) ? poseidon([slot.ownerPkHash, slot.nullifierPk]) : ZERO;
  return poseidon([
    slot.domain,
    slot.treeId,
    slot.asset,
    slot.amount,
    slot.dataHash,
    poseidon([slot.ringDataHash, slot.ringProgramId]),
    poseidon([owner, slot.blinding]),
  ]) as Bytes32;
}

function isUtxo(slot: RingSlotOpening): boolean {
  return amountOf(slot.domain) === BigInt(UTXO_DOMAIN);
}

function isRingOutput(slot: RingSlotOpening): boolean {
  return isUtxo(slot) && amountOf(slot.ringProgramId) !== 0n;
}

/** The published tag, the circuit reads `low248` so the top byte is zero. */
function tagOf(tag: Bytes32): Bytes31 {
  expect(tag[0]).toBe(0);
  return tag.slice(1) as Bytes31;
}

function exitOutput(hash: Bytes32): RingOutput {
  return { kind: "exit", hash, ownerTag: ZERO, payload: new Uint8Array(0) };
}

/** Go `MerkleRootGadget`, bit `i` of the index puts the node right of its sibling. */
function stateRoot(leaf: Bytes32, index: bigint, path: readonly Bytes32[]): Bytes32 {
  return path.reduce<Bytes32>(
    (node, sibling, level) =>
      (((index >> BigInt(level)) & 1n) === 0n
        ? poseidon([node, sibling])
        : poseidon([sibling, node])) as Bytes32,
    leaf,
  );
}

const CIRCUIT_TYPES = readdirSync(GOLDENS)
  .filter((name) => name.endsWith(".json"))
  .map((name) => name.slice(0, -".json".length))
  .sort();

describe("ring prover request encoding against the Go goldens", () => {
  it("lists every ring key of ring_keys.rs and names one for each golden", () => {
    const rust = readFileSync(
      new URL("../../../custom-rings/interface/src/ring_keys.rs", import.meta.url),
      "utf8",
    );
    const names = [...rust.matchAll(/name: "([a-z0-9-]+)"/gu)].map((match) => match[1]);
    expect(RING_KEYS.map((key) => key.name)).toEqual(names);
    for (const circuitType of CIRCUIT_TYPES) expect(names).toContain(circuitType);
    for (const key of RING_KEYS) expect(ringCircuitType(key.circuit)).toBe(key.name);
  });

  it.each(CIRCUIT_TYPES)("encodes %s byte for byte", (circuitType) => {
    const item = golden(circuitType);
    const typed = request(item);
    const body = ringProofRequestBody(typed);
    expect(body).toEqual(item);
    expect(JSON.stringify(body)).toBe(JSON.stringify(item));
    expect(ringCircuitType(ringProofCircuit(typed))).toBe(circuitType);
  });

  it("names the deposit key the prover loads and refuses a shape no ring key serves", () => {
    expect(ringProvingKey({ family: "deposit" })).toEqual({
      name: "custom_ring_deposit.key",
      sha256: PROVING_KEY_SHA256S["custom_ring_deposit.key"],
    });
    expect(() => ringProvingKey({ family: "packedAudit", outputs: 3 })).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
  });

  it("refuses a request no key serves or the strict decoder would refuse", () => {
    const base = request(golden("custom-ring-audit-packed-2"));
    if (base.kind !== "packedAudit") throw new Error("packed golden");
    const [first] = base.outputs;
    if (first === undefined) throw new Error("packed golden output");
    expect(() =>
      ringProofRequestBody({
        ...base,
        outputs: [...base.outputs, first],
        ownerKeys: [...base.ownerKeys, ZERO],
      }),
    ).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_PROOF_INPUTS" }));
    expect(() => ringProofRequestBody({ ...base, nOut: 0 })).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_INTEGER",
        details: { field: "nOut", length: 1 },
      }),
    );
    const modulus = Uint8Array.from(
      Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex"),
    ) as Bytes32;
    expect(() => ringProofRequestBody({ ...base, seedOut: modulus })).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_FIELD", details: { field: "seedOut" } }),
    );
    expect(() => ringProofRequestBody({ ...base, ownerKeys: [ZERO] })).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_LENGTH" }),
    );
  });
});

describe("ring statements rebuilt from the Go goldens", () => {
  it("rebuilds the register key statement and its sealed key", () => {
    const typed = request(golden("custom-ring-register-key"));
    if (typed.kind !== "registerKey") throw new Error("register key golden");
    expect(typed.nullifierSecret[0]).toBe(0);
    const key = NullifierKey.fromSecret(typed.nullifierSecret.slice(1) as Bytes31);
    const ephemeral = X25519Keypair.fromBytes(typed.ephSk);
    try {
      const envelope = sealNullifierKeyWith(
        ephemeral,
        key,
        X25519PublicKey.fromBytes(tagged(typed.auditorPk)),
      );
      const statement = {
        member: typed.member,
        nullifierPk: envelope.nullifierPublicKey,
        auditorPubkey: tagged(typed.auditorPk),
        ephU: envelope.sealed.ephemeralPublicKey.u(),
        ciphertext: envelope.sealed.ciphertext,
      };
      expect(hex(registerKeyStatementHash(statement))).toBe(hex(typed.publicInputHash));
    } finally {
      ephemeral.destroy();
      key.destroy();
    }
  });

  it.each(["custom-ring-apply-records-1", "custom-ring-apply-records-16"])(
    "replays %s to the golden root, index, chain and statement",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "applyRecords") throw new Error("apply golden");
      const replayed = replayRecordWrites({
        oldRoot: typed.oldRoot,
        oldNextIndex: typed.oldNextIndex,
        chainStart: typed.chainStart,
        writes: typed.writes,
      });
      expect(hex(replayed.newRoot)).toBe(hex(typed.newRoot));
      expect(replayed.newNextIndex).toBe(typed.newNextIndex);
      expect(hex(replayed.chainEnd)).toBe(hex(typed.chainEnd));
      expect(hex(applyRecordsStatementHash(applyRecordsStatement(replayed)))).toBe(
        hex(typed.publicInputHash),
      );
    },
  );

  it.each(["custom-ring-audit-packed-2", "custom-ring-audit-packed-4"])(
    "rebuilds %s from tx_sk",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "packedAudit") throw new Error("packed golden");
      const key = { txViewingSecret: typed.txViewingSk, salt: typed.salt };
      const { exits, keyEscrow, dataFree } = typed.layout;
      const published = typed.outputs.slice(0, typed.nOut);
      const outputs = published.map((slot, i): PackedOutputOpening | undefined => {
        if (!isUtxo(slot)) return undefined;
        if (isRingOutput(slot)) {
          const secret = packedSlotSecret({
            ...key,
            outputIndex: i,
            firstNullifier: typed.firstNullifier,
          });
          const ringSecret = confidentialRingSecret(secret);
          expect(
            hex(
              ringOutputBlinding({
                firstNullifier: typed.firstNullifier,
                ringSecret,
                outputIndex: i,
              }),
            ),
          ).toBe(hex(slot.blinding));
        } else {
          expect(hex(transactOutputBlinding(typed.firstNullifier, typed.seedOut, i))).toBe(
            hex(slot.blinding),
          );
        }
        return {
          ownerKey: typed.ownerKeys[i] ?? ZERO,
          nullifierPk: keyEscrow ? undefined : slot.nullifierPk,
          asset: slot.asset,
          amount: amountOf(slot.amount),
          dataHash: slot.dataHash,
          ringDataHash: slot.ringDataHash,
        };
      });
      const disclosure = sealRingDisclosure(key, {
        kind: "packed",
        layout: { outputs: typed.nOut, exits, keyEscrow, dataFree },
        seedOut: exits ? typed.seedOut : undefined,
        outputs,
      });
      const hash = auditStatementHash({
        head: auditHead(typed),
        outputs: published.map((slot) => ({
          kind: "packed",
          hash: openingHash(slot),
          u: ZERO,
          ciphertext: new Uint8Array(0),
        })),
        disclosure,
        kind: { kind: "packed" },
      });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );

  it.each(["custom-ring-audit-delivered-8", "custom-ring-audit-delivered-16"])(
    "rebuilds %s from tx_sk and every recipient key",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "deliveredAudit") throw new Error("delivered golden");
      const key = { txViewingSecret: typed.txViewingSk, salt: typed.salt };
      const { exits, keyEscrow } = typed.layout;
      const outputs = typed.outputs.map((slot, i): DeliveredOutputOpening => {
        const opened = slot.output;
        if (!isUtxo(opened)) return { kind: "dummy" };
        const nullifierPk = keyEscrow ? undefined : opened.nullifierPk;
        if (!isRingOutput(opened)) {
          expect(hex(transactOutputBlinding(typed.firstNullifier, typed.seedOut, i))).toBe(
            hex(opened.blinding),
          );
          return {
            kind: "exit",
            nullifierPk,
            asset: opened.asset,
            amount: amountOf(opened.amount),
          };
        }
        const secret = slotSecret(typed, slot, i);
        expect(
          hex(
            sealDeliveredBody(secret, {
              assetAddress: slot.assetAddress,
              amount: amountOf(opened.amount),
            }),
          ),
        ).toBe(hex(slot.body));
        const ringSecret = confidentialRingSecret(secret);
        expect(
          hex(
            ringOutputBlinding({
              firstNullifier: typed.firstNullifier,
              ringSecret,
              outputIndex: i,
            }),
          ),
        ).toBe(hex(opened.blinding));
        return { kind: "ring", nullifierPk, ownerKey: slot.ownerKey };
      });
      const disclosure = sealRingDisclosure(key, {
        kind: "delivered",
        layout: { outputs: typed.outputs.length, exits, keyEscrow },
        seedOut: exits ? typed.seedOut : undefined,
        outputs,
      });
      const hash = auditStatementHash({
        head: auditHead(typed),
        outputs: typed.outputs.map((slot) =>
          isUtxo(slot.output) && !isRingOutput(slot.output)
            ? exitOutput(openingHash(slot.output))
            : {
                kind: "delivered",
                hash: openingHash(slot.output),
                u: slot.recipientKey,
                body: slot.body,
              },
        ),
        disclosure,
        kind: { kind: "delivered" },
      });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-audit-anonymous-")))(
    "rebuilds %s with its tags, its anchor and its spent inputs",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "anonymousAudit") throw new Error("anonymous golden");
      const key = { txViewingSecret: typed.txViewingSk, salt: typed.salt };
      const senderPkHash = solanaOwnerIdentity(typed.senderKey) as Bytes32;
      const outputs = typed.outputs.map((slot, i): AnonymousOutputOpening => {
        const opened = slot.output;
        if (!isUtxo(opened)) return { kind: "dummy" };
        if (!isRingOutput(opened)) {
          expect(hex(transactOutputBlinding(typed.firstNullifier, typed.seedOut, i))).toBe(
            hex(opened.blinding),
          );
          return {
            kind: "exit",
            nullifierPk: opened.nullifierPk,
            asset: opened.asset,
            amount: amountOf(opened.amount),
          };
        }
        const secret = slotSecret(typed, slot, i);
        const tag = tagOf(slot.stream.tag);
        expect(
          hex(
            sealDeliveredBody(secret, {
              assetAddress: slot.assetAddress,
              amount: amountOf(opened.amount),
            }),
          ),
        ).toBe(hex(slot.body));
        const ringSecret = anonymousRingSecret(secret, tag);
        expect(
          hex(
            ringOutputBlinding({
              firstNullifier: typed.firstNullifier,
              ringSecret,
              outputIndex: i,
            }),
          ),
        ).toBe(hex(opened.blinding));
        const index = tagIndex(slot.stream.index);
        if (slot.stream.inbox) {
          const inbox = inboxKey(
            typed.ringId,
            X25519PublicKey.fromBytes(tagged(slot.recipientKey)),
          );
          expect(hex(inboxTag(inbox, typed.epoch, index))).toBe(hex(tag));
        }
        if (slot.stream.pair) {
          if (typed.anchor === undefined) throw new Error("pair slot without an anchor");
          expect(hex(pairTag(pairKey(typed.anchor.slotSecret), typed.epoch, index))).toBe(hex(tag));
        }
        if (slot.stream.self) expect(hex(opened.ownerPkHash)).toBe(hex(senderPkHash));
        return {
          kind: "ring",
          nullifierPk: opened.nullifierPk,
          ownerKey: slot.ownerKey,
          recipientU: slot.recipientKey,
        };
      });
      const pair = typed.outputs.find((slot) => slot.stream.pair);
      if (pair !== undefined && typed.anchor !== undefined) {
        const firstAnchor = typed.anchor;
        const inbox = inboxKey(typed.ringId, X25519PublicKey.fromBytes(tagged(pair.recipientKey)));
        const firstTag = inboxTag(inbox, firstAnchor.epoch, tagIndex(firstAnchor.index));
        const firstContact = openingHash({
          domain: pair.output.domain,
          treeId: firstAnchor.treeId,
          ownerPkHash: pair.output.ownerPkHash,
          nullifierPk: pair.output.nullifierPk,
          asset: firstAnchor.asset,
          amount: firstAnchor.amount,
          blinding: ringOutputBlinding({
            firstNullifier: firstAnchor.firstNullifier,
            ringSecret: anonymousRingSecret(firstAnchor.slotSecret, firstTag),
            outputIndex: firstAnchor.slotIndex,
          }),
          dataHash: ZERO,
          ringDataHash: ZERO,
          ringProgramId: typed.ringId,
        });
        expect(hex(stateRoot(firstContact, firstAnchor.pathIndex, firstAnchor.path))).toBe(
          hex(typed.firstContactRoot),
        );
      }
      const spent = typed.inputs.slice(0, typed.inputCount);
      expect(
        hex(senderCommitment({ senderPkHash, privateTxBlinding: typed.privateTxBlinding })),
      ).toBe(hex(typed.senderCommitment));
      expect(
        hex(
          privateTxHash({
            inputHashes: typed.inputs.map((slot) => (isUtxo(slot) ? openingHash(slot) : ZERO)),
            outputHashes: typed.outputs.map((slot) =>
              isUtxo(slot.output) ? openingHash(slot.output) : ZERO,
            ),
            blinding: typed.privateTxBlinding,
          }),
        ),
      ).toBe(hex(typed.privateTxHash));
      const { exits, fullOpenings } = typed.layout;
      const [first] = spent;
      if (first === undefined) throw new Error("anonymous golden without an input");
      const disclosure = sealRingDisclosure(key, {
        kind: "anonymous",
        layout: {
          key: fullOpenings
            ? { kind: "entry" }
            : { kind: "commitment", class: typed.inputs.length },
          inputs: typed.inputCount,
          outputs: typed.outputs.length,
          exits,
        },
        seedOut: exits ? typed.seedOut : undefined,
        senderKey: typed.senderKey,
        outputs,
        inputs: fullOpenings
          ? {
              kind: "openings",
              senderNullifierPk: first.nullifierPk,
              inputs: spent.map((slot) =>
                isUtxo(slot)
                  ? { asset: slot.asset, amount: amountOf(slot.amount), blinding: slot.blinding }
                  : undefined,
              ),
            }
          : {
              kind: "commitments",
              hashes: spent.map((slot) => (isUtxo(slot) ? openingHash(slot) : undefined)),
            },
      });
      const hash = auditStatementHash({
        head: auditHead(typed),
        outputs: typed.outputs.map((slot) =>
          isUtxo(slot.output) && !isRingOutput(slot.output)
            ? exitOutput(openingHash(slot.output))
            : {
                kind: "anonymous",
                hash: openingHash(slot.output),
                tag: tagOf(slot.stream.tag),
                body: slot.body,
              },
        ),
        disclosure,
        kind: {
          kind: "anonymous",
          privateTxHash: typed.privateTxHash,
          epoch: typed.epoch,
          firstContactRoot: typed.firstContactRoot,
          senderCommitment: typed.senderCommitment,
        },
      });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );

  it.each(CIRCUIT_TYPES.filter((name) => name.startsWith("custom-ring-policy-")))(
    "rebuilds %s, its table hash and its own-registry openings",
    (circuitType) => {
      const typed = request(golden(circuitType));
      if (typed.kind !== "memberPolicy" && typed.kind !== "delegatePolicy")
        throw new Error("policy golden");
      const table = buildRuleTable({
        rules: typed.rules.slice(0, typed.policyLen).map(decodeRule),
        inlineAssets: typed.inlineAssets.slice(0, typed.inlineCount),
        inlineLimits: typed.inlineLimits.slice(0, typed.inlineCount).map(amountOf),
        limits: typed.limits.slice(0, typed.limitCount).map((limit) => ({
          asset: limit.asset,
          cap: amountOf(limit.cap),
          cosignAbove: amountOf(limit.cosignAbove),
        })),
      });
      expect(hex(policyTableHash(table, typed.sources))).toBe(hex(typed.policyHash));
      const own = (
        opening: RecordOpening | undefined,
        member: Bytes32,
      ): MemberRecord | undefined => {
        if (opening === undefined) throw new Error("own opening missing");
        return verifyRecordOpening(opening, typed.ownRoot, member);
      };
      own(typed.senderEntry.own, typed.senderPkHash);
      typed.outputs.forEach((output, i) => {
        if (!isUtxo(output)) return;
        const owner = own(typed.ownerEntries[i]?.own, output.ownerPkHash);
        own(typed.assetEntries[i]?.own, output.asset);
        if (output.ctHash !== undefined && owner !== undefined)
          expect(hex(owner.escrowKey)).toBe(hex(poseidon([output.nullifierPk, output.ctHash])));
      });
      const statement = {
        privateTxHash: typed.privateTxHash,
        policyHash: typed.policyHash,
        ringId: typed.ringId,
        ownRoot: typed.ownRoot,
        curatorRoot: typed.curatorRoot,
        publicAssets: typed.publicAssets,
        publicAmounts: typed.publicAmounts,
      };
      const hash =
        typed.kind === "memberPolicy"
          ? policyStatementHash({
              ...statement,
              key: { kind: "member", anonymous: typed.anonymous },
              approvalRequired: typed.approvalRequired,
              keyEscrow: typed.keyEscrow,
              sender: typed.sender,
            })
          : policyStatementHash({
              ...statement,
              key: { kind: "delegate" },
              approvalRequired: false,
              keyEscrow: true,
              sender: ZERO,
            });
      expect(hex(hash)).toBe(hex(typed.publicInputHash));
    },
  );
});

/** CRDS under `X25519(tx_sk, u)`, the secret the recipient rebuilds from its own key. */
function slotSecret(
  envelope: AuditEnvelopeProofInputs,
  slot: DeliveredSlotProofInputs,
  outputIndex: number,
): Bytes32 {
  const recipient = X25519PublicKey.fromBytes(tagged(slot.recipientKey));
  return deliveredSlotSecret({
    agreement: agreement(envelope.txViewingSk, recipient),
    txViewingKey: publicKeyOf(envelope.txViewingSk),
    recipientViewingKey: recipient,
    salt: envelope.salt,
    outputIndex,
    firstNullifier: envelope.firstNullifier,
  });
}
