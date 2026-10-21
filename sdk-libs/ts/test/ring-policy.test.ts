import { hashBytes } from "../src/hasher/index.js";
import { getAddressDecoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";

import { decodeRingMemberRegistry } from "../src/ring/codecs.js";
import {
  LIST_IDS,
  ListId,
  buildRuleTable,
  decodeRule,
  decodeRuleTable,
  encodeRule,
  encodeRuleTable,
  listSet,
  listWriter,
  memberOfAsset,
  memberOfTag,
  pinnedPolicy,
  policySourceOwners,
  policyTableHash,
  referencedLists,
  ruleAlternatives,
  type PolicySource,
  type Rule,
  type RuleGuard,
} from "../src/ring/policy.js";
import { RingError } from "../src/ring/error.js";
import { memberRegistryData } from "./helpers/ring-accounts.js";

await initializePoseidon();

const hex = (text: string): Bytes32 => Uint8Array.from(Buffer.from(text, "hex")) as Bytes32;
const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (bytes: Uint8Array): Address => getAddressDecoder().decode(bytes);

/** Rust `Row`. */
function row(
  input: Readonly<{
    subject: number;
    mode: number;
    mask: number;
    alternative?: number;
    guardTag?: number;
    threshold?: bigint;
    reserved?: number;
  }>,
): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[0] = input.reserved ?? 0;
  bytes[19] = input.alternative ?? 0;
  let threshold = input.threshold ?? 0n;
  for (let index = 27; index >= 20; index -= 1) {
    bytes[index] = Number(threshold & 0xffn);
    threshold >>= 8n;
  }
  bytes[28] = input.guardTag ?? 0;
  bytes[29] = input.mask;
  bytes[30] = input.mode;
  bytes[31] = input.subject;
  return bytes as Bytes32;
}

const bit = (id: ListId): number => 1 << (id - 1);
const OUTPUT_OWNER = 1;
const SENDER = 2;
const EXIT = 3;
const ASSET = 4;
const PRESENT = 1;
const ABSENT = 2;

function reason(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    if (error instanceof RingError) return String(error.details?.["reason"]);
    throw error;
  }
  throw new Error("expected a RingError");
}

describe("rule rows", () => {
  it("decodes require, forbid, any-of, asset lists and a threshold", () => {
    expect(
      decodeRule(row({ subject: OUTPUT_OWNER, mode: PRESENT, mask: bit(ListId.allow) })),
    ).toEqual({
      subject: "outputOwner",
      source: { kind: "lists", present: [ListId.allow], absent: [] },
      guard: { kind: "always" },
    });
    expect(decodeRule(row({ subject: SENDER, mode: ABSENT, mask: bit(ListId.frozen) }))).toEqual({
      subject: "sender",
      source: { kind: "lists", present: [], absent: [ListId.frozen] },
      guard: { kind: "always" },
    });
    expect(
      decodeRule(
        row({
          subject: OUTPUT_OWNER,
          mode: PRESENT,
          mask: bit(ListId.approval),
          alternative: bit(ListId.block),
        }),
      ),
    ).toEqual({
      subject: "outputOwner",
      source: { kind: "lists", present: [ListId.approval], absent: [ListId.block] },
      guard: { kind: "always" },
    });
    expect(decodeRule(row({ subject: ASSET, mode: PRESENT, mask: 1 }))).toEqual({
      subject: "asset",
      source: { kind: "lists", present: [ListId.allow], absent: [] },
      guard: { kind: "always" },
    });
    expect(
      decodeRule(
        row({
          subject: OUTPUT_OWNER,
          mode: PRESENT,
          mask: bit(ListId.approval),
          guardTag: 1,
          threshold: 2000n,
        }),
      ).guard,
    ).toEqual({ kind: "aboveAmount", amount: 2000n });
    expect(
      decodeRule(
        row({
          subject: OUTPUT_OWNER,
          mode: PRESENT,
          mask: bit(ListId.allow),
          guardTag: 2,
        }),
      ).guard,
    ).toEqual({ kind: "aboveAmountByAsset" });
  });

  it("orders a set in slot order", () => {
    expect(listSet(0b1000_0101)).toEqual([ListId.allow, ListId.frozen, ListId.escrow]);
    expect(LIST_IDS).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("refuses every row Rust refuses", () => {
    const allow = bit(ListId.allow);
    const cases: readonly [string, Parameters<typeof row>[0]][] = [
      ["ReservedBytes", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, reserved: 1 }],
      ["UnknownSubject", { subject: 5, mode: PRESENT, mask: allow }],
      ["UnknownSubject", { subject: 0, mode: PRESENT, mask: allow }],
      ["UnknownMode", { subject: OUTPUT_OWNER, mode: 3, mask: allow }],
      ["EmptyLists", { subject: ASSET, mode: PRESENT, mask: 0, alternative: allow }],
      ["EmptyLists", { subject: ASSET, mode: ABSENT, mask: 0 }],
      [
        "NonCanonicalAlternative",
        { subject: SENDER, mode: ABSENT, mask: allow, alternative: allow },
      ],
      [
        "ThresholdWithoutGuard",
        { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, threshold: 1n },
      ],
      ["UnknownGuardTag", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, guardTag: 3 }],
      ["ExitDestination", { subject: EXIT, mode: PRESENT, mask: allow }],
      ["ListInBothSets", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, alternative: allow }],
      ["EmptyLists", { subject: OUTPUT_OWNER, mode: PRESENT, mask: 0 }],
      ["SenderGuard", { subject: SENDER, mode: PRESENT, mask: allow, guardTag: 1, threshold: 5n }],
      ["ZeroThreshold", { subject: OUTPUT_OWNER, mode: PRESENT, mask: allow, guardTag: 1 }],
      ["PerAssetGuardNotOwner", { subject: ASSET, mode: PRESENT, mask: 1, guardTag: 2 }],
    ];
    for (const [expected, input] of cases) {
      expect(reason(() => decodeRule(row(input)))).toBe(expected);
    }
  });
});

describe("rule tables", () => {
  const requireAllow = row({ subject: OUTPUT_OWNER, mode: PRESENT, mask: bit(ListId.allow) });
  const inline = row({ subject: ASSET, mode: PRESENT, mask: 1 });
  const guardedOwner = row({
    subject: OUTPUT_OWNER,
    mode: PRESENT,
    mask: bit(ListId.approval),
    guardTag: 1,
    threshold: 2000n,
  });
  const perAsset = row({
    subject: OUTPUT_OWNER,
    mode: PRESENT,
    mask: bit(ListId.allow),
    guardTag: 2,
  });
  const mint = filled(0x14);

  it("decodes the Go fixture table and names its lists", () => {
    const table = decodeRuleTable({
      rules: [
        requireAllow,
        row({ subject: SENDER, mode: ABSENT, mask: bit(ListId.frozen) }),
        inline,
        guardedOwner,
      ],
      inlineAssets: [],
      inlineLimits: [],
      limits: [],
    });
    expect(table.rules).toHaveLength(4);
    expect(table.rules[3]?.guard).toEqual({ kind: "aboveAmount", amount: 2000n });
    expect(referencedLists(table.rules)).toEqual([ListId.allow, ListId.frozen, ListId.approval]);
    expect(
      decodeRuleTable({
        rules: [],
        inlineAssets: [],
        inlineLimits: [],
        limits: [],
      }).rules,
    ).toEqual([]);
    const limited = decodeRuleTable({
      rules: [perAsset],
      inlineAssets: [mint],
      inlineLimits: [2000n],
      limits: [],
    });
    expect(limited.rules[0]?.guard).toEqual({ kind: "aboveAmountByAsset" });
    expect(limited.inlineLimits).toEqual([2000n]);
  });

  it("refuses every table Rust refuses", () => {
    const sender = (id: ListId): Bytes32 => row({ subject: SENDER, mode: PRESENT, mask: bit(id) });
    const cases: readonly [
      string,
      {
        rules: readonly Bytes32[];
        inlineAssets: readonly Bytes32[];
        inlineLimits: readonly bigint[];
      },
    ][] = [
      [
        "TooManyRules",
        {
          rules: Array.from({ length: 17 }, () => requireAllow),
          inlineAssets: [],
          inlineLimits: [],
        },
      ],
      [
        "TooManyInlineAssets",
        {
          rules: [inline],
          inlineAssets: Array.from({ length: 9 }, () => mint),
          inlineLimits: Array.from({ length: 9 }, () => 0n),
        },
      ],
      ["ZeroInlineAsset", { rules: [inline], inlineAssets: [filled(0)], inlineLimits: [0n] }],
      [
        "DuplicateRule",
        { rules: [requireAllow, requireAllow], inlineAssets: [], inlineLimits: [] },
      ],
      [
        "EmptyLists",
        {
          rules: [row({ subject: ASSET, mode: PRESENT, mask: 0 })],
          inlineAssets: [],
          inlineLimits: [],
        },
      ],
      [
        "PoolWithoutInlineRule",
        { rules: [requireAllow], inlineAssets: [mint], inlineLimits: [0n] },
      ],
      [
        "PoolWithoutInlineRule",
        { rules: [guardedOwner], inlineAssets: [mint], inlineLimits: [0n] },
      ],
      ["MissingAssetLimit", { rules: [perAsset], inlineAssets: [], inlineLimits: [] }],
      ["MissingAssetLimit", { rules: [perAsset], inlineAssets: [mint], inlineLimits: [0n] }],
      [
        "DuplicateInlineAsset",
        { rules: [perAsset], inlineAssets: [mint, mint], inlineLimits: [1n, 2n] },
      ],
      ["PoolWithoutInlineRule", { rules: [inline], inlineAssets: [mint], inlineLimits: [1n] }],
      [
        "PoolWithoutInlineRule",
        { rules: [guardedOwner, inline], inlineAssets: [mint, mint], inlineLimits: [0n, 0n] },
      ],
      [
        "EmptyLists",
        {
          rules: [
            requireAllow,
            ...LIST_IDS.slice(1, 3).map(sender),
            row({ subject: ASSET, mode: PRESENT, mask: 0 }),
            row({ subject: OUTPUT_OWNER, mode: ABSENT, mask: bit(ListId.block) }),
          ],
          inlineAssets: [],
          inlineLimits: [],
        },
      ],
    ];
    for (const [expected, input] of cases) {
      expect(reason(() => decodeRuleTable({ ...input, limits: [] }))).toBe(expected);
    }
  });
});

/** `custom-rings/sdk/tests/go_policy_vectors.rs`. */
const RECORDS_PDA = addressOf(filled(0x11));
const CURATOR_PDA = addressOf(filled(0x12));
function rule(
  subject: Rule["subject"],
  present: readonly ListId[],
  absent: readonly ListId[],
  guard: RuleGuard = { kind: "always" },
): Rule {
  return { subject, source: { kind: "lists", present, absent }, guard };
}
const require = (subject: Rule["subject"], id: ListId): Rule => rule(subject, [id], []);
const forbid = (subject: Rule["subject"], id: ListId): Rule => rule(subject, [], [id]);
const above = (base: Rule, amount: bigint): Rule => ({
  ...base,
  guard: { kind: "aboveAmount", amount },
});
const ALLOW_ONLY_ASSETS: Rule = {
  subject: "asset",
  source: { kind: "lists", present: [ListId.allow], absent: [] },
  guard: { kind: "always" },
};

/** Rust `SourceMap::new`, the positional slots of the listed owners. */
function owners(entries: readonly (readonly [ListId, Bytes32])[]): readonly PolicySource[] {
  return LIST_IDS.map((listId) => {
    const found = entries.find(([id]) => id === listId);
    return found === undefined
      ? { listId: 0, registry: filled(0) }
      : { listId, registry: found[1] };
  });
}

const ASSET_MINT = addressOf(filled(0xd4));

describe("rule encoding", () => {
  it("packs the circuit byte positions", () => {
    const cases: readonly [Rule, Parameters<typeof row>[0]][] = [
      [require("outputOwner", ListId.allow), { subject: OUTPUT_OWNER, mode: PRESENT, mask: 0b01 }],
      [forbid("sender", ListId.frozen), { subject: SENDER, mode: ABSENT, mask: 0b100 }],
      [
        above(require("outputOwner", ListId.approval), 2000n),
        { subject: OUTPUT_OWNER, mode: PRESENT, mask: 0b0100_0000, guardTag: 1, threshold: 2000n },
      ],
      [ALLOW_ONLY_ASSETS, { subject: ASSET, mode: PRESENT, mask: 1 }],
      [
        rule("outputOwner", [ListId.allow], [ListId.block]),
        { subject: OUTPUT_OWNER, mode: PRESENT, mask: 0b01, alternative: 0b10 },
      ],
      [
        rule("outputOwner", [], [ListId.block, ListId.frozen]),
        { subject: OUTPUT_OWNER, mode: ABSENT, mask: 0b110 },
      ],
      [
        rule("sender", [ListId.frozen, ListId.allow], []),
        { subject: SENDER, mode: PRESENT, mask: 0b101 },
      ],
      [
        { ...require("outputOwner", ListId.allow), guard: { kind: "aboveAmountByAsset" } },
        { subject: OUTPUT_OWNER, mode: PRESENT, mask: 0b01, guardTag: 2 },
      ],
    ];
    for (const [input, expected] of cases) {
      expect(encodeRule(input)).toEqual(row(expected));
    }
    expect(reason(() => encodeRule(require("exitDestination", ListId.allow)))).toBe(
      "ExitDestination",
    );
    expect(reason(() => encodeRule(above(require("outputOwner", ListId.allow), 1n << 64n)))).toBe(
      "ThresholdRange",
    );
  });

  it("lists presences before absences in slot order", () => {
    expect(
      ruleAlternatives(
        rule("outputOwner", [ListId.frozen, ListId.allow], [ListId.escrow, ListId.block]),
      ),
    ).toEqual([
      { listId: ListId.allow, mode: "present" },
      { listId: ListId.frozen, mode: "present" },
      { listId: ListId.block, mode: "absent" },
      { listId: ListId.escrow, mode: "absent" },
    ]);
    expect(ruleAlternatives(forbid("sender", ListId.frozen))).toEqual([
      { listId: ListId.frozen, mode: "absent" },
    ]);
    expect(ruleAlternatives(ALLOW_ONLY_ASSETS)).toEqual([
      { listId: ListId.allow, mode: "present" },
    ]);
  });
});

describe("rule table builder", () => {
  const asset = filled(0x14);
  const pool = Array.from({ length: 8 }, (_, index) => filled(0x20 + index));
  const requireAllow = require("outputOwner", ListId.allow);

  it("refuses every table Rust refuses", () => {
    const cases: readonly [string, Parameters<typeof buildRuleTable>[0]][] = [
      ["TooManyRules", { rules: Array.from({ length: 17 }, () => requireAllow) }],
      ["TooManyInlineAssets", { rules: [ALLOW_ONLY_ASSETS], inlineAssets: [...pool, asset] }],
      ["ZeroInlineAsset", { rules: [ALLOW_ONLY_ASSETS], inlineAssets: [filled(0)] }],
      [
        "PoolWithoutInlineRule",
        { rules: [{ ...ALLOW_ONLY_ASSETS, subject: "sender" }], inlineAssets: [asset] },
      ],
      ["EmptyLists", { rules: [rule("asset", [], [])] }],
      ["PoolWithoutInlineRule", { rules: [requireAllow], inlineAssets: [asset] }],
      ["EmptyLists", { rules: [rule("sender", [], [])] }],
      [
        "ListInBothSets",
        { rules: [rule("outputOwner", [ListId.allow], [ListId.allow, ListId.block])] },
      ],
      ["SenderGuard", { rules: [above(forbid("sender", ListId.frozen), 10n)] }],
      ["ExitDestination", { rules: [require("exitDestination", ListId.allow)] }],
      ["ZeroThreshold", { rules: [above(require("outputOwner", ListId.approval), 0n)] }],
      ["DuplicateRule", { rules: [requireAllow, above(requireAllow, 10n)] }],
      [
        "PoolWithoutInlineRule",
        {
          rules: [ALLOW_ONLY_ASSETS, above(requireAllow, 7n)],
          inlineAssets: [asset, filled(4)],
        },
      ],
      ["AssetLimitWithoutGuard", { rules: [requireAllow], inlineLimits: [0n] }],
      [
        "MissingAssetLimit",
        {
          rules: [{ ...requireAllow, guard: { kind: "aboveAmountByAsset" } }],
          inlineAssets: [asset],
        },
      ],
      [
        "MissingAssetLimit",
        {
          rules: [{ ...requireAllow, guard: { kind: "aboveAmountByAsset" } }],
          inlineAssets: [asset],
          inlineLimits: [0n],
        },
      ],
      [
        "DuplicateInlineAsset",
        {
          rules: [{ ...requireAllow, guard: { kind: "aboveAmountByAsset" } }],
          inlineAssets: [asset, asset],
          inlineLimits: [1n, 1n],
        },
      ],
      ["LimitRange", { rules: [requireAllow], inlineLimits: [1n << 64n] }],
    ];
    for (const [expected, input] of cases) {
      expect(reason(() => buildRuleTable(input))).toBe(expected);
    }
  });

  it("shares member witnesses across rules without the retired ten-answer limit", () => {
    expect(
      buildRuleTable({
        rules: [
          require("outputOwner", ListId.allow),
          forbid("outputOwner", ListId.block),
          require("outputOwner", ListId.approval),
        ],
      }).rules,
    ).toHaveLength(3);
  });
  it("keeps declaration order and pads a limit per inline asset", () => {
    const table = buildRuleTable({
      rules: [requireAllow, forbid("sender", ListId.frozen), ALLOW_ONLY_ASSETS],
    });
    expect(table.rules.map((entry) => entry.subject)).toEqual(["outputOwner", "sender", "asset"]);
    expect(table.inlineLimits).toEqual([]);
    const encoded = encodeRuleTable(table);
    expect(encoded.rules).toHaveLength(3);
    expect(encoded.rules[2]).toEqual(row({ subject: ASSET, mode: PRESENT, mask: 1 }));
    expect(decodeRuleTable(encoded)).toEqual(table);
  });
});

/** `custom-rings/sdk/tests/go_policy_vectors.rs`. */
describe("policy hash", () => {
  const records = filled(0);
  const curator = hex(Buffer.from(hashBytes(filled(0x12))).toString("hex"));

  it("derives the inline asset member", () => {
    expect(memberOfAsset(ASSET_MINT)).toEqual(
      hex("14a6b5092f941bd4336fe2a25fc617a9515b457e027e0cf5e4867c0858855ec1"),
    );
  });

  it("refuses a repeated or unbounded outflow limit", () => {
    expect(() =>
      buildRuleTable({
        rules: [],
        limits: [
          { asset: memberOfAsset(ASSET_MINT), cap: 1n, cosignAbove: 0n },
          { asset: memberOfAsset(ASSET_MINT), cap: 2n, cosignAbove: 0n },
        ],
      }),
    ).toThrow(expect.objectContaining({ details: { reason: "DuplicateLimitAsset" } }));
    expect(() =>
      buildRuleTable({
        rules: [],
        limits: [{ asset: memberOfAsset(ASSET_MINT), cap: 0n, cosignAbove: 0n }],
      }),
    ).toThrow(expect.objectContaining({ details: { reason: "LimitWithoutBound" } }));
  });

  it("fails closed on a referenced list without a source", () => {
    const table = buildRuleTable({ rules: [forbid("sender", ListId.frozen)] });
    expect(() => policyTableHash(table, owners([[ListId.allow, records]]))).toThrow(
      expect.objectContaining({
        code: "RING_POLICY_SOURCE_INVALID",
        details: { reason: "MissingSource", listId: ListId.frozen },
      }),
    );
  });

  it("reads stored slots positionally and refuses a moved or zero owner", () => {
    const stored = LIST_IDS.map((listId) => ({
      listId: listId === ListId.frozen ? listId : 0,
      registry: listId === ListId.frozen ? CURATOR_PDA : addressOf(filled(0)),
    }));
    expect(policySourceOwners(stored)).toEqual(owners([[ListId.frozen, curator]]));
    const moved = stored.map(
      (slot, index) => (index === 0 ? stored[2] : index === 2 ? stored[0] : slot) ?? slot,
    );
    expect(() => policySourceOwners(moved)).toThrow(
      expect.objectContaining({
        code: "RING_POLICY_SOURCE_INVALID",
        details: { reason: "NotPositional", index: 0 },
      }),
    );
    expect(() => policySourceOwners(stored.slice(1))).toThrow(
      expect.objectContaining({ details: { reason: "SlotCount", slots: 7 } }),
    );
    expect(() =>
      policyTableHash(buildRuleTable({ rules: [] }), [
        { listId: 2, registry: filled(0) },
        ...owners([]).slice(1),
      ]),
    ).toThrow(expect.objectContaining({ details: { reason: "NotPositional", index: 0 } }));
  });

  it("pins the registry's table to its policy hash and refuses a tampered or unset one", () => {
    const table = buildRuleTable({
      rules: [{ ...require("outputOwner", ListId.allow), guard: { kind: "aboveAmountByAsset" } }],
      inlineAssets: [memberOfAsset(ASSET_MINT)],
      inlineLimits: [123n],
    });
    const sources = LIST_IDS.map((listId) =>
      listId === ListId.allow
        ? { listId, registry: RECORDS_PDA }
        : { listId: 0, registry: addressOf(filled(0)) },
    );
    const registry = (policyHash: Bytes32) =>
      decodeRingMemberRegistry(
        memberRegistryData({
          bump: 1,
          history: [],
          nextIndex: 1,
          policyHash,
          sources,
          table,
          generation: 2,
        }),
      );
    const hash = policyTableHash(table, policySourceOwners(sources));
    const pinned = pinnedPolicy(registry(hash));
    expect(pinned.table).toEqual(table);
    expect(pinned.policyHash).toEqual(hash);
    const tampered = new Uint8Array(hash) as Bytes32;
    tampered[31] = (tampered[31] ?? 0) ^ 1;
    expect(() => pinnedPolicy(registry(tampered))).toThrow(
      expect.objectContaining({ code: "RING_POLICY_HASH_MISMATCH" }),
    );
    expect(() => pinnedPolicy(registry(filled(0)))).toThrow(
      expect.objectContaining({ code: "RING_POLICY_NOT_SET", details: { generation: 2 } }),
    );
  });
});

describe("list authorization", () => {
  it("names the writer of every list", () => {
    expect(LIST_IDS.map(listWriter)).toEqual([
      "authority",
      "authority",
      "authority",
      "member",
      "member",
      "authority",
      "authority",
      "member",
    ]);
  });

  it("refuses a list id outside the table before a mask or a writer", () => {
    const unknown = 33 as ListId;
    const refused = expect.objectContaining({
      code: "RING_RULE_TABLE_INVALID",
      details: { reason: "UnknownList" },
    });
    const rule: Rule = {
      subject: "outputOwner",
      source: { kind: "lists", present: [unknown], absent: [] },
      guard: { kind: "always" },
    };
    expect(() => encodeRule(rule)).toThrow(refused);
    expect(() => ruleAlternatives(rule)).toThrow(refused);
    expect(() => buildRuleTable({ rules: [rule] })).toThrow(refused);
    expect(() => listWriter(unknown)).toThrow(refused);
  });
});

it("refuses a member tag of the wrong length", () => {
  expect(reason(() => memberOfTag(new Uint8Array(31)))).toBe("tagLength");
});
