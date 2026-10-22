import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { address, getBase58Decoder, type Address, type Signature } from "@solana/kit";

import { wireDecoder } from "../src/interface/decode.js";
import { X25519PublicKey } from "../src/keypair/x25519.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import {
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
} from "../src/interface/program.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  InterfaceTransfer,
} from "../src/interface/types.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import { Writer, addressBytes } from "../src/interface/internal.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import { RingError } from "../src/ring/error.js";
import {
  confirmedInstructionGroups,
  confirmedRingWithdrawals,
  ringInvokedIn,
  ringWithdrawalsOf,
  RpcTransactionOrigin,
  type OriginInstructionGroup,
} from "../src/ring/origin.js";
import { RingInstructionTag } from "../src/ring/admin.js";
import { RingTransactData } from "../src/ring/transact.js";
import { solanaRpcReads } from "./helpers/clients.js";
import { ringFrame, ringInstructionData } from "./helpers/ring-frame.js";

// Mirrors custom-rings/client/tests/origin.rs.
const RING = address("zYYvj4LTBF4Lz2FBhDaAbJ7CsVWvHjyanxQJPmN2dSU");
const OTHER = address("ComputeBudget111111111111111111111111111111");
const POOL = SHIELDED_POOL_PROGRAM_ID;
const PAYER = address("11111111111111111111111111111112");
const SIGNATURE = "5".repeat(87) as Signature;

function group(
  outer: Address,
  inner: readonly (readonly [Address, number])[],
): OriginInstructionGroup {
  const empty = { accounts: [], data: new Uint8Array() };
  return {
    outer: { programId: outer, stackHeight: 1, ...empty },
    inner: inner.map(([programId, stackHeight]) => ({
      programId,
      stackHeight,
      ...empty,
    })),
  };
}

function origin(reason: "missing stack height" | "no parent", groups: OriginInstructionGroup[]) {
  let error: unknown;
  try {
    ringInvokedIn(groups, RING);
  } catch (cause) {
    error = cause;
  }
  expect(error).toBeInstanceOf(RingError);
  expect((error as RingError).code).toBe("RING_ORIGIN_STACK");
  expect((error as RingError).details?.["reason"]).toBe(reason);
}

describe("ringInvokedIn", () => {
  it("attributes the pool directly under the ring", () => {
    expect(
      ringInvokedIn(
        [
          group(RING, [
            [POOL, 2],
            [OTHER, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(true);
  });

  it("does not attribute the pool at top level", () => {
    expect(ringInvokedIn([group(POOL, [[OTHER, 2]])], RING)).toBe(false);
  });

  it("does not attribute the pool under an intermediary", () => {
    expect(
      ringInvokedIn(
        [
          group(RING, [
            [OTHER, 2],
            [POOL, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(false);
  });

  it("follows the ring nested under another program", () => {
    expect(
      ringInvokedIn(
        [
          group(OTHER, [
            [RING, 2],
            [POOL, 3],
            [OTHER, 2],
            [POOL, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(true);
    expect(
      ringInvokedIn(
        [
          group(OTHER, [
            [RING, 2],
            [OTHER, 2],
            [POOL, 3],
          ]),
        ],
        RING,
      ),
    ).toBe(false);
  });

  it("rejects malformed stack heights", () => {
    origin("missing stack height", [
      {
        outer: {
          programId: RING,
          stackHeight: 1,
          accounts: [],
          data: new Uint8Array(),
        },
        inner: [{ programId: POOL, accounts: [], data: new Uint8Array() }],
      },
    ]);
    origin("no parent", [group(RING, [[POOL, 4]])]);
    origin("no parent", [group(RING, [[POOL, 1]])]);
  });
});

function confirmedTransaction(
  loadedAddresses: {
    writable: readonly Address[];
    readonly: readonly Address[];
  },
  lookup?: Readonly<{ writableIndexes: readonly number[]; readonlyIndexes: readonly number[] }>,
): unknown {
  return {
    slot: 7,
    blockTime: null,
    transaction: {
      signatures: [SIGNATURE],
      message: {
        header: {
          numRequiredSignatures: 1,
          numReadonlySignedAccounts: 0,
          numReadonlyUnsignedAccounts: 1,
        },
        // A lookup loads the trailing keys the instructions index.
        accountKeys: lookup === undefined ? [PAYER, RING, OTHER, POOL] : [PAYER, RING],
        recentBlockhash: PAYER,
        instructions: [{ programIdIndex: 1, accounts: [0], data: "", stackHeight: null }],
        ...(lookup === undefined
          ? {}
          : { addressTableLookups: [{ accountKey: OTHER, ...lookup }] }),
      },
    },
    meta: {
      err: null,
      status: { Ok: null },
      fee: 5000,
      preBalances: [1, 0],
      postBalances: [0, 0],
      innerInstructions: [
        {
          index: 0,
          instructions: [
            {
              programIdIndex: 3,
              accounts: [2],
              data: getBase58Decoder().decode(Uint8Array.of(InstructionTag.ringTransact)),
              stackHeight: 2,
            },
            {
              programIdIndex: 3,
              accounts: [2],
              data: getBase58Decoder().decode(Uint8Array.of(InstructionTag.emitEvent)),
              stackHeight: 3,
            },
          ],
        },
      ],
      loadedAddresses,
    },
    version: 1,
  };
}

describe("confirmedInstructionGroups", () => {
  it("indexes a lookup table's loaded addresses after the static keys", () => {
    const loaded = { writable: [OTHER], readonly: [POOL] };
    expect(
      confirmedInstructionGroups(
        confirmedTransaction(loaded, { writableIndexes: [3], readonlyIndexes: [9] }),
      ),
    ).toEqual(confirmedInstructionGroups(confirmedTransaction({ writable: [], readonly: [] })));
  });

  it("refuses loaded addresses that differ from the lookups the message names", () => {
    const loaded = { writable: [OTHER], readonly: [POOL] };
    for (const transaction of [
      confirmedTransaction(loaded),
      confirmedTransaction(
        { writable: [], readonly: [] },
        { writableIndexes: [3], readonlyIndexes: [9] },
      ),
      confirmedTransaction(loaded, { writableIndexes: [3, 4], readonlyIndexes: [9] }),
    ])
      expect(() => confirmedInstructionGroups(transaction)).toThrow(
        expect.objectContaining({ code: "RING_ORIGIN_DECODE" }),
      );
    const missing = confirmedTransaction(loaded, {
      writableIndexes: [3],
      readonlyIndexes: [9],
    }) as { meta: Record<string, unknown> };
    delete missing.meta["loadedAddresses"];
    expect(() => confirmedInstructionGroups(missing)).toThrow(
      expect.objectContaining({ code: "RING_ORIGIN_DECODE" }),
    );
  });

  it("reads program ids from the message account keys", () => {
    const groups = confirmedInstructionGroups(confirmedTransaction({ writable: [], readonly: [] }));
    expect(groups).toEqual([
      {
        outer: { programId: RING, accounts: [PAYER], data: new Uint8Array() },
        inner: [
          {
            programId: POOL,
            accounts: [OTHER],
            data: Uint8Array.of(InstructionTag.ringTransact),
            stackHeight: 2,
          },
          {
            programId: POOL,
            accounts: [OTHER],
            data: Uint8Array.of(InstructionTag.emitEvent),
            stackHeight: 3,
          },
        ],
      },
    ]);
    expect(ringInvokedIn(groups, RING)).toBe(true);
  });

  it("refuses a transaction without inner instructions", () => {
    const transaction = confirmedTransaction({
      writable: [],
      readonly: [],
    }) as {
      meta: Record<string, unknown>;
    };
    delete transaction.meta["innerInstructions"];
    expect(() => confirmedInstructionGroups(transaction)).toThrow(RingError);
  });

  it("refuses failed transactions even when they contain ring events", () => {
    const transaction = confirmedTransaction({
      writable: [],
      readonly: [],
    }) as {
      meta: Record<string, unknown>;
    };
    transaction.meta["err"] = { InstructionError: [0, 1] };
    expect(() => confirmedInstructionGroups(transaction)).toThrow(RingError);
  });
});

const RECIPIENT = address("So11111111111111111111111111111111111111112");
const DEPOSITOR = address("Vote111111111111111111111111111111111111111");
const MINT = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const SPL_INTERFACE = address("SysvarRent111111111111111111111111111111111");
const TOKEN_ACCOUNT = address("Stake11111111111111111111111111111111111111");
const TOKEN_PROGRAM = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const SETTLEMENT_KEYS: readonly Address[] = [
  PAYER,
  RING,
  OTHER,
  POOL,
  SOL_INTERFACE,
  RECIPIENT,
  DEPOSITOR,
  SHIELDED_POOL_CPI_AUTHORITY,
  MINT,
  SPL_INTERFACE,
  TOKEN_ACCOUNT,
  TOKEN_PROGRAM,
];

const keyIndex = (account: Address) => SETTLEMENT_KEYS.indexOf(account);
const zeros = (length: number) => new Uint8Array(length);

// Rust pins all payloads to TransactIxData::serialize in client/tests/origin.rs.
describe("cached ring settlement wire vectors", () => {
  const vectors = readFileSync(
    new URL("../../../test-vectors/cached_ring_settlement.hex", import.meta.url),
    "utf8",
  )
    .trim()
    .split("\n");
  for (const [index, hex] of vectors.entries()) {
    it(`decodes cached ring rail ${index} before the trailing cache`, () => {
      expect(hex).toMatch(/^(?:[0-9a-f]{2})+$/u);
      // Rails 1 and 3 are anonymous, SPP takes the ring's co-signer behind their data.
      const coSigner = index % 2 === 1 ? new Uint8Array(32).fill(13) : new Uint8Array();
      const data = Uint8Array.from([
        InstructionTag.ringTransact,
        ...Buffer.from(hex, "hex"),
        ...coSigner,
      ]);
      const instruction = {
        programId: POOL,
        accounts: [
          PAYER,
          SOL_INTERFACE,
          RECIPIENT,
          SHIELDED_POOL_CPI_AUTHORITY,
          MINT,
          SPL_INTERFACE,
          TOKEN_ACCOUNT,
          TOKEN_PROGRAM,
          OTHER,
          ...(index >= 2 ? [OTHER, OTHER] : []),
        ],
        data,
      };
      expect(ringWithdrawalsOf([instruction])).toEqual([
        { recipient: RECIPIENT, asset: SOL_MINT, amount: 7n },
        { recipient: TOKEN_ACCOUNT, asset: MINT, amount: 9n },
      ]);
      expect(() =>
        ringWithdrawalsOf([{ ...instruction, accounts: instruction.accounts.slice(0, 7) }]),
      ).toThrow(RingError);
      expect(() => ringWithdrawalsOf([{ ...instruction, data: data.slice(0, -1) }])).toThrow(
        RingError,
      );
      expect(() =>
        ringWithdrawalsOf([{ ...instruction, data: Uint8Array.from([...data, 0]) }]),
      ).toThrow(RingError);
    });
  }
});

/** A real `ring_transact` payload, so the tail is read against decoded transfers. */
function transactData(transfers: readonly InterfaceTransfer[]): string {
  const encoded = encodeTransactInstructionData({
    expiryUnixTs: 0n,
    privateTxHash: zeros(32) as Bytes32,
    circuit: { kind: "confidentialRingEddsa", inputs: 1, outputs: 2, publicAssetSlots: 1 },
    txViewingPk: zeros(33) as Bytes33,
    salt: zeros(16) as Bytes16,
    proof: {
      a: zeros(32) as Bytes32,
      b: zeros(128) as Bytes128,
      c: zeros(32) as Bytes32,
    },
    inputs: [{ nullifierHash: zeros(32) as Bytes32, treeIndex: 0 }],
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: transfers,
    outputs: [],
    messages: [],
  });
  return getBase58Decoder().decode(Uint8Array.from([InstructionTag.ringTransact, ...encoded]));
}

function poolInstruction(
  transfers: readonly InterfaceTransfer[],
  tail: readonly Address[],
  stackHeight = 2,
): unknown {
  return {
    programIdIndex: keyIndex(POOL),
    accounts: [keyIndex(PAYER), ...tail.map(keyIndex)],
    data: transactData(transfers),
    stackHeight,
  };
}

function callerInstruction(programId: Address, accounts: readonly Address[] = []): unknown {
  return {
    programIdIndex: keyIndex(programId),
    accounts: accounts.map(keyIndex),
    data: "",
  };
}

function settlementTransaction(outer: readonly unknown[], inner: readonly unknown[]): unknown {
  return {
    slot: 7,
    blockTime: null,
    transaction: {
      signatures: [SIGNATURE],
      message: {
        accountKeys: [...SETTLEMENT_KEYS],
        recentBlockhash: PAYER,
        instructions: outer,
        addressTableLookups: [],
      },
    },
    meta: {
      err: null,
      innerInstructions: inner.length === 0 ? [] : [{ index: 0, instructions: inner }],
    },
    version: 0,
  };
}

const SOL_LEG = { recipient: RECIPIENT, asset: SOL_MINT, amount: 7n };

describe("confirmedRingWithdrawals", () => {
  it("names the recipient of a SOL withdrawal", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [SOL_INTERFACE, RECIPIENT])],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([SOL_LEG]);
  });

  it("leaves a SOL deposit out", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [poolInstruction([{ kind: "solDeposit", amount: 7n }], [SOL_INTERFACE, DEPOSITOR])],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([]);
  });

  it("names the recipient when the same instruction also deposits", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [
        poolInstruction(
          [
            { kind: "solDeposit", amount: 3n },
            { kind: "solWithdrawal", amount: 7n },
          ],
          [SOL_INTERFACE, DEPOSITOR, SOL_INTERFACE, RECIPIENT],
        ),
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([SOL_LEG]);
  });

  it("follows the ring nested under another program", () => {
    const transaction = settlementTransaction(
      [callerInstruction(OTHER)],
      [
        {
          programIdIndex: keyIndex(RING),
          accounts: [],
          data: "",
          stackHeight: 2,
        },
        poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [SOL_INTERFACE, RECIPIENT], 3),
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([SOL_LEG]);
  });

  it("ignores an unrelated instruction that names the interface", () => {
    const transaction = settlementTransaction(
      [callerInstruction(OTHER, [SOL_INTERFACE, RECIPIENT])],
      [],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([]);
  });

  it("ignores a pool instruction another program invoked", () => {
    const transaction = settlementTransaction(
      [callerInstruction(OTHER)],
      [poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [SOL_INTERFACE, RECIPIENT])],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([]);
  });

  it("names the token account and the mint of an SPL withdrawal", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [
        poolInstruction(
          [{ kind: "splWithdrawal", amount: 9n, splInterfaceBump: 254 }],
          [SHIELDED_POOL_CPI_AUTHORITY, MINT, SPL_INTERFACE, TOKEN_ACCOUNT, TOKEN_PROGRAM],
        ),
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([
      { recipient: TOKEN_ACCOUNT, asset: MINT, amount: 9n },
    ]);
  });

  it("names the withdrawals of an anonymous ring transact", () => {
    // custom-rings/client/tests/origin.rs pins the same payload.
    const hex = readFileSync(
      new URL("../../../test-vectors/anonymous_ring_settlement.hex", import.meta.url),
      "utf8",
    ).trim();
    const tail = [
      SOL_INTERFACE,
      RECIPIENT,
      SHIELDED_POOL_CPI_AUTHORITY,
      MINT,
      SPL_INTERFACE,
      TOKEN_ACCOUNT,
      TOKEN_PROGRAM,
    ];
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [
        {
          programIdIndex: keyIndex(POOL),
          accounts: [keyIndex(PAYER), ...tail.map(keyIndex)],
          data: getBase58Decoder().decode(
            Uint8Array.from([
              InstructionTag.ringTransact,
              ...Buffer.from(hex, "hex"),
              ...new Uint8Array(32).fill(13),
            ]),
          ),
          stackHeight: 2,
        },
      ],
    );
    expect(confirmedRingWithdrawals(transaction, RING)).toEqual([
      SOL_LEG,
      { recipient: TOKEN_ACCOUNT, asset: MINT, amount: 9n },
    ]);
  });

  it("refuses a settlement tail that does not match its transfers", () => {
    const transaction = settlementTransaction(
      [callerInstruction(RING)],
      [poolInstruction([{ kind: "solWithdrawal", amount: 7n }], [RECIPIENT, SOL_INTERFACE])],
    );
    expect(() => confirmedRingWithdrawals(transaction, RING)).toThrow(RingError);
  });
});

function rpcWith(result: unknown | Error): ConstructorParameters<typeof RpcTransactionOrigin>[0] {
  const getTransaction = () => ({
    send: () => (result instanceof Error ? Promise.reject(result) : Promise.resolve(result)),
  });
  return solanaRpcReads({ getTransaction });
}

function transferFixture(
  saltByte = 1,
  tag: number = InstructionTag.ringTransact,
  rail: Readonly<{ anonymous?: boolean; tail?: Uint8Array; inputTree?: Address }> = {},
) {
  const key = X25519Keypair.generate();
  const txViewingPublicKey = key.publicKey();
  key.destroy();
  const field = (byte: number) => new Uint8Array(32).fill(byte) as Bytes32;
  const tree = treeAddress(4);
  const indexed: IndexedShieldedTransaction = {
    slot: 7n,
    txSignature: SIGNATURE,
    eventIndex: 0,
    proofless: false,
    ringProgramId: RING,
    txViewingPublicKey,
    salt: new Uint8Array(16).fill(saltByte) as Bytes16,
    nullifiers: [field(1), field(2)],
    messages: [
      { viewTag: field(3), data: Uint8Array.of(4) },
      { viewTag: field(5), data: Uint8Array.of(6) },
    ],
    outputSlots: [
      {
        viewTag: field(7),
        payload: Uint8Array.of(8),
        outputContext: { tree, treeId: 4, leafIndex: 100n, hash: field(9) },
      },
      {
        viewTag: addressBytes(PAYER) as Bytes32,
        payload: Uint8Array.of(10),
        outputContext: { tree, treeId: 4, leafIndex: 101n, hash: field(11) },
      },
    ],
  };
  const instruction = encodeTransactInstructionData({
    expiryUnixTs: 0n,
    privateTxHash: field(12),
    circuit:
      rail.anonymous === true
        ? {
            kind: "anonymousRingEddsa",
            inputs: 2,
            outputs: 2,
            publicAssetSlots: 0,
            proofData: { bsb22Commitment: { commitment: field(0), commitmentPok: field(0) } },
          }
        : {
            kind:
              tag === InstructionTag.ringAuthorityTransact
                ? "ringAuthority"
                : "confidentialRingEddsa",
            inputs: 2,
            outputs: 2,
            publicAssetSlots: 0,
          },
    txViewingPk: txViewingPublicKey.toBytes(),
    salt: indexed.salt!,
    proof: { a: field(0), b: new Uint8Array(128) as Bytes128, c: field(0) },
    inputs: indexed.nullifiers.map((nullifierHash) => ({
      nullifierHash,
      treeIndex: 0,
    })),
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: [],
    messages: indexed.messages,
    outputs: indexed.outputSlots.map((output, index) => ({
      utxoHash: output.outputContext.hash,
      ownerTag:
        index === 0 ? { kind: "inline", value: output.viewTag } : { kind: "account", index: 0 },
      data: output.payload,
    })),
  });
  const event = new Writer()
    .u8(InstructionTag.emitEvent, "tag")
    .u8(2, "kind")
    .u32(1, "inputTrees")
    .bytes(addressBytes(rail.inputTree ?? tree), 32, "inputTree")
    .u64(0n, "inputSequence")
    .bytes(addressBytes(tree), 32, "outputTree")
    .u64(100n, "firstLeaf")
    .finish();
  const source = Uint8Array.of(tag, ...instruction, ...(rail.tail ?? []));
  const frame = ringFrame({
    rail:
      tag === InstructionTag.ringAuthorityTransact
        ? "delegate"
        : rail.anonymous === true
          ? "anonymous"
          : "confidential",
    inputs: 2,
    outputs: 2,
  });
  const ringData = ringInstructionData(frame);
  const confirmed = confirmedEvent(RING, [PAYER], source, event, ringData);
  return { indexed, confirmed, source, event, frame, ringData };
}

function confirmedEvent(
  ring: Address,
  accounts: readonly Address[],
  source: Uint8Array,
  event: Uint8Array,
  ringData: Uint8Array = new Uint8Array(),
) {
  const keys = [...new Set([...accounts, ring, POOL])];
  const indices = accounts.map((account) => keys.indexOf(account));
  return {
    slot: 7,
    transaction: {
      signatures: [SIGNATURE],
      message: {
        accountKeys: keys,
        instructions: [
          {
            programIdIndex: keys.indexOf(ring),
            accounts: indices,
            data: getBase58Decoder().decode(ringData),
          },
        ],
      },
    },
    meta: {
      err: null,
      innerInstructions: [
        {
          index: 0,
          instructions: [
            {
              programIdIndex: keys.indexOf(POOL),
              accounts: indices,
              stackHeight: 2,
              data: getBase58Decoder().decode(source),
            },
            {
              programIdIndex: keys.indexOf(POOL),
              accounts: indices,
              stackHeight: 3,
              data: getBase58Decoder().decode(event),
            },
          ],
        },
      ],
    },
  };
}

describe("RpcTransactionOrigin", () => {
  it.each(["confirmed-event", "confirmed-deposit-event", "confirmed-merge-event"])(
    "matches Rust's %s codec and rejects substituted recovery data",
    async (name) => {
      const decode = wireDecoder((path) => new Error(`fixture ${path}`));
      const fixture = decode.record(
        JSON.parse(
          readFileSync(
            new URL(`../../../custom-rings/client/tests/fixtures/${name}.json`, import.meta.url),
            "utf8",
          ),
        ),
        "fixture",
      );
      const source = decode.record(fixture["source"], "source");
      const expected = decode.record(fixture["expected"], "expected");
      const bytes = (value: unknown): Uint8Array => {
        const hex = decode.string(value, "hex");
        if (!/^(?:[a-f0-9]{2})*$/u.test(hex)) throw new Error("fixture hex");
        return Uint8Array.from(Buffer.from(hex, "hex"));
      };
      const field = (value: unknown): Bytes32 => {
        const result = bytes(value);
        if (result.length !== 32) throw new Error("fixture field");
        return result as Bytes32;
      };
      const ring = decode.address(fixture["ring"], "ring");
      const sourceBytes = bytes(source["dataHex"]);
      const viewingKey = bytes(expected["viewingKeyHex"]);
      const hasViewingKey = viewingKey.some((byte) => byte !== 0);
      const indexed: IndexedShieldedTransaction = {
        slot: 7n,
        txSignature: SIGNATURE,
        eventIndex: 0,
        proofless: sourceBytes[0] === InstructionTag.ringDeposit,
        ringProgramId: ring,
        ...(hasViewingKey ? { txViewingPublicKey: X25519PublicKey.fromBytes(viewingKey) } : {}),
        // Photon historical rows omitted zero salts. Confirmed source bytes restore it.
        nullifiers: decode.list(expected["nullifiersHex"], "nullifiers").map(field),
        messages: decode.list(expected["messages"], "messages").map((value) => {
          const item = decode.record(value, "message");
          return {
            viewTag: field(item["viewTagHex"]),
            data: bytes(item["dataHex"]),
          };
        }),
        outputSlots: decode.list(expected["outputs"], "outputs").map((value) => {
          const item = decode.record(value, "output");
          const id = decode.integer(item["treeId"], "treeId");
          if (id > 0xffffn) throw new Error("fixture treeId");
          const treeId = Number(id);
          return {
            viewTag: field(item["viewTagHex"]),
            payload: bytes(item["payloadHex"]),
            outputContext: {
              hash: field(item["hashHex"]),
              treeId,
              tree: treeAddress(treeId),
              leafIndex: decode.integer(item["leafIndex"], "leafIndex"),
            },
          };
        }),
      };
      const transfer = name === "confirmed-event";
      const confirmed = confirmedEvent(
        ring,
        decode
          .list(source["accounts"], "accounts")
          .map((account) => decode.address(account, "account")),
        sourceBytes,
        bytes(fixture["eventDataHex"]),
        transfer
          ? ringInstructionData(
              ringFrame({
                rail: "confidential",
                inputs: indexed.nullifiers.length,
                outputs: indexed.outputSlots.length,
              }),
            )
          : undefined,
      );
      const origin = new RpcTransactionOrigin(rpcWith(confirmed));
      const bound = await origin.confirmedTransaction(indexed, ring);
      expect(bound?.kind).toBe(
        name === "confirmed-merge-event"
          ? "merge"
          : name === "confirmed-deposit-event"
            ? "deposit"
            : "transfer",
      );
      expect(bound?.transaction).toEqual({
        ...indexed,
        ...(hasViewingKey ? { salt: bytes(expected["saltHex"]) } : {}),
      });
      const output = indexed.outputSlots[0]!;
      for (const forged of [
        { ...indexed, proofless: !indexed.proofless },
        { ...indexed, nullifiers: [output.viewTag] },
        {
          ...indexed,
          outputSlots: [{ ...output, payload: Uint8Array.of(99) }, ...indexed.outputSlots.slice(1)],
        },
        {
          ...indexed,
          outputSlots: [
            { ...output, outputContext: { ...output.outputContext, leafIndex: 100n } },
            ...indexed.outputSlots.slice(1),
          ],
        },
      ])
        await expect(origin.confirmedTransaction(forged, ring)).rejects.toMatchObject({
          code: "RING_ORIGIN_DECODE",
        });
      if (name === "confirmed-merge-event") {
        // Every framing, ring hash, salt and ciphertext byte comes from settlement.
        for (const [offset, byte] of output.payload.entries()) {
          const payload = new Uint8Array(output.payload);
          payload[offset] = byte ^ 1;
          await expect(
            origin.confirmedTransaction(
              { ...indexed, outputSlots: [{ ...output, payload }] },
              ring,
            ),
          ).rejects.toMatchObject({ code: "RING_ORIGIN_DECODE" });
        }
      }
    },
  );

  it.each([
    [3, InstructionTag.ringTransact],
    [25, InstructionTag.ringAuthorityTransact],
  ])("binds a transfer under the ring's outer tag %i", async (outer, tag) => {
    const { indexed, confirmed, frame, ringData } = transferFixture(1, tag);
    expect(ringData[0]).toBe(outer);
    await expect(
      new RpcTransactionOrigin(rpcWith(confirmed)).confirmedTransaction(indexed, RING),
    ).resolves.toMatchObject({
      kind: "transfer",
      transaction: indexed,
      layout: RingTransactData.disclosureLayout(frame),
    });
  });

  it("takes the layout from the ring's own frame and refuses a frame off the event", async () => {
    const { indexed, confirmed } = transferFixture();
    const bind = (ringData: Uint8Array) => {
      confirmed.transaction.message.instructions[0]!.data = getBase58Decoder().decode(ringData);
      return new RpcTransactionOrigin(rpcWith(confirmed)).confirmedTransaction(indexed, RING);
    };
    for (const ringData of [
      Uint8Array.of(3),
      ringInstructionData(ringFrame({ rail: "confidential", inputs: 1, outputs: 2 })),
      ringInstructionData(ringFrame({ rail: "confidential", inputs: 2, outputs: 4 })),
      ringInstructionData(ringFrame({ rail: "anonymous", inputs: 2, outputs: 2 })),
      Uint8Array.of(RingInstructionTag.setPaused),
    ])
      await expect(bind(ringData)).rejects.toMatchObject({
        code: expect.stringMatching(/^RING_(ORIGIN_DECODE|TRANSACT_DATA_INVALID)$/u),
      });
  });

  it("attributes each event to the ring that called its own source instruction", async () => {
    const { indexed, confirmed, source, event, ringData } = transferFixture();
    const keys = confirmed.transaction.message.accountKeys;
    const other = [...keys, OTHER];
    const pool = (data: Uint8Array, stackHeight: number) => ({
      programIdIndex: keys.indexOf(POOL),
      accounts: [keys.indexOf(PAYER)],
      stackHeight,
      data: getBase58Decoder().decode(data),
    });
    const twoEvents = {
      ...confirmed,
      transaction: {
        ...confirmed.transaction,
        message: {
          accountKeys: other,
          instructions: [
            {
              programIdIndex: other.indexOf(RING),
              accounts: [0],
              data: getBase58Decoder().decode(ringData),
            },
            { programIdIndex: other.indexOf(OTHER), accounts: [0], data: "" },
          ],
        },
      },
      meta: {
        err: null,
        innerInstructions: [0, 1].map((index) => ({
          index,
          instructions: [pool(source, 2), pool(event, 3)],
        })),
      },
    };
    const origin = new RpcTransactionOrigin(rpcWith(twoEvents));
    await expect(origin.confirmedTransaction(indexed, RING)).resolves.toMatchObject({
      kind: "transfer",
    });
    await expect(
      origin.confirmedTransaction({ ...indexed, eventIndex: 1 }, RING),
    ).resolves.toBeUndefined();
  });

  it("names the output tree's id for every input spent from it, none for another tree", async () => {
    for (const [inputTree, ids] of [
      [treeAddress(4), [4, 4]],
      [treeAddress(5), [undefined, undefined]],
    ] as const) {
      const { indexed, confirmed } = transferFixture(1, InstructionTag.ringTransact, { inputTree });
      await expect(
        new RpcTransactionOrigin(rpcWith(confirmed)).confirmedTransaction(indexed, RING),
      ).resolves.toMatchObject({ kind: "transfer", inputTreeIds: ids });
    }
  });

  it("reads the anonymous rail's co-signer tail and refuses a tail on any other rail", async () => {
    const coSigner = new Uint8Array(32).fill(13);
    const anonymous = transferFixture(1, InstructionTag.ringTransact, {
      anonymous: true,
      tail: coSigner,
    });
    await expect(
      new RpcTransactionOrigin(rpcWith(anonymous.confirmed)).confirmedTransaction(
        anonymous.indexed,
        RING,
      ),
    ).resolves.toMatchObject({ kind: "transfer", transaction: anonymous.indexed });
    for (const rail of [{ anonymous: true }, { tail: coSigner }]) {
      const { indexed, confirmed } = transferFixture(1, InstructionTag.ringTransact, rail);
      await expect(
        new RpcTransactionOrigin(rpcWith(confirmed)).confirmedTransaction(indexed, RING),
      ).rejects.toMatchObject({ code: "RING_ORIGIN_DECODE" });
    }
  });

  it.each([InstructionTag.ringTransact, InstructionTag.ringAuthorityTransact])(
    "binds every indexed transfer field to confirmed SPP tag %i",
    async (tag) => {
      const { indexed, confirmed } = transferFixture(1, tag);
      const origin = new RpcTransactionOrigin(rpcWith(confirmed));
      const authenticated = (await origin.confirmedTransaction(indexed, RING))?.transaction;
      expect(authenticated).toEqual(indexed);
      expect(authenticated?.messages[0]?.data).not.toBe(indexed.messages[0]?.data);
      const field = new Uint8Array(32).fill(42) as Bytes32;
      const first = indexed.outputSlots[0]!;
      const mutateOutput = (output: typeof first): IndexedShieldedTransaction => ({
        ...indexed,
        outputSlots: [output, ...indexed.outputSlots.slice(1)],
      });
      const forgeries: readonly IndexedShieldedTransaction[] = [
        { ...indexed, slot: indexed.slot + 1n },
        { ...indexed, proofless: true },
        { ...indexed, ringProgramId: OTHER },
        {
          ...indexed,
          txViewingPublicKey: transferFixture().indexed.txViewingPublicKey!,
        },
        { ...indexed, salt: new Uint8Array(16).fill(2) as Bytes16 },
        { ...indexed, nullifiers: [field, ...indexed.nullifiers.slice(1)] },
        { ...indexed, nullifiers: [...indexed.nullifiers].reverse() },
        {
          ...indexed,
          messages: [
            { ...indexed.messages[0]!, data: Uint8Array.of(99) },
            ...indexed.messages.slice(1),
          ],
        },
        { ...indexed, messages: [...indexed.messages].reverse() },
        { ...indexed, messages: [] },
        { ...indexed, outputSlots: [...indexed.outputSlots].reverse() },
        mutateOutput({ ...first, viewTag: field }),
        mutateOutput({ ...first, payload: Uint8Array.of(99) }),
        mutateOutput({
          ...first,
          outputContext: { ...first.outputContext, hash: field },
        }),
        mutateOutput({
          ...first,
          outputContext: { ...first.outputContext, tree: treeAddress(5) },
        }),
        mutateOutput({
          ...first,
          outputContext: { ...first.outputContext, treeId: 5 },
        }),
        mutateOutput({
          ...first,
          outputContext: { ...first.outputContext, leafIndex: 99n },
        }),
      ];
      for (const forged of forgeries) {
        await expect(origin.confirmedTransaction(forged, RING)).rejects.toMatchObject({
          code: "RING_ORIGIN_DECODE",
        });
      }
      await expect(origin.confirmedTransaction(indexed, OTHER)).resolves.toBeUndefined();
    },
  );

  it("accepts Kit bigint slots and rejects out-of-range RPC slots", async () => {
    const { indexed, confirmed } = transferFixture();
    for (const slot of [7n, 7, "7"])
      await expect(
        new RpcTransactionOrigin(rpcWith({ ...confirmed, slot })).confirmedTransaction(
          indexed,
          RING,
        ),
      ).resolves.toMatchObject({ transaction: indexed });
    for (const slot of [-1n, 1n << 64n, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])
      await expect(
        new RpcTransactionOrigin(rpcWith({ ...confirmed, slot })).confirmedTransaction(
          indexed,
          RING,
        ),
      ).rejects.toMatchObject({ code: "RING_ORIGIN_DECODE" });
  });

  it("normalizes omitted zero salt only when the confirmed instruction contains zero", async () => {
    for (const saltByte of [0, 1]) {
      const { indexed, confirmed } = transferFixture(saltByte);
      const { salt, ...omitted } = indexed;
      const result = new RpcTransactionOrigin(rpcWith(confirmed)).confirmedTransaction(
        omitted,
        RING,
      );
      if (saltByte === 0) await expect(result).resolves.toMatchObject({ transaction: { salt } });
      else
        await expect(result).rejects.toMatchObject({
          code: "RING_ORIGIN_DECODE",
        });
    }
  });

  it("reads each signature once unless the caller scopes the read", async () => {
    let calls = 0;
    const { indexed, confirmed } = transferFixture();
    const origin = new RpcTransactionOrigin(
      solanaRpcReads({
        getTransaction: () => ({
          send: async () => {
            calls += 1;
            return confirmed;
          },
        }),
      }),
    );
    const signal = new AbortController().signal;
    await origin.confirmedTransaction(indexed, RING, { signal });
    await origin.confirmedTransaction(indexed, RING, { signal });
    await origin.confirmedTransaction(indexed, RING);
    await origin.confirmedTransaction(indexed, RING);
    expect(calls).toBe(3);
  });

  it("treats an unknown signature and an RPC failure as errors", async () => {
    const { indexed } = transferFixture();
    for (const result of [null, new Error("rpc down")]) {
      const origin = new RpcTransactionOrigin(rpcWith(result));
      await expect(origin.confirmedTransaction(indexed, RING)).rejects.toMatchObject({
        code: "RING_ORIGIN_UNAVAILABLE",
      });
    }
  });

  it("rejects a response for a different signature", async () => {
    const { indexed, confirmed } = transferFixture();
    const origin = new RpcTransactionOrigin(rpcWith(confirmed));
    await expect(
      origin.confirmedTransaction({ ...indexed, txSignature: "6".repeat(87) as Signature }, RING),
    ).rejects.toMatchObject({ code: "RING_ORIGIN_DECODE" });
  });
});
