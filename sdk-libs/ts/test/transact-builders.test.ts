import { address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import * as pda from "../src/interface/pda/index.js";
import {
  ringTransactAccounts,
  transactCpiAccounts,
  transactInstruction,
} from "../src/interface/instructions/index.js";
import { SPL_TOKEN_2022_PROGRAM_ID } from "../src/interface/program.js";
import { MAX_OUTPUTS } from "../src/interface/shape.js";
import {
  TransactSettlement,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes128,
  type InterfaceTransfer,
  type TransactInstructionData,
} from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { createExternalData } from "../src/transaction/instructions/transact.js";

const PAYER = address("k7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn");
const TREE = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
const OUTPUT_TREE = address("2VDW9dFE1ZXz4zWAbaBDQFynNVdRpQ73HyfSHMzBSL6Z");
const RING_AUTH = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const DEPOSITOR = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const MINT = address("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
const TOKEN_ACCOUNT = address("79cu2QNvp92chEmBhBgcUfERDT9KHnUcr8eiJb5WzKML");
const SPL_TOKEN_INTERFACE = address("7DYCAhqwQSKqqL1h8V1XmY1BTcMWxrASQYKNMy87jeg3");

function filled(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function data(interfaceTransfers: readonly InterfaceTransfer[]): TransactInstructionData {
  return {
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    privateTxHash: filled(41, 32) as Bytes32,
    circuit: { kind: "confidentialSigner", inputs: 1, outputs: 2, publicAssetSlots: 3 },
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(42, 16) as Bytes16,
    proof: {
      a: filled(43, 32) as Bytes32,
      b: filled(44, 128) as Bytes128,
      c: filled(45, 32) as Bytes32,
    },
    inputs: [{ nullifierHash: filled(71, 32) as Bytes32, treeIndex: 0 }],
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers,
    outputs: [],
    messages: [],
  };
}

const SOL_DEPOSIT: InterfaceTransfer = { kind: "solDeposit", amount: 5n };
const SOL_WITHDRAWAL: InterfaceTransfer = { kind: "solWithdrawal", amount: 6n };
const SPL_DEPOSIT: InterfaceTransfer = { kind: "splDeposit", amount: 7n, splInterfaceBump: 254 };

const SOL_WITHDRAWAL_GROUP = TransactSettlement.solWithdrawal({ recipient: RECIPIENT });
const SPL_DEPOSIT_GROUP = TransactSettlement.splDeposit({
  mint: MINT,
  splTokenInterface: SPL_TOKEN_INTERFACE,
  tokenAuthority: DEPOSITOR,
  sourceTokenAccount: TOKEN_ACCOUNT,
  tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
});

/** Builds every transact account list from the same legs and groups. */
function builds(
  transfers: readonly InterfaceTransfer[],
  settlements?: readonly TransactSettlement[],
): readonly (() => Promise<unknown>)[] {
  const input = {
    payer: PAYER,
    inputTree: TREE,
    outputTree: OUTPUT_TREE,
    ownerSigners: [],
    ...(settlements === undefined ? {} : { settlements }),
    data: data(transfers),
  };
  return [
    () => transactInstruction(input),
    () => transactCpiAccounts({ ...input, signerPdas: [] }),
    () =>
      ringTransactAccounts({
        payer: PAYER,
        inputTrees: [TREE],
        outputTree: OUTPUT_TREE,
        ringAuth: RING_AUTH,
        inputs: input.data.inputs,
        treeContexts: input.data.treeContexts,
        interfaceTransfers: transfers,
        ...(settlements === undefined ? {} : { settlements }),
      }),
  ];
}

describe("transact settlement groups", () => {
  it.each([
    ["an SPL deposit leg without its group", [SPL_DEPOSIT], undefined],
    [
      "two SOL withdrawal legs with one group",
      [SOL_WITHDRAWAL, SOL_WITHDRAWAL],
      [SOL_WITHDRAWAL_GROUP],
    ],
    ["a group without a leg", [], [SOL_WITHDRAWAL_GROUP]],
  ] as const)("refuses %s before deriving any account", async (_name, transfers, settlements) => {
    const derive = vi.spyOn(pda, "nullifierPdaAddress");
    try {
      for (const build of builds(transfers, settlements)) {
        await expect(build()).rejects.toMatchObject({
          code: "INTERFACE_INVALID_SHAPE",
          details: {
            name: "settlements",
            expected: transfers.length,
            actual: settlements?.length ?? 0,
          },
        });
      }
      expect(derive).not.toHaveBeenCalled();
    } finally {
      derive.mockRestore();
    }
  });

  it.each([
    ["a withdrawal group for a SOL deposit leg", SOL_DEPOSIT, SOL_WITHDRAWAL_GROUP],
    [
      "a deposit group for a SOL withdrawal leg",
      SOL_WITHDRAWAL,
      TransactSettlement.solDeposit({ depositor: DEPOSITOR }),
    ],
    ["an SPL deposit group for a SOL withdrawal leg", SOL_WITHDRAWAL, SPL_DEPOSIT_GROUP],
  ] as const)("refuses %s", async (_name, transfer, group) => {
    for (const build of builds([transfer], [group])) {
      await expect(build()).rejects.toMatchObject({
        code: "INTERFACE_INVALID_SHAPE",
        details: { name: "settlements[0]", expected: transfer.kind, actual: group.kind },
      });
    }
  });
});

describe("transact external data bounds", () => {
  function externalData(outputs: number, messages: number) {
    const ownerTag = filled(8, 32) as Bytes32;
    return createExternalData({
      txViewingPublicKey: ShieldedKeypair.generate().viewingPublicKey(),
      salt: filled(1, 16) as Bytes16,
      outputs: Array.from({ length: outputs }, (_, index) => ({
        utxoHash: filled(index + 1, 32) as Bytes32,
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: Array.from({ length: outputs }, () => ownerTag),
      messages: Array.from({ length: messages }, () => ({
        viewTag: filled(9, 32) as Bytes32,
        data: new Uint8Array(0),
      })),
    });
  }

  it("refuses more outputs than any shape publishes and more messages than a u8 counts", () => {
    expect(MAX_OUTPUTS).toBe(16);
    expect(() => externalData(MAX_OUTPUTS, 0xff).hash()).not.toThrow();
    for (const [outputs, messages] of [
      [MAX_OUTPUTS + 1, 0],
      [0, 0x100],
    ] as const) {
      expect(() => externalData(outputs, messages).hash()).toThrowError(
        expect.objectContaining({
          code: "TRANSACTION_TOO_MANY_OUTPUTS",
          details: { outputs, messages },
        }),
      );
    }
  });
});
