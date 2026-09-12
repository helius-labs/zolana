import { AccountRole, address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import * as pda from "../src/interface/pda/index.js";

import prefixVector from "../../../test-vectors/transact_account_prefix.json" with { type: "json" };

import {
  mergeTransactInstruction,
  nullifierPdaAccounts,
  ringTransactAccounts,
  transactInstruction,
} from "../src/interface/instructions/index.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID, SOL_INTERFACE } from "../src/interface/index.js";
import { nullifierPdaAddress, nullifierPda } from "../src/interface/pda/index.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  InputUtxo,
  MergeTransactInstructionData,
  TransactInstructionData,
} from "../src/interface/types.js";

const PAYER = address("k7FaK87WHGVXzkaoHb7CdVPgkKDQhZ29VLDeBVbDfYn");
const TREE = address("2RJD1KnDRGEkvuFfAGrJ7PD28LRE9LRDjZznDywagzmr");
const OUTPUT_TREE = address("2VDW9dFE1ZXz4zWAbaBDQFynNVdRpQ73HyfSHMzBSL6Z");
const RING_AUTH = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const SYSTEM = address("11111111111111111111111111111111");
const PREFIX_ADDRESSES = new Map<string, Address>([
  ["payer", PAYER],
  ["outputTree", OUTPUT_TREE],
  ["program", SHIELDED_POOL_PROGRAM_ID],
  ["systemProgram", SYSTEM],
  ["ringConfig", RING_AUTH],
]);

function filled(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

function input(byte: number): InputUtxo {
  return { nullifierHash: filled(byte, 32) as Bytes32, treeIndex: 0 };
}

function transactData(inputs: readonly InputUtxo[]): TransactInstructionData {
  return {
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    privateTxHash: filled(41, 32) as Bytes32,
    circuit: { kind: "confidentialEddsa", inputs: 2, outputs: 3, publicAssetSlots: 3 },
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(42, 16) as Bytes16,
    proof: {
      a: filled(43, 32) as Bytes32,
      b: filled(44, 128) as Bytes128,
      c: filled(45, 32) as Bytes32,
    },
    inputs,
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: [],
    outputs: [],
    messages: [],
  };
}

async function nullifierPdas(inputs: readonly InputUtxo[]) {
  const accounts = await nullifierPdaAccounts(
    TREE,
    inputs.map((utxo) => utxo.nullifierHash),
  );
  return accounts.map((account) => account.address);
}

describe("nullifier PDA accounts", () => {
  it("rejects unsupported tree declarations before deriving nullifier accounts", async () => {
    const context = { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 };
    const derive = vi.spyOn(pda, "nullifierPdaAddress");
    try {
      for (const data of [
        { ...transactData([input(71)]), treeContexts: [] },
        { ...transactData([input(71)]), treeContexts: [context, context] },
        transactData([{ ...input(71), treeIndex: 1 }]),
      ]) {
        await expect(
          transactInstruction({
            payer: PAYER,
            inputTree: TREE,
            outputTree: OUTPUT_TREE,
            data,
          }),
        ).rejects.toMatchObject({ code: "INTERFACE_INVALID_SHAPE" });
        await expect(
          ringTransactAccounts({
            payer: PAYER,
            inputTree: TREE,
            outputTree: OUTPUT_TREE,
            ringAuth: RING_AUTH,
            inputs: data.inputs,
            treeContexts: data.treeContexts,
          }),
        ).rejects.toMatchObject({ code: "INTERFACE_INVALID_SHAPE" });
      }
      expect(derive).not.toHaveBeenCalled();
    } finally {
      derive.mockRestore();
    }
  });

  it("derives the PDA from the input tree and the nullifier", async () => {
    const [expected] = await nullifierPda(TREE, filled(7, 32));
    expect(await nullifierPdaAddress(TREE, filled(7, 32))).toBe(expected);
    expect(await nullifierPdaAddress(OUTPUT_TREE, filled(7, 32))).not.toBe(expected);
    expect(await nullifierPdaAddress(TREE, filled(8, 32))).not.toBe(expected);
  });

  it("matches the fixed Rust PDA vector", async () => {
    expect(await nullifierPda(TREE, filled(7, 32))).toEqual([
      address("FketprhoGrMJG7tu9XaXEXhm4vCqzEubwMPFm874xtMm"),
      252,
    ]);
  });

  it("exposes the close-nullifier-pdas instruction tag", () => {
    expect(InstructionTag.closeNullifierPdas).toBe(18);
  });

  it("rejects a nullifier that is not 32 bytes", async () => {
    await expect(nullifierPda(TREE, filled(7, 31))).rejects.toMatchObject({
      code: "INTERFACE_INVALID_LENGTH",
    });
  });

  it("places one writable PDA per input after the fixed prefix and input tree in transact", async () => {
    const inputs = [input(71), input(72)];
    const instruction = await transactInstruction({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      withdrawal: { kind: "sol", recipient: OWNER },
      data: transactData(inputs),
    });

    const [first, second] = await nullifierPdas(inputs);
    expect(
      instruction.accounts?.slice(0, prefixVector.transact.length).map((meta) => meta.address),
    ).toEqual(prefixVector.transact.map((name) => PREFIX_ADDRESSES.get(name)));
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [OUTPUT_TREE, AccountRole.WRITABLE],
      [SHIELDED_POOL_PROGRAM_ID, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [TREE, AccountRole.WRITABLE],
      [first, AccountRole.WRITABLE],
      [second, AccountRole.WRITABLE],
      [SOL_INTERFACE, AccountRole.WRITABLE],
      [OWNER, AccountRole.WRITABLE],
    ]);
  });

  it("keeps ring_config at index 4 and puts the PDAs before the owner signers", async () => {
    const inputs = [input(71), input(72)];
    const accounts = await ringTransactAccounts({
      payer: PAYER,
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      ringAuth: RING_AUTH,
      inputs,
      treeContexts: transactData(inputs).treeContexts,
      ownerSigners: [OWNER],
    });

    const [first, second] = await nullifierPdas(inputs);
    expect(accounts.slice(0, prefixVector.ringTransact.length).map((meta) => meta.address)).toEqual(
      prefixVector.ringTransact.map((name) => PREFIX_ADDRESSES.get(name)),
    );
    expect(accounts.map((meta) => [meta.address, meta.role])).toEqual([
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [OUTPUT_TREE, AccountRole.WRITABLE],
      [SHIELDED_POOL_PROGRAM_ID, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [RING_AUTH, AccountRole.READONLY],
      [TREE, AccountRole.WRITABLE],
      [first, AccountRole.WRITABLE],
      [second, AccountRole.WRITABLE],
      [OWNER, AccountRole.READONLY_SIGNER],
    ]);
  });

  it("places the eight merge PDAs after the pool program", async () => {
    const nullifiers = Array.from({ length: 8 }, (_, index) => filled(80 + index, 32) as Bytes32);
    const data: MergeTransactInstructionData = {
      expiryUnixTs: 0xffff_ffff_ffff_ffffn,
      proof: {
        a: filled(43, 32) as Bytes32,
        b: filled(44, 128) as Bytes128,
        c: filled(45, 32) as Bytes32,
      },
      outputUtxoHash: filled(46, 32) as Bytes32,
      eddsaOwner: true,
      privateTxHash: filled(47, 32) as Bytes32,
      nullifiers,
      utxoTreeRootIndex: 0,
      nullifierTreeRootIndex: 0,
    };
    const instruction = await mergeTransactInstruction({
      inputTree: TREE,
      outputTree: OUTPUT_TREE,
      payer: PAYER,
      userRecord: OWNER,
      data,
    });

    const expectedNullifierPdas = await Promise.all(
      nullifiers.map((nullifier) => nullifierPdaAddress(TREE, nullifier)),
    );
    expect(instruction.accounts?.map((meta) => [meta.address, meta.role])).toEqual([
      [TREE, AccountRole.WRITABLE],
      [OUTPUT_TREE, AccountRole.WRITABLE],
      [PAYER, AccountRole.WRITABLE_SIGNER],
      [OWNER, AccountRole.READONLY],
      [SYSTEM, AccountRole.READONLY],
      [SHIELDED_POOL_PROGRAM_ID, AccountRole.READONLY],
      ...expectedNullifierPdas.map((pda) => [pda, AccountRole.WRITABLE]),
    ]);
  });
});
