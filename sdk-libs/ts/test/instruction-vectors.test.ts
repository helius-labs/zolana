import { address, isSignerRole, isWritableRole, type AccountMeta } from "@solana/kit";
import { describe, expect, it } from "vitest";

import protocolConfigVector from "../../../test-vectors/create_protocol_config.json" with { type: "json" };
import settlementVector from "../../../test-vectors/transact_settlements.json" with { type: "json" };

import {
  createProtocolConfigInstruction,
  ringTransactAccounts,
  transactCpiAccounts,
  transactInstruction,
} from "../src/interface/instructions/index.js";
import { InstructionTag } from "../src/interface/program.js";
import {
  TransactSettlement,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes128,
  type InterfaceTransfer,
  type TransactInstructionData,
} from "../src/interface/types.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";

function hex(bytes: Readonly<ArrayLike<number>>): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function filled(value: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function field(seed: number): Bytes32 {
  const value = filled(seed, 32);
  value[0] = 0;
  return value as Bytes32;
}

function metas(accounts: readonly AccountMeta[]) {
  return accounts.map((account) => ({
    address: account.address,
    signer: isSignerRole(account.role),
    writable: isWritableRole(account.role),
  }));
}

type TransferVector = (typeof settlementVector.interfaceTransfers)[number];
type SettlementVector = (typeof settlementVector.settlements)[number];

function interfaceTransfer(vector: TransferVector): InterfaceTransfer {
  const amount = BigInt(vector.amount);
  switch (vector.kind) {
    case "solDeposit":
    case "solWithdrawal":
      return { kind: vector.kind, amount };
    case "splDeposit":
    case "splWithdrawal":
      if (vector.splInterfaceBump === undefined) throw new Error("an SPL leg names its bump");
      return { kind: vector.kind, amount, splInterfaceBump: vector.splInterfaceBump };
    default:
      throw new Error(`unknown leg ${vector.kind}`);
  }
}

function required(value: string | undefined, name: string): string {
  if (value === undefined) throw new Error(`the vector names ${name}`);
  return value;
}

function settlement(vector: SettlementVector): TransactSettlement {
  switch (vector.kind) {
    case "solDeposit":
      return TransactSettlement.solDeposit({
        depositor: address(required(vector.depositor, "depositor")),
      });
    case "solWithdrawal":
      return TransactSettlement.solWithdrawal({
        recipient: address(required(vector.recipient, "recipient")),
      });
    case "splDeposit":
      return TransactSettlement.splDeposit({
        mint: address(required(vector.mint, "mint")),
        splTokenInterface: address(required(vector.splTokenInterface, "splTokenInterface")),
        tokenAuthority: address(required(vector.tokenAuthority, "tokenAuthority")),
        sourceTokenAccount: address(required(vector.sourceTokenAccount, "sourceTokenAccount")),
        tokenProgram: address(required(vector.tokenProgram, "tokenProgram")),
      });
    case "splWithdrawal":
      return TransactSettlement.splWithdrawal({
        mint: address(required(vector.mint, "mint")),
        splTokenInterface: address(required(vector.splTokenInterface, "splTokenInterface")),
        recipientTokenAccount: address(
          required(vector.recipientTokenAccount, "recipientTokenAccount"),
        ),
        tokenProgram: address(required(vector.tokenProgram, "tokenProgram")),
      });
    default:
      throw new Error(`unknown settlement ${vector.kind}`);
  }
}

/** The Rust vector's `transact_data`, field for field. */
function transactData(): TransactInstructionData {
  return {
    expiryUnixTs: 77n,
    txViewingPk: filled(3, 33) as Bytes33,
    salt: filled(4, 16) as Bytes16,
    interfaceTransfers: settlementVector.interfaceTransfers.map(interfaceTransfer),
    outputs: [],
    messages: [],
    privateTxHash: field(5),
    circuit: { kind: "confidentialSigner", inputs: 2, outputs: 2, publicAssetSlots: 3 },
    proof: {
      a: filled(6, 32) as Bytes32,
      b: filled(7, 128) as Bytes128,
      c: filled(8, 32) as Bytes32,
    },
    inputs: [0, 1].map((index) => ({ nullifierHash: field(0x10 + index), treeIndex: 0 })),
    treeContexts: [{ utxoTreeRootIndex: 9, nullifierTreeRootIndex: 10 }],
  };
}

const TRANSACT_INPUT = {
  payer: address(settlementVector.payer),
  inputTree: address(settlementVector.inputTree),
  outputTree: address(settlementVector.outputTree),
  ownerSigners: [address(settlementVector.ownerSigner)],
  settlements: settlementVector.settlements.map(settlement),
  data: transactData(),
};

describe("transact settlement accounts (test-vectors/transact_settlements.json)", () => {
  it("lists one settlement group per interface transfer as Rust `Transact::instruction` does", async () => {
    const built = await transactInstruction(TRANSACT_INPUT);
    expect(built.programAddress).toBe(settlementVector.transact.programAddress);
    expect(hex(built.data ?? [])).toBe(settlementVector.transact.data);
    expect(metas(built.accounts ?? [])).toEqual(settlementVector.transact.accounts);
  });

  it("lists the signing PDA before the settlement groups as Rust `Transact::cpi_accounts` does", async () => {
    const accounts = await transactCpiAccounts({
      ...TRANSACT_INPUT,
      signerPdas: [address(settlementVector.signerPda)],
    });
    expect(metas(accounts)).toEqual(settlementVector.transactCpiAccounts);
  });

  it("lists the same groups after the ring owner signers as Rust `RingTransact::instruction` does", async () => {
    const data = transactData();
    const accounts = await ringTransactAccounts({
      payer: TRANSACT_INPUT.payer,
      inputTrees: [TRANSACT_INPUT.inputTree],
      outputTree: TRANSACT_INPUT.outputTree,
      ringAuth: address(settlementVector.ringAuth),
      inputs: data.inputs,
      treeContexts: data.treeContexts,
      interfaceTransfers: data.interfaceTransfers,
      ownerSigners: TRANSACT_INPUT.ownerSigners,
      settlements: TRANSACT_INPUT.settlements,
    });
    expect(metas(accounts)).toEqual(settlementVector.ringTransact.accounts);
    expect(hex([InstructionTag.ringTransact, ...encodeTransactInstructionData(data)])).toBe(
      settlementVector.ringTransact.data,
    );
  });
});

describe("create protocol config (test-vectors/create_protocol_config.json)", () => {
  it("builds the six accounts and data of Rust `CreateProtocolConfig::instruction`", async () => {
    const vector = protocolConfigVector;
    const built = await createProtocolConfigInstruction({
      feePayer: address(vector.feePayer),
      initializationAuthority: address(vector.initializationAuthority),
      protocolAuthority: address(vector.protocolAuthority),
      treeCreationAuthority: address(vector.treeCreationAuthority),
      treeCreationIsPermissionless: vector.treeCreationIsPermissionless,
      foresterAuthority: address(vector.foresterAuthority),
      ringCreationAuthority: address(vector.ringCreationAuthority),
      ringActivationIsPermissionless: vector.ringActivationIsPermissionless,
      splInterfaceCreationIsPermissionless: vector.splInterfaceCreationIsPermissionless,
      feeAuthority: address(vector.feeAuthority),
    });
    expect(built.programAddress).toBe(vector.instruction.programAddress);
    expect(hex(built.data ?? [])).toBe(vector.instruction.data);
    expect(metas(built.accounts ?? [])).toEqual(vector.instruction.accounts);
  });
});
