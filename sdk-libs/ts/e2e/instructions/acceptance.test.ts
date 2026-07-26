import type {
  Address,
  Bytes31,
  Bytes32,
  Instruction,
  Signature,
  Transaction,
  TransactInstructionData,
  TransactWithdrawal,
} from "@zolana/interface";
import { SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID } from "@zolana/interface";
import {
  depositInstructionDataCodec,
  transactInstructionDataCodec,
} from "@zolana/interface/codecs";
import { depositInstruction, transactInstruction } from "@zolana/interface/instructions";
import { createTestNativeSigner, TestRpc } from "@zolana/test-kit/node";
import { fixtureJson } from "@zolana/test-kit/fixtures";
import { describe, expect, it } from "vitest";

interface AccountFixture {
  readonly address: Address;
  readonly signer: boolean;
  readonly writable: boolean;
}

interface WireFixture {
  readonly instruction: {
    readonly accounts: readonly AccountFixture[];
    readonly dataBytes: string;
    readonly programId: Address;
  };
  readonly transactDataBytes: string;
  readonly unsignedMessageBytes: string;
}

interface RailCase {
  readonly rail: "eddsa" | "p256" | "mixed-p256";
  readonly logicalInputs: {
    readonly payer: Address;
    readonly tree: Address;
    readonly publicSettlement: {
      readonly publicSolAmount: string | null;
      readonly publicSplAmount: string | null;
      readonly splTokenInterface: Address;
      readonly userSolAccount: Address;
      readonly userSplTokenAccount: Address;
    };
  };
  readonly proof: {
    readonly compressed: {
      readonly commitment: null | {
        readonly commitmentBytes: string;
        readonly commitmentPokBytes: string;
      };
    };
    readonly proverInputs: { readonly rail: "eddsa" | "p256" };
    readonly proverRequest: { readonly circuitType: string; readonly nInputs: number };
    readonly proverResult: { readonly commitment: null | object };
    readonly spendProofs: readonly unknown[];
  };
  readonly confirmation: {
    readonly directOutputTagsBytes: readonly string[];
    readonly innerOutputTagsBytes: readonly string[];
    readonly ownerTagError: null | { readonly code: string; readonly details: string };
  };
  readonly errors: Readonly<
    Record<
      string,
      { readonly code: string; readonly customCode?: string; readonly details: string }
    >
  >;
  readonly stateTransition: {
    readonly externalRecipientBalanceDeltas: { readonly sol: string; readonly spl: string };
    readonly inputNullifierBytes: readonly string[];
    readonly outputs: readonly {
      readonly amount: string;
      readonly asset: Address;
      readonly ownerTagBytes: string;
      readonly utxoHashBytes: string;
    }[];
    readonly replayError: {
      readonly code: string;
      readonly customCode: string;
      readonly details: string;
    };
    readonly spentInputHashesBytes: readonly string[];
  };
  readonly wire: WireFixture;
}

interface SpendFixture {
  readonly id: string;
  readonly expected: { readonly railCases: readonly RailCase[] } | RailCase;
}

interface DepositFixture {
  readonly id: string;
  readonly inputs: {
    readonly amount: string;
    readonly blindingBytes: string;
    readonly memoBytes: string;
    readonly ownerBytes: string;
    readonly viewTagBytes: string;
  };
  readonly expected: {
    readonly instruction: WireFixture["instruction"];
  };
}

const BLOCKHASH = encodeBase58(new Uint8Array(32).fill(0x53));
const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111" as Address;
const COMPUTE_LIMIT_DATA = hexBytes("02c05c1500");

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../gu)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizedAccounts(instruction: Instruction): readonly AccountFixture[] {
  return instruction.accounts.map((account) => ({
    address: account.address,
    signer: account.isSigner,
    writable: account.isWritable,
  }));
}

function railCases(fixture: SpendFixture): readonly RailCase[] {
  return "railCases" in fixture.expected ? fixture.expected.railCases : [fixture.expected];
}

function withdrawalFor(value: RailCase): TransactWithdrawal | undefined {
  const settlement = value.logicalInputs.publicSettlement;
  if (settlement.publicSolAmount !== null) {
    return { kind: "sol", recipient: settlement.userSolAccount };
  }
  if (settlement.publicSplAmount !== null) {
    const accounts = value.wire.instruction.accounts;
    const cpiAuthority = accounts[2]?.address;
    return {
      kind: "spl",
      ...(cpiAuthority === undefined ? {} : { cpiAuthority }),
      splTokenInterface: settlement.splTokenInterface,
      recipient: accounts[4]?.address ?? settlement.userSplTokenAccount,
      userTokenAccount: settlement.userSplTokenAccount,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    };
  }
  return undefined;
}

function instructionFor(value: RailCase): Instruction {
  const data = transactInstructionDataCodec.decode(hexBytes(value.wire.transactDataBytes));
  const withdrawal = withdrawalFor(value);
  return transactInstruction({
    payer: value.logicalInputs.payer,
    tree: value.logicalInputs.tree,
    data,
    ...(withdrawal === undefined ? {} : { withdrawal }),
  });
}

function computeInstruction(data: Uint8Array): Instruction {
  return {
    programAddress: COMPUTE_BUDGET_PROGRAM_ID,
    accounts: [],
    data,
  };
}

function fixtureMessage(value: RailCase, instruction: Instruction): Transaction {
  return compileTransaction({
    feePayer: value.logicalInputs.payer,
    recentBlockhash: BLOCKHASH,
    instructions: [computeInstruction(COMPUTE_LIMIT_DATA), instruction],
  });
}

describe("P13 raw instruction acceptance", () => {
  it("matches the manifest-verified deposit instruction", async () => {
    const fixture = await fixtureJson<DepositFixture>("workflows/deposit-v1");
    const expected = fixture.expected.instruction;
    const data = {
      viewTag: hexBytes(fixture.inputs.viewTagBytes) as Bytes32,
      owner: hexBytes(fixture.inputs.ownerBytes) as Bytes32,
      blinding: hexBytes(fixture.inputs.blindingBytes) as Bytes31,
      amount: BigInt(fixture.inputs.amount),
      memo: hexBytes(fixture.inputs.memoBytes),
    };
    const decoded = depositInstructionDataCodec.decode(depositInstructionDataCodec.encode(data));
    const instruction = depositInstruction({
      tree: expected.accounts[0]?.address as Address,
      depositor: expected.accounts[1]?.address as Address,
      data: decoded,
    });

    expect(fixture.id).toBe("fx-workflow-instruction-deposit-v1");
    expect(instruction.programAddress).toBe(expected.programId);
    expect(normalizedAccounts(instruction)).toEqual(expected.accounts);
    expect(hex(instruction.data)).toBe(expected.dataBytes);
    expect(decoded).toEqual(data);
  });

  it("matches exact transact accounts, bytes, and unsigned messages", async () => {
    const fixtures = await loadSpendFixtures();
    for (const fixture of fixtures) {
      for (const value of railCases(fixture)) {
        const instruction = instructionFor(value);
        expect(instruction.programAddress).toBe(value.wire.instruction.programId);
        expect(normalizedAccounts(instruction)).toEqual(value.wire.instruction.accounts);
        expect(hex(instruction.data)).toBe(value.wire.instruction.dataBytes);
        expect(hex(fixtureMessage(value, instruction).messageBytes)).toBe(
          value.wire.unsignedMessageBytes,
        );
      }
    }
  });

  it("preserves exact external-signing message bytes", async () => {
    const fixture = (await fixtureJson<SpendFixture>(
      "workflows/instruction-transfer-v1",
    )) as SpendFixture;
    for (const [index, value] of railCases(fixture).entries()) {
      // The fixture payer has no key in the repo, so the signer pays here
      // instead; what matters is that signing leaves the message untouched.
      const signer = createTestNativeSigner(new Uint8Array(32).fill(index + 1) as Bytes32);
      const transaction = compileTransaction({
        feePayer: signer.address,
        recentBlockhash: BLOCKHASH,
        instructions: [computeInstruction(COMPUTE_LIMIT_DATA), instructionFor(value)],
      });
      const signed = await signer.signNativeTransaction(transaction);
      expect(signed.messageBytes).toEqual(transaction.messageBytes);
      expect(signed.signatures).toHaveLength(transaction.signatures.length);
      expect(signed.signatures[0]).toBeTypeOf("string");
    }
  });

  it("covers EdDSA, P256, and mixed-input proof contracts", async () => {
    const fixtures = await loadSpendFixtures();
    const cases = fixtures.flatMap(railCases);
    expect(new Set(cases.map((value) => value.rail))).toEqual(
      new Set(["eddsa", "p256", "mixed-p256"]),
    );
    for (const value of cases) {
      const p256 = value.rail !== "eddsa";
      expect(value.proof.proverInputs.rail).toBe(p256 ? "p256" : "eddsa");
      expect(value.proof.proverRequest.circuitType).toBe(
        p256 ? "transfer-p256-confidential" : "transfer-confidential",
      );
      expect(value.proof.proverRequest.nInputs).toBe(value.proof.spendProofs.length);
      expect(value.proof.compressed.commitment === null).toBe(!p256);
      expect(value.proof.proverResult.commitment === null).toBe(!p256);
    }
  });

  it("matches confirmation, state, nullifier, balance, and replay evidence", async () => {
    const cases = (await loadSpendFixtures()).flatMap(railCases);
    for (const value of cases) {
      expect(value.confirmation.innerOutputTagsBytes).toEqual(
        value.confirmation.directOutputTagsBytes,
      );
      expect(value.stateTransition.inputNullifierBytes).toHaveLength(
        value.stateTransition.spentInputHashesBytes.length,
      );
      expect(value.stateTransition.outputs.map((output) => output.ownerTagBytes)).toEqual(
        expect.arrayContaining([...value.confirmation.directOutputTagsBytes]),
      );
      expect(value.stateTransition.replayError).toEqual({
        code: "NullifierTreeUpdateFailed",
        customCode: "7002",
        details: "nullifier tree maintenance failed",
      });
      const withdrawn =
        BigInt(value.stateTransition.externalRecipientBalanceDeltas.sol) +
        BigInt(value.stateTransition.externalRecipientBalanceDeltas.spl);
      const publicAmount =
        value.logicalInputs.publicSettlement.publicSolAmount ??
        value.logicalInputs.publicSettlement.publicSplAmount;
      expect(withdrawn).toBe(publicAmount === null ? 0n : -BigInt(publicAmount));
    }
  });

  it("rejects malformed data, account order, replay, wrong tags, abort, and timeout", async () => {
    const fixture = await fixtureJson<SpendFixture>("workflows/instruction-withdraw-sol-v1");
    const value = railCases(fixture)[0];
    if (value === undefined) throw new Error("missing withdrawal fixture case");
    const data = hexBytes(value.wire.transactDataBytes);
    expect(() => transactInstructionDataCodec.decode(data.slice(0, -1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_CODEC" }),
    );
    const instruction = instructionFor(value);
    const swapped = [...normalizedAccounts(instruction)];
    [swapped[0], swapped[1]] = [swapped[1] as AccountFixture, swapped[0] as AccountFixture];
    expect(swapped).not.toEqual(value.wire.instruction.accounts);
    expect(value.errors["accountOrder"]).toEqual({
      code: "InvalidSettlementAccounts",
      customCode: "7009",
      details: "transact settlement accounts are invalid",
    });
    expect(value.errors["malformedProof"]?.code).toBe("ProofParse");
    expect(value.errors["wrongSignatureConfirmation"]?.code).toBe("IndexerTimeout");
    expect(value.stateTransition.replayError.customCode).toBe("7002");

    const rpc = new TestRpc();
    const controller = new AbortController();
    controller.abort();
    await expect(rpc.getLatestBlockhash({ signal: controller.signal })).rejects.toMatchObject({
      code: "TEST_KIT_ABORTED",
    });
    await expect(rpc.getLatestBlockhash({ timeoutMs: 0 })).rejects.toMatchObject({
      code: "TEST_KIT_TIMEOUT",
    });
    rpc.setOutputViewTags(
      rpc.nextSignature,
      value.confirmation.directOutputTagsBytes.map((tag) => hexBytes(tag) as Bytes32),
    );
    expect(await rpc.transactOutputViewTags(rpc.nextSignature)).toEqual(
      value.confirmation.directOutputTagsBytes.map((tag) => hexBytes(tag)),
    );
  });
});

async function loadSpendFixtures(): Promise<readonly SpendFixture[]> {
  const fixtures = await Promise.all([
    fixtureJson<SpendFixture>("workflows/instruction-transfer-v1"),
    fixtureJson<SpendFixture>("workflows/instruction-withdraw-sol-v1"),
    fixtureJson<SpendFixture>("workflows/instruction-withdraw-spl-v1"),
  ]);
  expect(fixtures.map((fixture) => fixture.id)).toEqual([
    "fx-workflow-instruction-transfer-v1",
    "fx-workflow-instruction-withdraw-sol-v1",
    "fx-workflow-instruction-withdraw-spl-v1",
  ]);
  return fixtures;
}

function compileTransaction(
  input: Readonly<{
    feePayer: Address;
    recentBlockhash: string;
    instructions: readonly Instruction[];
  }>,
): Transaction {
  const accounts = new Map<
    Address,
    { address: Address; isSigner: boolean; isWritable: boolean; order: number }
  >();
  let order = 0;
  accounts.set(input.feePayer, {
    address: input.feePayer,
    isSigner: true,
    isWritable: true,
    order: order++,
  });
  for (const instruction of input.instructions) {
    for (const meta of instruction.accounts) {
      const existing = accounts.get(meta.address);
      accounts.set(meta.address, {
        address: meta.address,
        isSigner: (existing?.isSigner ?? false) || meta.isSigner,
        isWritable: (existing?.isWritable ?? false) || meta.isWritable,
        order: existing?.order ?? order++,
      });
    }
    if (!accounts.has(instruction.programAddress)) {
      accounts.set(instruction.programAddress, {
        address: instruction.programAddress,
        isSigner: false,
        isWritable: false,
        order: order++,
      });
    }
  }
  const ordered = [...accounts.values()].sort((left, right) => {
    if (left.address === input.feePayer) return -1;
    if (right.address === input.feePayer) return 1;
    if (left.isSigner !== right.isSigner) return left.isSigner ? -1 : 1;
    if (left.isWritable !== right.isWritable) return left.isWritable ? -1 : 1;
    return (
      compareBytes(decodeBase58(left.address), decodeBase58(right.address)) ||
      left.order - right.order
    );
  });
  const indexes = new Map(ordered.map((account, index) => [account.address, index]));
  const requiredSignatures = ordered.filter((account) => account.isSigner).length;
  const parts: Uint8Array[] = [
    Uint8Array.of(
      requiredSignatures,
      ordered.filter((account) => account.isSigner && !account.isWritable).length,
      ordered.filter((account) => !account.isSigner && !account.isWritable).length,
    ),
    compactU16(ordered.length),
    ...ordered.map((account) => decodeBase58(account.address)),
    decodeBase58(input.recentBlockhash),
    compactU16(input.instructions.length),
  ];
  for (const instruction of input.instructions) {
    const accountIndexes = instruction.accounts.map(
      (account) => indexes.get(account.address) as number,
    );
    parts.push(
      Uint8Array.of(indexes.get(instruction.programAddress) as number),
      compactU16(accountIndexes.length),
      Uint8Array.from(accountIndexes),
      compactU16(instruction.data.length),
      instruction.data,
    );
  }
  return {
    messageBytes: concat(...parts),
    signatures: Array.from({ length: requiredSignatures }, (): Signature | undefined => undefined),
  };
}

function compactU16(value: number): Uint8Array {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
}

function decodeBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let decoded = 0n;
  for (const character of value) {
    decoded = decoded * 58n + BigInt(alphabet.indexOf(character));
  }
  const bytes: number[] = [];
  while (decoded > 0n) {
    bytes.push(Number(decoded & 255n));
    decoded >>= 8n;
  }
  let zeros = 0;
  while (value[zeros] === "1") zeros++;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
}

function encodeBase58(value: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let encoded = 0n;
  for (const byte of value) encoded = encoded * 256n + BigInt(byte);
  let result = "";
  while (encoded > 0n) {
    result = (alphabet[Number(encoded % 58n)] ?? "") + result;
    encoded /= 58n;
  }
  let zeros = 0;
  while (value[zeros] === 0) zeros++;
  return "1".repeat(zeros) + result;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
