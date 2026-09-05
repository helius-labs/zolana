import { getCreateAssociatedTokenIdempotentInstructionAsync } from "@solana-program/token";
import {
  AccountRole,
  address,
  createNoopSigner,
  type Instruction,
  type TransactionSigner,
} from "@solana/kit";

import {
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
  nullifierTreeParams,
} from "../program.js";
import type { NullifierTreeParams } from "../program.js";
import { TREE_CREATION_STEP_COUNT, defaultTreeFees } from "../state.js";
import {
  type Address,
  type AssetDeposit,
  type DepositAsset,
  type InputUtxo,
  type MergeTransactInstructionData,
  type DepositSplAccounts,
  type RingAssetDeposit,
  type TransactInstructionData,
  type TransactWithdrawal,
  type TreeFeeSchedule,
} from "../types.js";
import { Writer, addressBytes, checkedAddress, fail } from "../internal.js";
import {
  nullifierPdaAddress,
  protocolConfigAddress,
  ringAuthAddress,
  solInterfaceAddress,
  splAssetCounterAddress,
  splAssetRegistryAddress,
  splAssetVaultAddress,
  splInterfaceWithBump,
  treeAddress,
} from "../pda/index.js";
import {
  encodeCreateTreeData,
  encodeDepositInstructionData,
  encodeRingDepositInstructionData,
  encodeMergeTransactInstructionData,
  encodeTransactInstructionData,
  encodeTreeFeeSchedule,
} from "../codecs/index.js";

export const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
export type { MergeTransactInstructionData } from "../types.js";

type Meta = NonNullable<Instruction["accounts"]>[number];

export type SignerAccount = Address | TransactionSigner;

function accountAddress(account: SignerAccount): Address {
  return checkedAddress(typeof account === "string" ? account : account.address);
}

export function meta(account: SignerAccount, isSigner: boolean, isWritable: boolean): Meta {
  const address = accountAddress(account);
  return {
    address,
    role: isSigner
      ? isWritable
        ? AccountRole.WRITABLE_SIGNER
        : AccountRole.READONLY_SIGNER
      : isWritable
        ? AccountRole.WRITABLE
        : AccountRole.READONLY,
    ...(isSigner && typeof account !== "string" ? { signer: account } : {}),
  } as Meta;
}

function instruction(
  data: Uint8Array,
  accounts: readonly Meta[],
  programAddress: Address = SHIELDED_POOL_PROGRAM_ID,
): Instruction {
  return {
    programAddress: checkedAddress(programAddress, "programAddress"),
    accounts: accounts.map((account) => ({ ...account })),
    data: data.slice(),
  };
}

function tagged(tag: number, payload?: Uint8Array): Uint8Array {
  const data = new Uint8Array(1 + (payload?.length ?? 0));
  data[0] = tag;
  if (payload !== undefined) data.set(payload, 1);
  return data;
}

/// The forester's `batch_update_nullifier_tree` builder is deliberately absent.
/// Its `compressedProof` comes from the `address-append` circuit, which no
/// TypeScript path can prove: nothing here ships a forester, and producing the
/// proof needs witness generation and gnark proving rather than the hashing that
/// compiles. Publishing the builder advertised the last step of a pipeline whose
/// earlier steps are missing.

export async function createAssetCounterInstruction(
  input: Readonly<{ authority: SignerAccount }>,
): Promise<Instruction> {
  const [protocolConfig, assetCounter] = await Promise.all([
    protocolConfigAddress(),
    splAssetCounterAddress(),
  ]);
  return instruction(Uint8Array.of(InstructionTag.createAssetCounter), [
    meta(input.authority, true, true),
    meta(protocolConfig, false, false),
    meta(assetCounter, false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export function createAssociatedTokenAccountInstruction(
  input: Readonly<{
    payer: SignerAccount;
    owner: Address;
    mint: Address;
    tokenProgram?: Address | null;
  }>,
): Promise<Instruction> {
  return getCreateAssociatedTokenIdempotentInstructionAsync({
    payer: typeof input.payer === "string" ? createNoopSigner(input.payer) : input.payer,
    owner: input.owner,
    mint: input.mint,
    tokenProgram: input.tokenProgram ?? SPL_TOKEN_PROGRAM_ID,
  });
}

export async function createSplInterfaceInstruction(
  input: Readonly<{ authority: SignerAccount; mint: Address; tokenProgram?: Address | null }>,
): Promise<Instruction> {
  const tokenProgram = input.tokenProgram ?? SPL_TOKEN_PROGRAM_ID;
  const [protocolConfig, assetCounter, registry, vault] = await Promise.all([
    protocolConfigAddress(),
    splAssetCounterAddress(),
    splAssetRegistryAddress(input.mint),
    splAssetVaultAddress(input.mint),
  ]);
  return instruction(Uint8Array.of(InstructionTag.createSplInterface), [
    meta(input.authority, true, true),
    meta(protocolConfig, false, false),
    meta(assetCounter, false, true),
    meta(registry, false, true),
    meta(input.mint, false, false),
    meta(vault, false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(tokenProgram, false, false),
  ]);
}

/**
 * Mirrors Rust `CreateTree::instructions`. The tree PDA is allocated in
 * `TREE_ALLOCATION_STEP` chunks, so creation is `TREE_CREATION_STEP_COUNT`
 * identical instructions that must land in one transaction. `treeId` has to be
 * the protocol config's `nextTreeId`. `fees` defaults to the at-cost schedule
 * for the chosen ZKP batch size.
 */
export async function createTreeInstructions(
  input: Readonly<{
    payer: SignerAccount;
    authority: SignerAccount;
    treeId: number;
    nullifierTreeParams?: NullifierTreeParams;
    fees?: TreeFeeSchedule;
  }>,
): Promise<Instruction[]> {
  const nullifierParams = input.nullifierTreeParams ?? nullifierTreeParams();
  const data = tagged(
    InstructionTag.createTree,
    encodeCreateTreeData({
      treeId: input.treeId,
      nullifierParams,
      fees: input.fees ?? defaultTreeFees(nullifierParams.inputQueueZkpBatchSize),
    }),
  );
  const accounts = [
    meta(input.payer, true, true),
    meta(input.authority, true, false),
    meta(await protocolConfigAddress(), false, true),
    meta(treeAddress(input.treeId), false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ];
  return Array.from({ length: TREE_CREATION_STEP_COUNT }, () => instruction(data, accounts));
}

interface DepositLayout {
  readonly hasSol: boolean;
  readonly splGroups: readonly DepositSplAccounts[];
}

function depositLayout(deposits: readonly Readonly<{ asset: DepositAsset }>[]): DepositLayout {
  if (deposits.length === 0 || deposits.length > 0xff) {
    fail("INTERFACE_CODEC", { reason: "invalid deposit count", count: deposits.length });
  }
  let hasSol = false;
  const splGroups: DepositSplAccounts[] = [];
  for (const deposit of deposits) {
    if (deposit.asset.kind === "sol") {
      hasSol = true;
      continue;
    }
    const spl = deposit.asset.accounts;
    const existing = splGroups.find((candidate) => candidate.mint === spl.mint);
    if (
      existing !== undefined &&
      (existing.sourceTokenAccount !== spl.sourceTokenAccount ||
        existing.tokenProgram !== spl.tokenProgram)
    ) {
      fail("INTERFACE_CODEC", { reason: "conflicting SPL deposit accounts", mint: spl.mint });
    }
    if (existing === undefined) splGroups.push(spl);
  }
  if (Number(hasSol) + splGroups.length > 5) {
    fail("INTERFACE_CODEC", { reason: "too many deposit assets" });
  }
  return Object.freeze({ hasSol, splGroups: Object.freeze(splGroups) });
}

function depositAssetIndex(
  layout: DepositLayout,
  deposit: Readonly<{ asset: DepositAsset }>,
): number {
  if (deposit.asset.kind === "sol") return 0;
  const mint = deposit.asset.accounts.mint;
  const index = layout.splGroups.findIndex((candidate) => candidate.mint === mint);
  if (index < 0) fail("INTERFACE_CODEC", { reason: "missing SPL deposit group" });
  return Number(layout.hasSol) + index;
}

async function depositAccounts(
  tree: Address,
  depositor: SignerAccount,
  layout: DepositLayout,
  ringAuth?: Address,
): Promise<Readonly<{ accounts: Meta[]; splInterfaceBumps: number[] }>> {
  const accounts = [
    meta(tree, false, true),
    meta(depositor, true, true),
    // The ring program signs this account inside its CPI.
    ...(ringAuth === undefined ? [] : [meta(ringAuth, false, false)]),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ];
  if (layout.hasSol) {
    accounts.push(meta(SYSTEM_PROGRAM, false, false), meta(solInterfaceAddress(), false, true));
  }
  const splInterfaceBumps: number[] = [];
  for (const spl of layout.splGroups) {
    const [vault, bump] = await splInterfaceWithBump(spl.mint);
    splInterfaceBumps.push(bump);
    accounts.push(
      meta(spl.tokenProgram, false, false),
      meta(spl.mint, false, false),
      meta(spl.sourceTokenAccount, false, true),
      meta(vault, false, true),
    );
  }
  return Object.freeze({ accounts, splInterfaceBumps });
}

export async function depositInstruction(
  input: Readonly<{
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly AssetDeposit[];
  }>,
): Promise<Instruction> {
  const layout = depositLayout(input.deposits);
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
  );
  return instruction(
    tagged(
      InstructionTag.deposit,
      encodeDepositInstructionData({
        assets: [
          ...(layout.hasSol ? ([{ kind: "sol" }] as const) : []),
          ...splInterfaceBumps.map((splInterfaceBump) => ({
            kind: "spl" as const,
            splInterfaceBump,
          })),
        ],
        deposits: input.deposits.map((deposit) => ({
          assetIndex: depositAssetIndex(layout, deposit),
          viewTag: deposit.viewTag,
          recipientOwnerHash: deposit.recipientOwnerHash,
          amount: deposit.amount,
          ...(deposit.utxoData === undefined ? {} : { utxoData: deposit.utxoData }),
          ...(deposit.memo === undefined ? {} : { memo: deposit.memo }),
        })),
      }),
    ),
    accounts,
  );
}

/** Mirrors Rust `RingDeposit::instruction`. The ring program forwards it to the shielded pool unchanged. */
export async function ringDepositInstruction(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
  }>,
): Promise<Instruction> {
  const layout = depositLayout(input.deposits);
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
    await ringAuthAddress(input.ringProgramId),
  );
  return instruction(
    tagged(
      InstructionTag.ringDeposit,
      encodeRingDepositInstructionData({
        assets: [
          ...(layout.hasSol ? ([{ kind: "sol" }] as const) : []),
          ...splInterfaceBumps.map((splInterfaceBump) => ({
            kind: "spl" as const,
            splInterfaceBump,
          })),
        ],
        deposits: input.deposits.map((deposit) => ({
          assetIndex: depositAssetIndex(layout, deposit),
          viewTag: deposit.viewTag,
          ownerUtxoHash: deposit.ownerUtxoHash,
          amount: deposit.amount,
          ...(deposit.dataHash === undefined ? {} : { dataHash: deposit.dataHash }),
          ringDataHash: deposit.ringDataHash,
          encrypted: deposit.encrypted,
        })),
      }),
    ),
    accounts,
    input.ringProgramId,
  );
}

function settlementAccounts(withdrawal?: TransactWithdrawal): Meta[] {
  if (withdrawal === undefined) return [];
  if (withdrawal.kind === "sol") {
    return [meta(SOL_INTERFACE, false, true), meta(withdrawal.recipient, false, true)];
  }
  return [
    meta(SHIELDED_POOL_CPI_AUTHORITY, false, false),
    meta(withdrawal.mint, false, false),
    meta(withdrawal.splTokenInterface, false, true),
    meta(withdrawal.recipientTokenAccount, false, true),
    meta(withdrawal.tokenProgram, false, false),
  ];
}

/**
 * One writable nullifier PDA per nullifier, preserving input order.
 */
export async function nullifierPdaAccounts(
  inputTree: Address,
  nullifiers: readonly Uint8Array[],
): Promise<Meta[]> {
  const nullifierPdas = await Promise.all(
    nullifiers.map((nullifier) => nullifierPdaAddress(inputTree, nullifier)),
  );
  return nullifierPdas.map((pda) => meta(pda, false, true));
}

async function transactAccounts(
  payer: SignerAccount,
  inputTree: Address,
  outputTree: Address,
  inputs: readonly InputUtxo[],
  withdrawal?: TransactWithdrawal,
): Promise<Meta[]> {
  const accounts = [
    meta(payer, true, true),
    meta(inputTree, false, true),
    meta(outputTree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    meta(SYSTEM_PROGRAM, false, false),
    ...(await nullifierPdaAccounts(
      inputTree,
      inputs.map((input) => input.nullifierHash),
    )),
  ];
  accounts.push(...settlementAccounts(withdrawal));
  return accounts;
}

export async function transactInstruction(
  input: Readonly<{
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
  }>,
): Promise<Instruction> {
  return instruction(
    tagged(InstructionTag.transact, encodeTransactInstructionData(input.data)),
    await transactAccounts(
      input.payer,
      input.inputTree,
      input.outputTree,
      input.data.inputs,
      input.withdrawal,
    ),
  );
}

/**
 * Mirrors Rust `RingTransact::instruction`. `ringAuth` is unsigned here, the ring
 * program signs it inside its CPI. `inputs` are the payload's spent inputs; their
 * nullifier PDAs follow `ringAuth`.
 */
export async function ringTransactAccounts(
  input: Readonly<{
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    ringAuth: Address;
    inputs: readonly InputUtxo[];
    ownerSigners?: readonly SignerAccount[];
    withdrawal?: TransactWithdrawal;
  }>,
): Promise<readonly Meta[]> {
  return [
    meta(input.payer, true, true),
    meta(input.inputTree, false, true),
    meta(input.outputTree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    meta(SYSTEM_PROGRAM, false, false),
    meta(input.ringAuth, false, false),
    ...(await nullifierPdaAccounts(
      input.inputTree,
      input.inputs.map((spentInput) => spentInput.nullifierHash),
    )),
    ...(input.ownerSigners ?? []).map((signer) => meta(signer, true, false)),
    ...settlementAccounts(input.withdrawal),
  ];
}

export async function createProtocolConfigInstruction(
  input: Readonly<{
    authority: SignerAccount;
    protocolAuthority: Address;
    treeCreationAuthority: Address;
    treeCreationIsPermissionless: boolean;
    foresterAuthority: Address;
    ringCreationAuthority: Address;
    ringCreationIsPermissionless: boolean;
    splInterfaceCreationIsPermissionless: boolean;
    feeAuthority: Address;
  }>,
): Promise<Instruction> {
  const payload = new Writer()
    .bytes(addressBytes(input.protocolAuthority, "protocolAuthority"))
    .bytes(addressBytes(input.treeCreationAuthority, "treeCreationAuthority"))
    .bool(input.treeCreationIsPermissionless, "treeCreationIsPermissionless")
    .bytes(addressBytes(input.foresterAuthority, "foresterAuthority"))
    .bytes(addressBytes(input.ringCreationAuthority, "ringCreationAuthority"))
    .bool(input.ringCreationIsPermissionless, "ringCreationIsPermissionless")
    .bool(input.splInterfaceCreationIsPermissionless, "splInterfaceCreationIsPermissionless")
    .bytes(addressBytes(input.feeAuthority, "feeAuthority"))
    .finish();
  return instruction(tagged(InstructionTag.createProtocolConfig, payload), [
    meta(input.authority, true, true),
    meta(await protocolConfigAddress(), false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export type ProtocolConfigUpdate =
  | Readonly<{ field: "protocolAuthority"; value: SignerAccount }>
  | Readonly<{ field: "treeCreationAuthority"; value: Address }>
  | Readonly<{ field: "foresterAuthority"; value: Address }>
  | Readonly<{ field: "ringCreationAuthority"; value: Address }>
  | Readonly<{ field: "treeCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "ringCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "splInterfaceCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "feeAuthority"; value: Address }>;

export async function updateProtocolConfigInstruction(
  input: Readonly<{ authority: SignerAccount; update: ProtocolConfigUpdate }>,
): Promise<Instruction> {
  const writer = new Writer();
  let newAuthority: SignerAccount | undefined;
  switch (input.update.field) {
    case "protocolAuthority":
      writer.u8(0, "update.field").bytes(addressBytes(accountAddress(input.update.value)));
      newAuthority = input.update.value;
      break;
    case "treeCreationAuthority":
      writer.u8(1, "update.field").bytes(addressBytes(input.update.value));
      break;
    case "foresterAuthority":
      writer.u8(2, "update.field").bytes(addressBytes(input.update.value));
      break;
    case "ringCreationAuthority":
      writer.u8(3, "update.field").bytes(addressBytes(input.update.value));
      break;
    case "treeCreationPermissionless":
      writer.u8(4, "update.field").bool(input.update.value, "update.value");
      break;
    case "ringCreationPermissionless":
      writer.u8(5, "update.field").bool(input.update.value, "update.value");
      break;
    case "splInterfaceCreationPermissionless":
      writer.u8(6, "update.field").bool(input.update.value, "update.value");
      break;
    case "feeAuthority":
      writer.u8(7, "update.field").bytes(addressBytes(input.update.value));
      break;
    default:
      fail("INTERFACE_CODEC", { name: "update.field" });
  }
  const accounts = [
    meta(input.authority, true, false),
    meta(await protocolConfigAddress(), false, true),
  ];
  if (newAuthority !== undefined) accounts.push(meta(newAuthority, true, false));
  return instruction(tagged(InstructionTag.updateProtocolConfig, writer.finish()), accounts);
}

export async function pauseTreeInstruction(
  input: Readonly<{ authority: SignerAccount; tree: Address; paused: boolean }>,
): Promise<Instruction> {
  return instruction(
    tagged(InstructionTag.pauseTree, new Writer().bool(input.paused, "paused").finish()),
    [
      meta(input.authority, true, false),
      meta(await protocolConfigAddress(), false, true),
      meta(input.tree, false, true),
    ],
  );
}

/** Mirrors Rust `SetTreeFees::instruction`. The authority must be the config's fee authority. */
export async function setTreeFeesInstruction(
  input: Readonly<{ authority: SignerAccount; tree: Address; fees: TreeFeeSchedule }>,
): Promise<Instruction> {
  return instruction(tagged(InstructionTag.setTreeFees, encodeTreeFeeSchedule(input.fees)), [
    meta(input.authority, true, false),
    meta(await protocolConfigAddress(), false, false),
    meta(input.tree, false, true),
  ]);
}

/**
 * Mirrors Rust `MergeTransact::instruction`: one nullifier PDA per declared nullifier follows
 * the pool program, so the account list widens with the shape (8 or 36 inputs, see
 * `MERGE_SUPPORTED_INPUT_COUNTS`).
 *
 * Compute budget: no merge fits the 200,000 CU per-instruction default. Prepend a
 * `SetComputeUnitLimit` instruction. Measured on LiteSVM (2026-09): 8 inputs consume
 * 193,000-212,000 CU (suggested limit 400,000), 36 inputs consume 406,000-446,000 CU (suggested
 * limit 800,000). The cost is a range because each nullifier PDA is derived with a canonical bump
 * search whose iteration count depends on the nullifier. This builder returns only the merge
 * instruction, so the caller controls the returned instruction list.
 */
export async function mergeTransactInstruction(
  input: Readonly<{
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    userRecord: Address;
    data: MergeTransactInstructionData;
  }>,
): Promise<Instruction> {
  return instruction(
    tagged(InstructionTag.mergeTransact, encodeMergeTransactInstructionData(input.data)),
    [
      meta(input.inputTree, false, true),
      meta(input.outputTree, false, true),
      meta(input.payer, true, true),
      meta(input.userRecord, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
      ...(await nullifierPdaAccounts(input.inputTree, input.data.nullifiers)),
    ],
  );
}
