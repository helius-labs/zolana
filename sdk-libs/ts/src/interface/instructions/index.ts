import { getCreateAssociatedTokenIdempotentInstructionAsync } from "@solana-program/token";
import { AccountRole, address, type Instruction, type TransactionSigner } from "@solana/kit";

import {
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
} from "../program.js";
import type { AddressTreeParams } from "../program.js";
import {
  type Address,
  type MergeTransactInstructionData,
  type ZoneDepositInstructionData,
  type Bytes31,
  type Bytes32,
  type DepositInstructionData,
  type DepositSplAccounts,
  type TransactInstructionData,
  type TransactWithdrawal,
} from "../types.js";
import { Writer, addressBytes, checkedAddress, fail } from "../internal.js";
import {
  protocolConfigAddress,
  solInterfaceAddress,
  splAssetCounterAddress,
  splAssetRegistryAddress,
  splAssetVaultAddress,
  zoneAuthAddress,
} from "../pda/index.js";
import {
  encodeAddressTreeParams,
  encodeCreateZoneConfigData,
  encodeDepositInstructionData,
  encodeMergeTransactInstructionData,
  encodeMergeZoneInstructionData,
  encodeTransactInstructionData,
  encodeUpdateZoneConfigData,
  encodeUpdateZoneConfigOwnerData,
  encodeZoneDepositInstructionData,
} from "../codecs/index.js";

const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
export type { MergeTransactInstructionData } from "../types.js";

type Meta = NonNullable<Instruction["accounts"]>[number];

export type SignerAccount = Address | TransactionSigner;

function accountAddress(account: SignerAccount): Address {
  return checkedAddress(typeof account === "string" ? account : account.address);
}

function meta(account: SignerAccount, isSigner: boolean, isWritable: boolean): Meta {
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
  input: Readonly<{ payer: TransactionSigner; owner: Address; mint: Address }>,
): Promise<Instruction> {
  return getCreateAssociatedTokenIdempotentInstructionAsync(input);
}

export async function createSplInterfaceInstruction(
  input: Readonly<{ authority: SignerAccount; mint: Address }>,
): Promise<Instruction> {
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
    meta(SPL_TOKEN_PROGRAM_ID, false, false),
  ]);
}

export async function createTreeInstruction(
  input: Readonly<{
    authority: SignerAccount;
    tree: Address;
    nullifierTreeParams?: AddressTreeParams;
  }>,
): Promise<Instruction> {
  const payload =
    input.nullifierTreeParams === undefined
      ? undefined
      : encodeAddressTreeParams(input.nullifierTreeParams);
  return instruction(tagged(InstructionTag.createTree, payload), [
    meta(input.authority, true, false),
    meta(await protocolConfigAddress(), false, false),
    meta(input.tree, false, true),
  ]);
}

function depositAccounts(
  tree: Address,
  depositor: SignerAccount,
  spl?: DepositSplAccounts,
  zoneAuthority?: Readonly<{ address: Address; signer: boolean }>,
): Meta[] {
  const accounts = [meta(tree, false, true), meta(depositor, true, true)];
  if (zoneAuthority !== undefined) {
    accounts.push(meta(zoneAuthority.address, zoneAuthority.signer, false));
  }
  if (spl === undefined) {
    accounts.push(
      meta(SYSTEM_PROGRAM, false, false),
      meta(solInterfaceAddress(), false, true),
      meta(depositor, false, true),
    );
  } else {
    accounts.push(
      meta(spl.userToken, false, true),
      meta(spl.splTokenInterface, false, true),
      meta(spl.registry, false, false),
      meta(spl.tokenProgram, false, false),
    );
  }
  accounts.push(meta(SHIELDED_POOL_PROGRAM_ID, false, false));
  return accounts;
}

export function depositInstruction(
  input: Readonly<{
    tree: Address;
    depositor: SignerAccount;
    spl?: DepositSplAccounts;
    data: DepositInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.deposit, encodeDepositInstructionData(input.data)),
    depositAccounts(input.tree, input.depositor, input.spl),
  );
}

function settlementAccounts(withdrawal?: TransactWithdrawal): Meta[] {
  if (withdrawal === undefined) return [];
  if (withdrawal.kind === "sol") {
    return [meta(SOL_INTERFACE, false, true), meta(withdrawal.recipient, false, true)];
  }
  const accounts: Meta[] = [];
  if (withdrawal.cpiAuthority !== undefined) {
    accounts.push(meta(withdrawal.cpiAuthority, false, false));
  }
  accounts.push(
    meta(withdrawal.splTokenInterface, false, true),
    meta(withdrawal.recipient, false, true),
    meta(withdrawal.userTokenAccount, false, true),
    meta(withdrawal.tokenProgram, false, false),
  );
  return accounts;
}

function transactAccounts(
  payer: SignerAccount,
  tree: Address,
  withdrawal?: TransactWithdrawal,
  zoneAuthority?: Readonly<{ address: Address; signer: boolean }>,
): Meta[] {
  const accounts = [meta(payer, true, true), meta(tree, false, true)];
  if (zoneAuthority !== undefined) {
    accounts.push(meta(zoneAuthority.address, zoneAuthority.signer, false));
  }
  accounts.push(...settlementAccounts(withdrawal));
  // System program for the forester-fee collection CPI and, on the native SOL
  // rail, public settlement.
  accounts.push(meta(SYSTEM_PROGRAM, false, false));
  accounts.push(meta(SHIELDED_POOL_PROGRAM_ID, false, false));
  return accounts;
}

export function transactInstruction(
  input: Readonly<{
    payer: SignerAccount;
    tree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.transact, encodeTransactInstructionData(input.data)),
    transactAccounts(input.payer, input.tree, input.withdrawal),
  );
}

export async function createProtocolConfigInstruction(
  input: Readonly<{
    authority: SignerAccount;
    protocolAuthority: Address;
    treeCreationAuthority: Address;
    treeCreationIsPermissionless: boolean;
    foresterAuthority: Address;
    zoneCreationAuthority: Address;
    zoneCreationIsPermissionless: boolean;
    splInterfaceCreationIsPermissionless: boolean;
  }>,
): Promise<Instruction> {
  const payload = new Writer()
    .bytes(addressBytes(input.protocolAuthority, "protocolAuthority"))
    .bytes(addressBytes(input.treeCreationAuthority, "treeCreationAuthority"))
    .bool(input.treeCreationIsPermissionless, "treeCreationIsPermissionless")
    .bytes(addressBytes(input.foresterAuthority, "foresterAuthority"))
    .bytes(addressBytes(input.zoneCreationAuthority, "zoneCreationAuthority"))
    .bool(input.zoneCreationIsPermissionless, "zoneCreationIsPermissionless")
    .bool(input.splInterfaceCreationIsPermissionless, "splInterfaceCreationIsPermissionless")
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
  | Readonly<{ field: "zoneCreationAuthority"; value: Address }>
  | Readonly<{ field: "treeCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "zoneCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "splInterfaceCreationPermissionless"; value: boolean }>;

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
    case "zoneCreationAuthority":
      writer.u8(3, "update.field").bytes(addressBytes(input.update.value));
      break;
    case "treeCreationPermissionless":
      writer.u8(4, "update.field").bool(input.update.value, "update.value");
      break;
    case "zoneCreationPermissionless":
      writer.u8(5, "update.field").bool(input.update.value, "update.value");
      break;
    case "splInterfaceCreationPermissionless":
      writer.u8(6, "update.field").bool(input.update.value, "update.value");
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

export async function createZoneConfigInstruction(
  input: Readonly<{
    payer: SignerAccount;
    programId: Address;
    authority: Address;
    zoneAuthorityTransactIsEnabled: boolean;
  }>,
): Promise<Instruction> {
  const [[zoneAuthority], protocolConfig] = await Promise.all([
    zoneAuthAddress(input.programId),
    protocolConfigAddress(),
  ]);
  const payload = encodeCreateZoneConfigData(input);
  return instruction(tagged(InstructionTag.createZoneConfig, payload), [
    meta(input.payer, true, true),
    meta(protocolConfig, false, false),
    meta(zoneAuthority, true, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export function updateZoneConfigInstruction(
  input: Readonly<{
    authority: SignerAccount;
    zoneConfig: Address;
    zoneAuthorityTransactIsEnabled: boolean;
  }>,
): Instruction {
  return instruction(tagged(InstructionTag.updateZoneConfig, encodeUpdateZoneConfigData(input)), [
    meta(input.authority, true, false),
    meta(input.zoneConfig, false, true),
  ]);
}

export function updateZoneConfigOwnerInstruction(
  input: Readonly<{
    authority: SignerAccount;
    zoneConfig: Address;
    newAuthority: SignerAccount;
  }>,
): Instruction {
  return instruction(
    tagged(
      InstructionTag.updateZoneConfigOwner,
      encodeUpdateZoneConfigOwnerData({ newAuthority: accountAddress(input.newAuthority) }),
    ),
    [
      meta(input.authority, true, false),
      meta(input.zoneConfig, false, true),
      meta(input.newAuthority, true, false),
    ],
  );
}

export async function zoneDepositInstruction(
  input: Readonly<{
    tree: Address;
    depositor: SignerAccount;
    spl?: DepositSplAccounts;
    viewTag: Bytes32;
    owner: Bytes32;
    blinding: Bytes31;
    amount: bigint;
    zoneProgramId: Address;
    zoneDataHash: Bytes32;
    zoneData: Uint8Array;
    utxoData?: Readonly<{ dataHash: Bytes32; data: Uint8Array }>;
    memo?: Uint8Array;
    cpi?: boolean;
  }>,
): Promise<Instruction> {
  const [zoneAuthority] = await zoneAuthAddress(input.zoneProgramId);
  const data: ZoneDepositInstructionData = input;
  return instruction(
    tagged(InstructionTag.zoneDeposit, encodeZoneDepositInstructionData(data)),
    depositAccounts(input.tree, input.depositor, input.spl, {
      address: zoneAuthority,
      signer: input.cpi === true,
    }),
    input.cpi === true ? SHIELDED_POOL_PROGRAM_ID : input.zoneProgramId,
  );
}

type ZoneTransactInput = Readonly<{
  payer: SignerAccount;
  tree: Address;
  zoneProgramId: Address;
  withdrawal?: TransactWithdrawal;
  data: TransactInstructionData;
  cpi?: boolean;
}>;

async function buildZoneTransact(tag: number, input: ZoneTransactInput): Promise<Instruction> {
  const [zoneAuthority] = await zoneAuthAddress(input.zoneProgramId);
  return instruction(
    tagged(tag, encodeTransactInstructionData(input.data)),
    transactAccounts(input.payer, input.tree, input.withdrawal, {
      address: zoneAuthority,
      signer: input.cpi === true,
    }),
    input.cpi === true ? SHIELDED_POOL_PROGRAM_ID : input.zoneProgramId,
  );
}

export function zoneTransactInstruction(
  input: Readonly<{
    payer: SignerAccount;
    tree: Address;
    zoneProgramId: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    cpi?: boolean;
  }>,
): Promise<Instruction> {
  return buildZoneTransact(InstructionTag.zoneTransact, input);
}

export function zoneAuthorityTransactInstruction(
  input: Readonly<{
    payer: SignerAccount;
    tree: Address;
    zoneProgramId: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    cpi?: boolean;
  }>,
): Promise<Instruction> {
  return buildZoneTransact(InstructionTag.zoneAuthorityTransact, input);
}

export function mergeTransactInstruction(
  input: Readonly<{
    tree: Address;
    payer: SignerAccount;
    userRecord: Address;
    data: MergeTransactInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.mergeTransact, encodeMergeTransactInstructionData(input.data)),
    [
      meta(input.tree, false, true),
      meta(input.payer, true, true),
      meta(input.userRecord, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
  );
}

export async function mergeZoneInstruction(
  input: Readonly<{
    tree: Address;
    zoneProgramId: Address;
    payer: SignerAccount;
    data: MergeTransactInstructionData;
    mergeViewTag: Bytes32;
    cpi?: boolean;
  }>,
): Promise<Instruction> {
  const [authority] = await zoneAuthAddress(input.zoneProgramId);
  return instruction(
    tagged(
      InstructionTag.zoneMergeTransact,
      encodeMergeZoneInstructionData({
        mergeViewTag: input.mergeViewTag,
        merge: input.data,
      }),
    ),
    [
      meta(input.tree, false, true),
      meta(authority, input.cpi === true, false),
      meta(input.payer, true, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
    input.cpi === true ? SHIELDED_POOL_PROGRAM_ID : input.zoneProgramId,
  );
}
