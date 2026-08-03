import { getCreateAssociatedTokenIdempotentInstructionAsync } from "@solana-program/token";
import { AccountRole, address, type Instruction, type TransactionSigner } from "@solana/kit";

import {
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
} from "../program.js";
import type { AddressTreeParams } from "../program.js";
import {
  type Address,
  type AssetDeposit,
  type MergeTransactInstructionData,
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
  splAssetVaultPda,
} from "../pda/index.js";
import {
  encodeAddressTreeParams,
  encodeDepositInstructionData,
  encodeMergeTransactInstructionData,
  encodeTransactInstructionData,
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
  input: Readonly<{
    payer: TransactionSigner;
    owner: Address;
    mint: Address;
    tokenProgram?: Address | null;
  }>,
): Promise<Instruction> {
  return getCreateAssociatedTokenIdempotentInstructionAsync({
    payer: input.payer,
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

interface DepositLayout {
  readonly hasSol: boolean;
  readonly splGroups: readonly DepositSplAccounts[];
}

function depositLayout(deposits: readonly AssetDeposit[]): DepositLayout {
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
      (existing.userToken !== spl.userToken || existing.tokenProgram !== spl.tokenProgram)
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

function depositAssetIndex(layout: DepositLayout, deposit: AssetDeposit): number {
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
): Promise<Readonly<{ accounts: Meta[]; vaultBumps: number[] }>> {
  const accounts = [
    meta(tree, false, true),
    meta(depositor, true, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ];
  if (layout.hasSol) {
    accounts.push(meta(SYSTEM_PROGRAM, false, false), meta(solInterfaceAddress(), false, true));
  }
  const vaultBumps: number[] = [];
  for (const spl of layout.splGroups) {
    const [vault, bump] = await splAssetVaultPda(spl.mint);
    vaultBumps.push(bump);
    accounts.push(
      meta(spl.tokenProgram, false, false),
      meta(spl.mint, false, false),
      meta(spl.userToken, false, true),
      meta(vault, false, true),
    );
  }
  return Object.freeze({ accounts, vaultBumps });
}

export async function depositInstruction(
  input: Readonly<{
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly AssetDeposit[];
  }>,
): Promise<Instruction> {
  const layout = depositLayout(input.deposits);
  const { accounts, vaultBumps } = await depositAccounts(input.tree, input.depositor, layout);
  return instruction(
    tagged(
      InstructionTag.deposit,
      encodeDepositInstructionData({
        assets: [
          ...(layout.hasSol ? ([{ kind: "sol" }] as const) : []),
          ...vaultBumps.map((vaultBump) => ({ kind: "spl" as const, vaultBump })),
        ],
        deposits: input.deposits.map((deposit) => ({
          assetIndex: depositAssetIndex(layout, deposit),
          viewTag: deposit.viewTag,
          owner: deposit.owner,
          blinding: deposit.blinding,
          amount: deposit.amount,
          ...(deposit.utxoData === undefined ? {} : { utxoData: deposit.utxoData }),
          ...(deposit.memo === undefined ? {} : { memo: deposit.memo }),
        })),
      }),
    ),
    accounts,
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
    meta(withdrawal.userTokenAccount, false, true),
    meta(withdrawal.tokenProgram, false, false),
  ];
}

function transactAccounts(
  payer: SignerAccount,
  inputTree: Address,
  outputTree: Address,
  withdrawal?: TransactWithdrawal,
): Meta[] {
  const accounts = [
    meta(payer, true, true),
    meta(inputTree, false, true),
    meta(outputTree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    meta(SYSTEM_PROGRAM, false, false),
  ];
  accounts.push(...settlementAccounts(withdrawal));
  return accounts;
}

export function transactInstruction(
  input: Readonly<{
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.transact, encodeTransactInstructionData(input.data)),
    transactAccounts(input.payer, input.inputTree, input.outputTree, input.withdrawal),
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

export function mergeTransactInstruction(
  input: Readonly<{
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    userRecord: Address;
    data: MergeTransactInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.mergeTransact, encodeMergeTransactInstructionData(input.data)),
    [
      meta(input.inputTree, false, true),
      meta(input.outputTree, false, true),
      meta(input.payer, true, true),
      meta(input.userRecord, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
  );
}
