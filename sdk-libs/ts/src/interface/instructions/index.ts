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
  type CircuitId,
  type CreateCacheData,
  type DepositAsset,
  type InputUtxo,
  type MergeTransactInstructionData,
  type DepositSplAccounts,
  type TransactInstructionData,
  type TreeContext,
  type TransactWithdrawal,
  type TreeFeeSchedule,
} from "../types.js";
import { writesCache } from "../cache.js";
import { Writer, addressBytes, checkedAddress, fail } from "../internal.js";
import {
  cacheAddress,
  nullifierPdaAddress,
  protocolConfigAddress,
  ringSpendWindowAddress,
  solInterfaceAddress,
  splAssetCounterAddress,
  splAssetRegistryAddress,
  splAssetVaultAddress,
  splInterfaceWithBump,
  treeAddress,
} from "../pda/index.js";
import {
  encodeCreateCacheData,
  encodeCreateTreeData,
  encodeDepositInstructionData,
  encodeMergeTransactInstructionData,
  encodeTransactInstructionData,
  encodeTreeFeeSchedule,
} from "../codecs/index.js";

export const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
export type { MergeTransactInstructionData } from "../types.js";

type Meta = NonNullable<Instruction["accounts"]>[number];

export type SignerAccount = Address | TransactionSigner;

export interface CacheWriteAccounts {
  readonly cache: Address;
  readonly writer: SignerAccount;
}

export interface TransactCacheAccounts {
  readonly readCache?: Address;
  readonly writeCache?: CacheWriteAccounts;
}

export const TransactCacheAccounts = Object.freeze({
  read(cache: Address): TransactCacheAccounts {
    return Object.freeze({ readCache: cache });
  },
  write(input: CacheWriteAccounts): TransactCacheAccounts {
    return Object.freeze({
      writeCache: Object.freeze({ cache: input.cache, writer: input.writer }),
    });
  },
  readAndWrite(readCache: Address, write: CacheWriteAccounts): TransactCacheAccounts {
    return Object.freeze({
      readCache,
      writeCache: Object.freeze({ cache: write.cache, writer: write.writer }),
    });
  },
});

export function signerAddress(account: SignerAccount): Address {
  return checkedAddress(typeof account === "string" ? account : account.address);
}

export function meta(account: SignerAccount, isSigner: boolean, isWritable: boolean): Meta {
  const address = signerAddress(account);
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

export function instruction(
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

export function tagged(tag: number, payload?: Uint8Array): Uint8Array {
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

export function depositLayout(
  deposits: readonly Readonly<{ asset: DepositAsset }>[],
): DepositLayout {
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

export function depositAssetIndex(
  layout: DepositLayout,
  deposit: Readonly<{ asset: DepositAsset }>,
): number {
  if (deposit.asset.kind === "sol") return 0;
  const mint = deposit.asset.accounts.mint;
  const index = layout.splGroups.findIndex((candidate) => candidate.mint === mint);
  if (index < 0) fail("INTERFACE_CODEC", { reason: "missing SPL deposit group" });
  return Number(layout.hasSol) + index;
}

export async function depositAccounts(
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

/** An unset co-signer repeats the PDA, the message signer flag comes from the address. */
export function ringCoSignerMetas(
  cosignerPda: Address,
  cosigner: SignerAccount | undefined,
): Meta[] {
  return [
    meta(cosignerPda, false, false),
    cosigner === undefined ? meta(cosignerPda, false, false) : meta(cosigner, true, false),
  ];
}

/** One writable spend window slot per public leg, in leg order. */
export async function ringSpendWindowMetas(
  ringProgramId: Address,
  mints: readonly Address[],
): Promise<Meta[]> {
  const windows = await Promise.all(
    mints.map((mint) => ringSpendWindowAddress(ringProgramId, mint)),
  );
  return windows.map((window) => meta(window, false, true));
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

function validateSingleInputTree(
  inputs: readonly InputUtxo[],
  treeContexts: readonly TreeContext[],
): void {
  if (treeContexts.length !== 1 || inputs.some((input) => input.treeIndex !== 0)) {
    fail("INTERFACE_INVALID_SHAPE", {
      reason: "single-tree builder requires one tree context and tree index zero for every input",
    });
  }
}

function cacheWriteAccountMetas(accounts: CacheWriteAccounts): Meta[] {
  return [meta(accounts.cache, false, true), meta(accounts.writer, true, false)];
}

function cacheAccountMetas(cache: TransactCacheAccounts | undefined): Meta[] {
  if (cache === undefined) return [];
  return [
    ...(cache.readCache === undefined ? [] : [meta(cache.readCache, false, false)]),
    ...(cache.writeCache === undefined ? [] : cacheWriteAccountMetas(cache.writeCache)),
  ];
}

function cacheRoles(reads: boolean, writes: boolean): string {
  return reads ? (writes ? "readAndWrite" : "read") : writes ? "write" : "none";
}

export function checkTransactCacheAccounts(
  circuit: CircuitId,
  cache: TransactCacheAccounts | undefined,
): void {
  const access =
    circuit.kind === "confidentialEddsaCached" || circuit.kind === "ringEddsaCached"
      ? circuit.cacheAccess
      : undefined;
  const expected = cacheRoles(
    access !== undefined && access.readBitmap !== 0n,
    access !== undefined && writesCache(access),
  );
  const actual = cacheRoles(cache?.readCache !== undefined, cache?.writeCache !== undefined);
  if (actual !== expected) {
    fail("INTERFACE_INVALID_SHAPE", { name: "cache", expected, actual });
  }
}

async function transactAccounts(
  payer: SignerAccount,
  inputTree: Address,
  outputTree: Address,
  inputs: readonly InputUtxo[],
  treeContexts: readonly TreeContext[],
  withdrawal?: TransactWithdrawal,
  cache?: TransactCacheAccounts,
): Promise<Meta[]> {
  validateSingleInputTree(inputs, treeContexts);
  const accounts = [
    meta(payer, true, true),
    meta(outputTree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    meta(SYSTEM_PROGRAM, false, false),
    meta(inputTree, false, true),
    ...(await nullifierPdaAccounts(
      inputTree,
      inputs.map((input) => input.nullifierHash),
    )),
  ];
  accounts.push(...settlementAccounts(withdrawal), ...cacheAccountMetas(cache));
  return accounts;
}

export async function transactInstruction(
  input: Readonly<{
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    withdrawal?: TransactWithdrawal;
    cache?: TransactCacheAccounts;
    data: TransactInstructionData;
  }>,
): Promise<Instruction> {
  checkTransactCacheAccounts(input.data.circuit, input.cache);
  return instruction(
    tagged(InstructionTag.transact, encodeTransactInstructionData(input.data)),
    await transactAccounts(
      input.payer,
      input.inputTree,
      input.outputTree,
      input.data.inputs,
      input.data.treeContexts,
      input.withdrawal,
      input.cache,
    ),
  );
}

/**
 * Mirrors Rust `RingTransact::instruction`. `ringAuth` is unsigned here, the ring
 * program signs it inside its CPI. `inputs` are the payload's spent inputs. The
 * input trees, then one nullifier PDA per input under its own tree, follow the
 * fixed prefix ending in `ringAuth`.
 */
export async function ringTransactAccounts(
  input: Readonly<{
    payer: SignerAccount;
    /** One per tree context, in context order. */
    inputTrees: readonly Address[];
    outputTree: Address;
    ringAuth: Address;
    inputs: readonly InputUtxo[];
    treeContexts: readonly TreeContext[];
    ownerSigners?: readonly SignerAccount[];
    withdrawal?: TransactWithdrawal;
    cache?: TransactCacheAccounts;
  }>,
): Promise<readonly Meta[]> {
  if (
    input.inputTrees.length !== input.treeContexts.length ||
    input.inputTrees.length === 0 ||
    new Set(input.inputTrees).size !== input.inputTrees.length
  ) {
    fail("INTERFACE_INVALID_SHAPE", {
      reason: "one distinct input tree per tree context",
    });
  }
  const nullifierPdas = await Promise.all(
    input.inputs.map((spent) => {
      const tree = input.inputTrees[spent.treeIndex];
      if (tree === undefined) {
        fail("INTERFACE_INVALID_SHAPE", { reason: "input tree index outside the tree contexts" });
      }
      return nullifierPdaAddress(tree, spent.nullifierHash);
    }),
  );
  return [
    meta(input.payer, true, true),
    meta(input.outputTree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    meta(SYSTEM_PROGRAM, false, false),
    meta(input.ringAuth, false, false),
    ...input.inputTrees.map((tree) => meta(tree, false, true)),
    ...nullifierPdas.map((pda) => meta(pda, false, true)),
    ...(input.ownerSigners ?? []).map((signer) => meta(signer, true, false)),
    ...settlementAccounts(input.withdrawal),
    ...cacheAccountMetas(input.cache),
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
    ringActivationIsPermissionless: boolean;
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
    .bool(input.ringActivationIsPermissionless, "ringActivationIsPermissionless")
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
  | Readonly<{ field: "ringActivationPermissionless"; value: boolean }>
  | Readonly<{ field: "splInterfaceCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "feeAuthority"; value: Address }>;

export async function updateProtocolConfigInstruction(
  input: Readonly<{ authority: SignerAccount; update: ProtocolConfigUpdate }>,
): Promise<Instruction> {
  const writer = new Writer();
  let newAuthority: SignerAccount | undefined;
  switch (input.update.field) {
    case "protocolAuthority":
      writer.u8(0, "update.field").bytes(addressBytes(signerAddress(input.update.value)));
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
    case "ringActivationPermissionless":
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

/**
 * Mirrors Rust `SetRingActivation::instruction`. Governance admits a ring, or
 * contains one it no longer trusts, and owns the authority-transact rail for
 * the ring's whole life. The authority must be the config's ring creation
 * authority. This never touches the ring's own `paused` flag.
 *
 * Ring creation is permissionless and lands inert on a permissioned pool, so
 * this is the second of the two transactions that bring a ring up. The pool is
 * called directly, which is what keeps a governance signature out of the
 * candidate ring program's call chain.
 */
export async function setRingActivationInstruction(
  input: Readonly<{
    authority: SignerAccount;
    ringConfig: Address;
    activated: boolean;
    ringAuthorityTransactIsEnabled: boolean;
  }>,
): Promise<Instruction> {
  return instruction(
    tagged(
      InstructionTag.setRingActivation,
      new Writer()
        .bool(input.activated, "activated")
        .bool(input.ringAuthorityTransactIsEnabled, "ringAuthorityTransactIsEnabled")
        .finish(),
    ),
    [
      meta(input.authority, true, false),
      meta(await protocolConfigAddress(), false, false),
      meta(input.ringConfig, false, true),
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

/** Mirrors Rust `MergeTransact::instruction`: the eight nullifier PDAs follow the pool program. */
export async function mergeTransactInstruction(
  input: Readonly<{
    inputTree: Address;
    outputTree: Address;
    payer: SignerAccount;
    userRecord: Address;
    cache?: CacheWriteAccounts;
    data: MergeTransactInstructionData;
  }>,
): Promise<Instruction> {
  if ((input.cache === undefined) !== (input.data.cacheSlot === undefined)) {
    fail("INTERFACE_INVALID_SHAPE", {
      name: "cache",
      expected: input.data.cacheSlot === undefined ? "none" : "write",
      actual: input.cache === undefined ? "none" : "write",
    });
  }
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
      ...(input.cache === undefined ? [] : cacheWriteAccountMetas(input.cache)),
    ],
  );
}

export async function createCacheInstruction(
  input: Readonly<{ payer: SignerAccount; data: CreateCacheData }>,
): Promise<Instruction> {
  const data = tagged(InstructionTag.createCache, encodeCreateCacheData(input.data));
  return instruction(data, [
    meta(input.payer, true, true),
    meta(await cacheAddress(signerAddress(input.payer), input.data.nonce), false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export function closeCacheInstruction(
  input: Readonly<{ cache: Address; rentRecipient: Address; writer?: SignerAccount }>,
): Instruction {
  return instruction(Uint8Array.of(InstructionTag.closeCache), [
    meta(input.cache, false, true),
    meta(input.rentRecipient, false, true),
    ...(input.writer === undefined ? [] : [meta(input.writer, true, false)]),
  ]);
}
