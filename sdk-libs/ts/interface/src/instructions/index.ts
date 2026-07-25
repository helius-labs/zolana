import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
  type Address,
  type AddressTreeParams,
  type BatchUpdateNullifierTreeData,
  type MergeTransactInstructionData,
  type ZoneDepositInstructionData,
  type Bytes31,
  type Bytes32,
  type DepositInstructionData,
  type DepositSplAccounts,
  type Instruction,
  type TransactInstructionData,
  type TransactWithdrawal,
} from "../index.js";
import { Writer, addressBytes, checkedAddress, fail } from "../internal.js";
import {
  associatedTokenAddress,
  protocolConfigAddress,
  solInterfaceAddress,
  splAssetCounterAddress,
  splAssetRegistryAddress,
  splAssetVaultAddress,
  zoneAuthAddress,
} from "../pda/index.js";
import {
  addressTreeParamsCodec,
  batchUpdateNullifierTreeDataCodec,
  createTreeDataCodec,
  createZoneConfigDataCodec,
  depositInstructionDataCodec,
  mergeTransactInstructionDataCodec,
  mergeZoneInstructionDataCodec,
  transactInstructionDataCodec,
  updateZoneConfigDataCodec,
  updateZoneConfigOwnerDataCodec,
  zoneDepositInstructionDataCodec,
} from "../codecs/index.js";

const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
export type { MergeTransactInstructionData } from "../index.js";

type Meta = Instruction["accounts"][number];

function meta(address: Address, isSigner: boolean, isWritable: boolean): Meta {
  return {
    address: checkedAddress(address),
    isSigner,
    isWritable,
  };
}

function instruction(
  data: Uint8Array,
  accounts: readonly Meta[],
  programAddress = SHIELDED_POOL_PROGRAM_ID,
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

export function batchUpdateNullifierTreeInstruction(
  input: Readonly<{
    authority: Address;
    tree: Address;
  }> &
    Omit<BatchUpdateNullifierTreeData, "compressedProof"> &
    Readonly<{ compressedProof: BatchUpdateNullifierTreeData["compressedProof"] }>,
): Instruction {
  const payload = batchUpdateNullifierTreeDataCodec.encode(input);
  return instruction(tagged(InstructionTag.batchUpdateNullifierTree, payload), [
    meta(input.authority, true, false),
    meta(protocolConfigAddress(), false, false),
    meta(input.tree, false, true),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
  ]);
}

export function createAssetCounterInstruction(
  input: Readonly<{ authority: Address }>,
): Instruction {
  return instruction(Uint8Array.of(InstructionTag.createAssetCounter), [
    meta(input.authority, true, true),
    meta(protocolConfigAddress(), false, false),
    meta(splAssetCounterAddress(), false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export function createAssociatedTokenAccountInstruction(
  input: Readonly<{ payer: Address; owner: Address; mint: Address }>,
): Instruction {
  const address = associatedTokenAddress(input.owner, input.mint);
  return instruction(
    Uint8Array.of(1),
    [
      meta(input.payer, true, true),
      meta(address, false, true),
      meta(input.owner, false, false),
      meta(input.mint, false, false),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SPL_TOKEN_PROGRAM_ID, false, false),
    ],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  );
}

export function createSplInterfaceInstruction(
  input: Readonly<{ authority: Address; mint: Address }>,
): Instruction {
  return instruction(Uint8Array.of(InstructionTag.createSplInterface), [
    meta(input.authority, true, true),
    meta(protocolConfigAddress(), false, false),
    meta(splAssetCounterAddress(), false, true),
    meta(splAssetRegistryAddress(input.mint), false, true),
    meta(input.mint, false, false),
    meta(splAssetVaultAddress(input.mint), false, true),
    meta(SYSTEM_PROGRAM, false, false),
    meta(SPL_TOKEN_PROGRAM_ID, false, false),
  ]);
}

export function createTreeInstruction(
  input: Readonly<{
    authority: Address;
    tree: Address;
    owner: Address;
    nullifierTreeParams?: AddressTreeParams;
  }>,
): Instruction {
  const owner = createTreeDataCodec.encode({ owner: input.owner });
  const params =
    input.nullifierTreeParams === undefined
      ? undefined
      : addressTreeParamsCodec.encode(input.nullifierTreeParams);
  const payload = new Uint8Array(owner.length + (params?.length ?? 0));
  payload.set(owner);
  if (params !== undefined) payload.set(params, owner.length);
  return instruction(tagged(InstructionTag.createTree, payload), [
    meta(input.authority, true, false),
    meta(protocolConfigAddress(), false, false),
    meta(input.tree, false, true),
  ]);
}

function depositAccounts(
  tree: Address,
  depositor: Address,
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
    depositor: Address;
    spl?: DepositSplAccounts;
    data: DepositInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.deposit, depositInstructionDataCodec.encode(input.data)),
    depositAccounts(input.tree, input.depositor, input.spl),
  );
}

function settlementAccounts(withdrawal?: TransactWithdrawal): Meta[] {
  if (withdrawal === undefined) return [];
  if (withdrawal.kind === "sol") {
    return [
      meta(SOL_INTERFACE, false, true),
      meta(withdrawal.recipient, false, true),
      meta(SYSTEM_PROGRAM, false, false),
    ];
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
  payer: Address,
  tree: Address,
  data: TransactInstructionData,
  withdrawal?: TransactWithdrawal,
  zoneAuthority?: Readonly<{ address: Address; signer: boolean }>,
): Meta[] {
  const accounts = [meta(payer, true, true), meta(tree, false, true)];
  if (zoneAuthority !== undefined) {
    accounts.push(meta(zoneAuthority.address, zoneAuthority.signer, false));
  }
  accounts.push(...settlementAccounts(withdrawal));
  accounts.push(meta(SHIELDED_POOL_PROGRAM_ID, false, false));
  return accounts;
}

export function transactInstruction(
  input: Readonly<{
    payer: Address;
    tree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.transact, transactInstructionDataCodec.encode(input.data)),
    transactAccounts(input.payer, input.tree, input.data, input.withdrawal),
  );
}

export function createProtocolConfigInstruction(
  input: Readonly<{
    authority: Address;
    protocolAuthority: Address;
    treeCreationAuthority: Address;
    treeCreationIsPermissionless: boolean;
    foresterAuthority: Address;
    zoneCreationAuthority: Address;
    zoneCreationIsPermissionless: boolean;
    splInterfaceCreationIsPermissionless: boolean;
  }>,
): Instruction {
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
    meta(protocolConfigAddress(), false, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export type ProtocolConfigUpdate =
  | Readonly<{ field: "protocolAuthority"; value: Address }>
  | Readonly<{ field: "treeCreationAuthority"; value: Address }>
  | Readonly<{ field: "foresterAuthority"; value: Address }>
  | Readonly<{ field: "zoneCreationAuthority"; value: Address }>
  | Readonly<{ field: "treeCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "zoneCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "splInterfaceCreationPermissionless"; value: boolean }>;

export function updateProtocolConfigInstruction(
  input: Readonly<{ authority: Address; update: ProtocolConfigUpdate }>,
): Instruction {
  const writer = new Writer();
  let newAuthority: Address | undefined;
  switch (input.update.field) {
    case "protocolAuthority":
      writer.u8(0, "update.field").bytes(addressBytes(input.update.value));
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
  const accounts = [meta(input.authority, true, false), meta(protocolConfigAddress(), false, true)];
  if (newAuthority !== undefined) accounts.push(meta(newAuthority, true, false));
  return instruction(tagged(InstructionTag.updateProtocolConfig, writer.finish()), accounts);
}

export function pauseTreeInstruction(
  input: Readonly<{ authority: Address; tree: Address; paused: boolean }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.pauseTree, new Writer().bool(input.paused, "paused").finish()),
    [
      meta(input.authority, true, false),
      meta(protocolConfigAddress(), false, true),
      meta(input.tree, false, true),
    ],
  );
}

export function createZoneConfigInstruction(
  input: Readonly<{
    payer: Address;
    programId: Address;
    authority: Address;
    zoneAuthorityTransactIsEnabled: boolean;
  }>,
): Instruction {
  const zoneAuthority = zoneAuthAddress(input.programId)[0];
  const payload = createZoneConfigDataCodec.encode(input);
  return instruction(tagged(InstructionTag.createZoneConfig, payload), [
    meta(input.payer, true, true),
    meta(protocolConfigAddress(), false, false),
    meta(zoneAuthority, true, true),
    meta(SYSTEM_PROGRAM, false, false),
  ]);
}

export function updateZoneConfigInstruction(
  input: Readonly<{
    authority: Address;
    zoneConfig: Address;
    zoneAuthorityTransactIsEnabled: boolean;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.updateZoneConfig, updateZoneConfigDataCodec.encode(input)),
    [meta(input.authority, true, false), meta(input.zoneConfig, false, true)],
  );
}

export function updateZoneConfigOwnerInstruction(
  input: Readonly<{
    authority: Address;
    zoneConfig: Address;
    newAuthority: Address;
  }>,
): Instruction {
  return instruction(
    tagged(
      InstructionTag.updateZoneConfigOwner,
      updateZoneConfigOwnerDataCodec.encode({ newAuthority: input.newAuthority }),
    ),
    [
      meta(input.authority, true, false),
      meta(input.zoneConfig, false, true),
      meta(input.newAuthority, true, false),
    ],
  );
}

export function zoneDepositInstruction(
  input: Readonly<{
    tree: Address;
    depositor: Address;
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
): Instruction {
  const zoneAuthority = zoneAuthAddress(input.zoneProgramId)[0];
  const data: ZoneDepositInstructionData = input;
  return instruction(
    tagged(InstructionTag.zoneDeposit, zoneDepositInstructionDataCodec.encode(data)),
    depositAccounts(input.tree, input.depositor, input.spl, {
      address: zoneAuthority,
      signer: input.cpi === true,
    }),
    input.cpi === true ? SHIELDED_POOL_PROGRAM_ID : input.zoneProgramId,
  );
}

type ZoneTransactInput = Readonly<{
  payer: Address;
  tree: Address;
  zoneProgramId: Address;
  withdrawal?: TransactWithdrawal;
  data: TransactInstructionData;
  cpi?: boolean;
}>;

function buildZoneTransact(tag: number, input: ZoneTransactInput): Instruction {
  const zoneAuthority = zoneAuthAddress(input.zoneProgramId)[0];
  return instruction(
    tagged(tag, transactInstructionDataCodec.encode(input.data)),
    transactAccounts(input.payer, input.tree, input.data, input.withdrawal, {
      address: zoneAuthority,
      signer: input.cpi === true,
    }),
    input.cpi === true ? SHIELDED_POOL_PROGRAM_ID : input.zoneProgramId,
  );
}

export function zoneTransactInstruction(
  input: Readonly<{
    payer: Address;
    tree: Address;
    zoneProgramId: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    cpi?: boolean;
  }>,
): Instruction {
  return buildZoneTransact(InstructionTag.zoneTransact, input);
}

export function zoneAuthorityTransactInstruction(
  input: Readonly<{
    payer: Address;
    tree: Address;
    zoneProgramId: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    cpi?: boolean;
  }>,
): Instruction {
  return buildZoneTransact(InstructionTag.zoneAuthorityTransact, input);
}

export function mergeTransactInstruction(
  input: Readonly<{
    tree: Address;
    payer: Address;
    userRecord: Address;
    data: MergeTransactInstructionData;
  }>,
): Instruction {
  return instruction(
    tagged(InstructionTag.mergeTransact, mergeTransactInstructionDataCodec.encode(input.data)),
    [
    meta(input.tree, false, true),
    meta(input.payer, true, true),
    meta(input.userRecord, false, false),
    meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
  );
}

export function mergeZoneInstruction(
  input: Readonly<{
    tree: Address;
    zoneProgramId: Address;
    payer: Address;
    data: MergeTransactInstructionData;
    mergeViewTag: Bytes32;
    cpi?: boolean;
  }>,
): Instruction {
  const authority = zoneAuthAddress(input.zoneProgramId)[0];
  return instruction(
    tagged(
      InstructionTag.zoneMergeTransact,
      mergeZoneInstructionDataCodec.encode({
        mergeViewTag: input.mergeViewTag,
        merge: input.data,
      }),
    ),
    [
      meta(input.tree, false, true),
      meta(authority, input.cpi === true, false),
      meta(input.payer, true, true),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
    input.cpi === true ? SHIELDED_POOL_PROGRAM_ID : input.zoneProgramId,
  );
}
