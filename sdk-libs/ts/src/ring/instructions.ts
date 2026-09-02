import { COMPUTE_BUDGET_PROGRAM_ADDRESS } from "@solana-program/compute-budget";
import { AccountRole, type Address, type Instruction } from "@solana/kit";

import {
  SYSTEM_PROGRAM,
  meta,
  ringTransactAccounts,
  type SignerAccount,
} from "../interface/instructions/index.js";
import { encodeTransactInstructionData } from "../interface/codecs/index.js";
import {
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
} from "../interface/program.js";
import { protocolConfigAddress, ringAuthAddress } from "../interface/pda/index.js";
import type { TransactInstructionData, TransactWithdrawal } from "../interface/types.js";
import { isDerivationPoint } from "../keypair/derivation.js";
import type { P256PublicKey } from "../keypair/public-key.js";

import { Writer } from "../interface/internal.js";

import { checkedCustomRingProof } from "./codecs.js";
import { ringConfigAddress, ringPolicyConfigAddress, ringProgramDataAddress } from "./config.js";
import { RingError } from "./error.js";

/** Rust `tag::CREATE_CONFIG`, `tag::INIT_SPP_RING_CONFIG` and `tag::TRANSACT`. */
const RingProgramTag = Object.freeze({
  createConfig: 1,
  initSppRingConfig: 2,
  transact: 3,
} as const);

/** Rust `CREATE_CONFIG_COMPUTE_UNIT_LIMIT`, `INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT` and `READ_ACCESS_COMPUTE_UNIT_LIMIT`. */
export const RING_CREATE_CONFIG_COMPUTE_UNIT_LIMIT = 50_000;
export const RING_INIT_SPP_RING_CONFIG_COMPUTE_UNIT_LIMIT = 50_000;
export const RING_READ_ACCESS_COMPUTE_UNIT_LIMIT = 50_000;

/** Mirrors Rust `CreateConfig`. The authority signs, so the recorded authority consented to the role. */
export async function createRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
    auditorPublicKey: P256PublicKey;
    /** A policy ring enforces its compiled rules, an audit-only ring skips them. */
    hasPolicy: boolean;
  }>,
): Promise<Instruction> {
  if (isDerivationPoint(input.auditorPublicKey)) {
    throw new RingError("RING_RESERVED_AUDITOR_KEY");
  }
  const [config, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  const data = new Uint8Array(1 + 33 + 1);
  data[0] = RingProgramTag.createConfig;
  data.set(input.auditorPublicKey.toBytes(), 1);
  data[34] = input.hasPolicy ? 1 : 0;
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(input.ringProgramId, false, false),
      meta(programData, false, false),
    ],
    data,
  };
}

/** Mirrors Rust `InitSppRingConfig`. `ringAuth` stays unsigned, the ring program signs it inside its CPI. */
export async function initSppRingConfigInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    authority: SignerAccount;
  }>,
): Promise<Instruction> {
  const [config, protocolConfig, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    protocolConfigAddress(),
    ringAuthAddress(input.ringProgramId),
  ]);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      meta(input.payer, true, true),
      meta(input.authority, true, false),
      meta(config, false, false),
      meta(protocolConfig, false, false),
      meta(ringAuth, false, true),
      meta(SYSTEM_PROGRAM, false, false),
      meta(SHIELDED_POOL_PROGRAM_ID, false, false),
    ],
    data: Uint8Array.of(RingProgramTag.initSppRingConfig),
  };
}

/**
 * Mirrors Rust `CustomRingTransact`. Data layout is
 * `tag || proof || state root index || nullifier root index || transact data`.
 */
export async function ringTransactInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    /** Read for the policy roots, never forwarded to SPP. Required for the policy tier. */
    entriesTree?: Address;
    /** The config tier. False drops the policy_config and entries_tree accounts. */
    hasPolicy?: boolean;
    proof: Uint8Array;
    /** History entries the ring statement binds, unread by a ring without rules. */
    stateRootIndex: number;
    nullifierRootIndex: number;
    data: TransactInstructionData;
    /** Non-payer input owners, the ed25519 rail adds them as signers. */
    ownerSigners?: readonly SignerAccount[];
    /** Settlement accounts for a public withdrawal in `data.interfaceTransfers`. */
    withdrawal?: TransactWithdrawal;
  }>,
): Promise<Instruction> {
  const hasPolicy = input.hasPolicy ?? true;
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const payerAddress = typeof input.payer === "string" ? input.payer : input.payer.address;
  const answers = ringTransactAccounts({
    payer: input.payer,
    inputTree: input.inputTree,
    outputTree: input.outputTree,
    ringAuth,
    ...(input.ownerSigners === undefined ? {} : { ownerSigners: input.ownerSigners }),
    ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
  });
  const proof = checkedCustomRingProof(input.proof);
  const rootIndexes = new Writer()
    .u16(input.stateRootIndex, "stateRootIndex")
    .u16(input.nullifierRootIndex, "nullifierRootIndex")
    .finish();
  const transact = encodeTransactInstructionData(input.data);
  const data = new Uint8Array(1 + proof.length + rootIndexes.length + transact.length);
  data[0] = RingProgramTag.transact;
  data.set(proof, 1);
  data.set(rootIndexes, 1 + proof.length);
  data.set(transact, 1 + proof.length + rootIndexes.length);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      {
        address: payerAddress,
        role: AccountRole.WRITABLE_SIGNER,
        ...(typeof input.payer === "string" ? {} : { signer: input.payer }),
      },
      { address: config, role: AccountRole.READONLY },
      ...(hasPolicy ? await policyAccountMetas(input.ringProgramId, input.entriesTree) : []),
      ...answers,
    ],
    data,
  };
}

/** The policy tier reads `policy_config` and `entries_tree`, read-only and before the SPP list. */
async function policyAccountMetas(
  ringProgramId: Address,
  entriesTree: Address | undefined,
): Promise<readonly { address: Address; role: AccountRole }[]> {
  if (entriesTree === undefined) {
    throw new RingError("RING_ENTRIES_TREE_REQUIRED", { details: { ringProgramId } });
  }
  const policyConfig = await ringPolicyConfigAddress(ringProgramId);
  return [
    { address: policyConfig, role: AccountRole.READONLY },
    { address: entriesTree, role: AccountRole.READONLY },
  ];
}

/** Mirrors Rust `lookup_table_addresses`; optional trees default to `tree`. */
export async function ringLookupTableAddresses(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    outputTree?: Address;
    entriesTree?: Address;
    /** The config tier. False drops the policy_config and entries_tree entries. */
    hasPolicy?: boolean;
  }>,
): Promise<readonly Address[]> {
  const hasPolicy = input.hasPolicy ?? true;
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const answers = ringTransactAccounts({
    payer: SHIELDED_POOL_PROGRAM_ID,
    inputTree: input.tree,
    outputTree: input.outputTree ?? input.tree,
    ringAuth,
  });
  const addresses = [
    config,
    ...(hasPolicy
      ? [await ringPolicyConfigAddress(input.ringProgramId), input.entriesTree ?? input.tree]
      : []),
    ...answers
      .filter(
        (meta) =>
          meta.role !== AccountRole.WRITABLE_SIGNER && meta.role !== AccountRole.READONLY_SIGNER,
      )
      .map((meta) => meta.address),
    input.ringProgramId,
    COMPUTE_BUDGET_PROGRAM_ADDRESS,
  ];
  return Object.freeze([...new Set(addresses)]);
}

/** In every new table, never required at fetch, an old table stays valid. */
export function ringSettlementStatics(): readonly Address[] {
  return Object.freeze([
    SHIELDED_POOL_CPI_AUTHORITY,
    SPL_TOKEN_PROGRAM_ID,
    SPL_TOKEN_2022_PROGRAM_ID,
  ]);
}
