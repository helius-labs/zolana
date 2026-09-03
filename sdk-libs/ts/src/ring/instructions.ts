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

import { checkedCustomRingProof } from "./codecs.js";
import { ringConfigAddress, ringProgramDataAddress } from "./config.js";
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
  }>,
): Promise<Instruction> {
  if (isDerivationPoint(input.auditorPublicKey)) {
    throw new RingError("RING_RESERVED_AUDITOR_KEY");
  }
  const [config, programData] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringProgramDataAddress(input.ringProgramId),
  ]);
  const data = new Uint8Array(1 + 33);
  data[0] = RingProgramTag.createConfig;
  data.set(input.auditorPublicKey.toBytes(), 1);
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

/** Mirrors Rust `CustomRingTransact`. Data layout is `tag || proof || transact data`. */
export async function ringTransactInstruction(
  input: Readonly<{
    ringProgramId: Address;
    payer: SignerAccount;
    inputTree: Address;
    outputTree: Address;
    proof: Uint8Array;
    data: TransactInstructionData;
    /** Non-payer input owners, the ed25519 rail adds them as signers. */
    ownerSigners?: readonly SignerAccount[];
    /** Settlement accounts for a public withdrawal in `data.interfaceTransfers`. */
    withdrawal?: TransactWithdrawal;
  }>,
): Promise<Instruction> {
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  const payerAddress = typeof input.payer === "string" ? input.payer : input.payer.address;
  const pool = await ringTransactAccounts({
    payer: input.payer,
    inputTree: input.inputTree,
    outputTree: input.outputTree,
    ringAuth,
    inputs: input.data.inputs,
    ...(input.ownerSigners === undefined ? {} : { ownerSigners: input.ownerSigners }),
    ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
  });
  const proof = checkedCustomRingProof(input.proof);
  const transact = encodeTransactInstructionData(input.data);
  const data = new Uint8Array(1 + proof.length + transact.length);
  data[0] = RingProgramTag.transact;
  data.set(proof, 1);
  data.set(transact, 1 + proof.length);
  return {
    programAddress: input.ringProgramId,
    accounts: [
      {
        address: payerAddress,
        role: AccountRole.WRITABLE_SIGNER,
        ...(typeof input.payer === "string" ? {} : { signer: input.payer }),
      },
      { address: config, role: AccountRole.READONLY },
      ...pool,
    ],
    data,
  };
}

/** Mirrors Rust `lookup_table_addresses`. */
export async function ringLookupTableAddresses(
  input: Readonly<{ ringProgramId: Address; tree: Address }>,
): Promise<readonly Address[]> {
  const [config, ringAuth] = await Promise.all([
    ringConfigAddress(input.ringProgramId),
    ringAuthAddress(input.ringProgramId),
  ]);
  // Nullifier PDAs are fresh per transaction, so none belongs in the table.
  const pool = await ringTransactAccounts({
    payer: SHIELDED_POOL_PROGRAM_ID,
    inputTree: input.tree,
    outputTree: input.tree,
    ringAuth,
    inputs: [],
  });
  const addresses = [
    config,
    ...pool
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
