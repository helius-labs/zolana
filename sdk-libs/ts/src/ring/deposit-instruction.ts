import type { AccountMeta, Instruction } from "@solana/kit";

import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { encodeRingDepositInstructionData } from "../interface/codecs/index.js";
import {
  depositAccounts,
  depositAssetIndex,
  depositLayout,
  instruction,
  meta,
  tagged,
  type SignerAccount,
} from "../interface/instructions/index.js";
import { Writer, fail } from "../interface/internal.js";
import {
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
} from "../interface/pda/index.js";
import { InstructionTag } from "../interface/program.js";
import type { Address, RingAssetDeposit } from "../interface/types.js";

import {
  AUDITED_RING_DEPOSIT_TAG,
  RING_DEPOSIT_AUDIT_SLOTS,
  readRingDepositCapsule,
} from "./deposit-capsule.js";

/** The SPP ring deposit the ring program forwards unchanged, Rust `RingDeposit`. */
export interface RingDepositSpp {
  /** `RING_DEPOSIT ‖ RingDepositIxData`, the bytes the deposit proof binds. */
  readonly data: Uint8Array;
  readonly accounts: readonly AccountMeta[];
}

/**
 * `AUDITED_DEPOSIT ‖ proof ‖ registry_root_index ‖ spp`, the accounts
 * `[config, registry?, co_signer?]` ahead of SPP's deposit list.
 */
export async function ringDepositInstruction(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
    proof: Uint8Array;
    /** The registry history slot of the bound root, present exactly on a ring that escrows keys. */
    registryRootIndex?: number;
    /** The co-signer the config demands for deposits. */
    cosigner?: SignerAccount;
  }>,
): Promise<Instruction> {
  const [spp, config, registry] = await Promise.all([
    ringDepositSpp(input),
    ringConfigAddress(input.ringProgramId),
    input.registryRootIndex === undefined
      ? undefined
      : ringMemberRegistryAddress(input.ringProgramId),
  ]);
  const prefix = new Writer()
    .bytes(input.proof, CUSTOM_RING_PROOF_LENGTH, "deposit proof")
    .u8(input.registryRootIndex ?? 0, "registryRootIndex")
    .finish();
  return instruction(
    tagged(AUDITED_RING_DEPOSIT_TAG, new Uint8Array([...prefix, ...spp.data])),
    [
      meta(config, false, false),
      ...(registry === undefined ? [] : [meta(registry, false, false)]),
      ...(input.cosigner === undefined ? [] : [meta(input.cosigner, true, false)]),
      ...spp.accounts,
    ],
    input.ringProgramId,
  );
}

/** One capsule per output at its own slot, all under one ephemeral key, as the program reads them. */
export async function ringDepositSpp(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
  }>,
): Promise<RingDepositSpp> {
  if (input.deposits.length > RING_DEPOSIT_AUDIT_SLOTS)
    fail("INTERFACE_CODEC", { field: "deposit count" });
  let ephemeralKey: Uint8Array | undefined;
  for (const [index, deposit] of input.deposits.entries()) {
    const capsule = readRingDepositCapsule(deposit.encrypted.ciphertext);
    if (
      capsule === undefined ||
      capsule.slotIndex !== index ||
      (ephemeralKey !== undefined &&
        !ephemeralKey.every((byte, offset) => capsule.ephemeralPublicKey[offset] === byte))
    )
      fail("INTERFACE_CODEC", { field: "deposit capsule" });
    ephemeralKey = capsule.ephemeralPublicKey;
  }
  const layout = depositLayout(input.deposits);
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
    await ringAuthAddress(input.ringProgramId),
  );
  const data = tagged(
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
        ringDataHash: deposit.ringDataHash,
        encrypted: deposit.encrypted,
      })),
    }),
  );
  return Object.freeze({ data, accounts: Object.freeze(accounts) });
}
