import type { Instruction } from "@solana/kit";
import type { Address, RingAssetDeposit } from "../interface/types.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import { copyBytes, fail } from "../interface/internal.js";
import { InstructionTag } from "../interface/program.js";
import { encodeRingDepositInstructionData } from "../interface/codecs/index.js";
import {
  ringAuthAddress,
  ringConfigAddress,
  ringCoSignerAddress,
  ringDepositAuditAddress,
  ringPolicyConfigAddress,
} from "../interface/pda/index.js";
import {
  depositLayout,
  depositAssetIndex,
  depositAccounts,
  instruction,
  tagged,
  meta,
  ringCoSignerMetas,
  ringSpendWindowMetas,
  SYSTEM_PROGRAM,
  type SignerAccount,
} from "../interface/instructions/index.js";
import {
  AUDITED_RING_DEPOSIT_TAG,
  RING_DEPOSIT_AUDIT_SLOTS,
  readRingDepositCapsule,
} from "./deposit-capsule.js";

export async function ringDepositInstruction(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
    proof?: Uint8Array;
    cosigner?: SignerAccount;
    /** Omit only for an audit-only ring. */
    hasPolicy?: boolean;
  }>,
): Promise<Instruction> {
  const layout = depositLayout(input.deposits);
  if (input.proof !== undefined) {
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
  }
  const [ringAuth, config, cosignerPda, depositAudit, policyConfig, windows] = await Promise.all([
    ringAuthAddress(input.ringProgramId),
    ringConfigAddress(input.ringProgramId),
    ringCoSignerAddress(input.ringProgramId),
    ringDepositAuditAddress(input.ringProgramId),
    input.hasPolicy === true ? ringPolicyConfigAddress(input.ringProgramId) : undefined,
    ringSpendWindowMetas(input.ringProgramId, [
      ...(layout.hasSol ? [SYSTEM_PROGRAM] : []),
      ...layout.splGroups.map((spl) => spl.mint),
    ]),
  ]);
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
    ringAuth,
  );
  accounts.unshift(
    meta(config, false, false),
    ...ringCoSignerMetas(cosignerPda, input.cosigner),
    meta(depositAudit, false, false),
    ...(policyConfig === undefined ? [] : [meta(policyConfig, false, false)]),
    ...windows,
  );
  const sppWire = tagged(
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
  );
  return instruction(
    input.proof === undefined
      ? sppWire
      : tagged(
          AUDITED_RING_DEPOSIT_TAG,
          new Uint8Array([
            ...copyBytes(input.proof, CUSTOM_RING_PROOF_LENGTH, "deposit proof"),
            ...sppWire,
          ]),
        ),
    accounts,
    input.ringProgramId,
  );
}
