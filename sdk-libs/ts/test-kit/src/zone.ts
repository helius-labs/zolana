import type { Address, Bytes31, Bytes32, DepositSplAccounts, Instruction } from "@zolana/interface";
import { zoneAuthAddress } from "@zolana/interface/pda";
import {
  createZoneConfigInstruction,
  updateZoneConfigInstruction,
  updateZoneConfigOwnerInstruction,
  zoneDepositInstruction,
} from "@zolana/interface/instructions";

export function createZoneConfig(
  input: Readonly<{
    payer: Address;
    programId: Address;
    authority: Address;
    enabled: boolean;
  }>,
): Readonly<{ address: Address; instruction: Instruction }> {
  const [address] = zoneAuthAddress(input.programId);
  return Object.freeze({
    address,
    instruction: createZoneConfigInstruction({
      payer: input.payer,
      programId: input.programId,
      authority: input.authority,
      zoneAuthorityTransactIsEnabled: input.enabled,
    }),
  });
}

export function updateZoneConfig(
  authority: Address,
  zoneConfig: Address,
  enabled: boolean,
): Instruction {
  return updateZoneConfigInstruction({
    authority,
    zoneConfig,
    zoneAuthorityTransactIsEnabled: enabled,
  });
}

export function updateZoneOwner(
  authority: Address,
  zoneConfig: Address,
  newAuthority: Address,
): Instruction {
  return updateZoneConfigOwnerInstruction({ authority, zoneConfig, newAuthority });
}

export function zoneDeposit(
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
    memo?: Uint8Array;
  }>,
): Instruction {
  return zoneDepositInstruction({
    ...input,
    blinding: new Uint8Array(input.blinding) as Bytes31,
  });
}
