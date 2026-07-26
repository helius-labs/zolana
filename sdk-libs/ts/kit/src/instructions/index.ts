import type { Instruction as KitInstruction } from "@solana/kit";
import type { Instruction } from "@zolana/interface";
import * as zolana from "@zolana/interface/instructions";

import { toKitInstruction } from "../instruction.js";

export type {
  MergeTransactInstructionData,
  ProtocolConfigUpdate,
} from "@zolana/interface/instructions";

/**
 * Wrappers around the `@zolana/interface` builders that return Kit
 * `Instruction` values. Encoding stays in the interface package; input types
 * are inferred from the originals.
 */
function kitBuilder<TInput>(
  build: (input: TInput) => Instruction,
): (input: TInput) => KitInstruction {
  return function buildKitInstruction(input: TInput): KitInstruction {
    return toKitInstruction(build(input));
  };
}

export const createAssetCounterInstruction = kitBuilder(zolana.createAssetCounterInstruction);
export const createAssociatedTokenAccountInstruction = kitBuilder(
  zolana.createAssociatedTokenAccountInstruction,
);
export const createProtocolConfigInstruction = kitBuilder(zolana.createProtocolConfigInstruction);
export const createSplInterfaceInstruction = kitBuilder(zolana.createSplInterfaceInstruction);
export const createTreeInstruction = kitBuilder(zolana.createTreeInstruction);
export const createZoneConfigInstruction = kitBuilder(zolana.createZoneConfigInstruction);
export const depositInstruction = kitBuilder(zolana.depositInstruction);
export const mergeTransactInstruction = kitBuilder(zolana.mergeTransactInstruction);
export const mergeZoneInstruction = kitBuilder(zolana.mergeZoneInstruction);
export const pauseTreeInstruction = kitBuilder(zolana.pauseTreeInstruction);
export const transactInstruction = kitBuilder(zolana.transactInstruction);
export const updateProtocolConfigInstruction = kitBuilder(zolana.updateProtocolConfigInstruction);
export const updateZoneConfigInstruction = kitBuilder(zolana.updateZoneConfigInstruction);
export const updateZoneConfigOwnerInstruction = kitBuilder(zolana.updateZoneConfigOwnerInstruction);
export const zoneAuthorityTransactInstruction = kitBuilder(zolana.zoneAuthorityTransactInstruction);
export const zoneDepositInstruction = kitBuilder(zolana.zoneDepositInstruction);
export const zoneTransactInstruction = kitBuilder(zolana.zoneTransactInstruction);
