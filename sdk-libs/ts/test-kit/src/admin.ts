import type { Address, Instruction } from "@zolana/interface";
import {
  createAssetCounterInstruction,
  createProtocolConfigInstruction,
  pauseTreeInstruction,
  type ProtocolConfigUpdate,
  updateProtocolConfigInstruction,
} from "@zolana/interface/instructions";

export function createProtocolConfigInstructions(
  input: Readonly<{
    authority: Address;
    permissionless?: boolean;
  }>,
): readonly Instruction[] {
  const permissionless = input.permissionless ?? false;
  return Object.freeze([
    createProtocolConfigInstruction({
      authority: input.authority,
      protocolAuthority: input.authority,
      treeCreationAuthority: input.authority,
      treeCreationIsPermissionless: permissionless,
      foresterAuthority: input.authority,
      zoneCreationAuthority: input.authority,
      zoneCreationIsPermissionless: permissionless,
      splInterfaceCreationIsPermissionless: permissionless,
    }),
  ]);
}

export function rotateProtocolAuthorityInstructions(
  authority: Address,
  next: Address,
): readonly Instruction[] {
  const updates: readonly ProtocolConfigUpdate[] = [
    { field: "treeCreationAuthority", value: next },
    { field: "foresterAuthority", value: next },
    { field: "zoneCreationAuthority", value: next },
    { field: "protocolAuthority", value: next },
  ];
  return Object.freeze(
    updates.map((update) => updateProtocolConfigInstruction({ authority, update })),
  );
}

export function pauseTree(authority: Address, tree: Address, paused: boolean): Instruction {
  return pauseTreeInstruction({ authority, tree, paused });
}

export function createAssetCounter(authority: Address): Instruction {
  return createAssetCounterInstruction({ authority });
}
