import {
  AccountRole,
  isSignerRole,
  isWritableRole,
  type AccountLookupMeta,
  type AccountMeta,
  type Instruction as KitInstruction,
} from "@solana/kit";
import type { Instruction } from "@zolana/interface";

import { fromKitAddress, toKitAddress } from "./address.js";
import { KitError } from "./error.js";

/**
 * Maps Zolana's separate `isSigner` / `isWritable` flags to Kit's `AccountRole`.
 * The compiled message header uses the same two flags.
 */
export function toAccountRole(
  permissions: Readonly<{ isSigner: boolean; isWritable: boolean }>,
): AccountRole {
  if (permissions.isSigner && permissions.isWritable) return AccountRole.WRITABLE_SIGNER;
  if (permissions.isSigner) return AccountRole.READONLY_SIGNER;
  if (permissions.isWritable) return AccountRole.WRITABLE;
  return AccountRole.READONLY;
}

export function fromAccountRole(
  role: AccountRole,
): Readonly<{ isSigner: boolean; isWritable: boolean }> {
  if (!(role in AccountRole)) {
    throw new KitError("KIT_UNKNOWN_ACCOUNT_ROLE", "account role is outside the Kit enum", {
      details: { role },
    });
  }
  return { isSigner: isSignerRole(role), isWritable: isWritableRole(role) };
}

export function toKitInstruction(instruction: Instruction): KitInstruction {
  return {
    programAddress: toKitAddress(instruction.programAddress),
    accounts: instruction.accounts.map((account): AccountMeta => ({
      address: toKitAddress(account.address),
      role: toAccountRole(account),
    })),
    data: instruction.data,
  };
}

export function fromKitInstruction(instruction: KitInstruction): Instruction {
  return {
    programAddress: fromKitAddress(instruction.programAddress),
    // Kit omits both fields when unused; Zolana's Instruction includes them, so
    // absent means empty.
    accounts: (instruction.accounts ?? []).map((account) => {
      if (isLookup(account)) {
        throw new KitError(
          "KIT_ADDRESS_LOOKUP_UNSUPPORTED",
          "Zolana instructions include addresses inline, not through an address lookup table",
          { details: { lookupTableAddress: account.lookupTableAddress } },
        );
      }
      return { address: fromKitAddress(account.address), ...fromAccountRole(account.role) };
    }),
    data: instruction.data === undefined ? new Uint8Array(0) : Uint8Array.from(instruction.data),
  };
}

function isLookup(account: AccountLookupMeta | AccountMeta): account is AccountLookupMeta {
  return "lookupTableAddress" in account;
}
