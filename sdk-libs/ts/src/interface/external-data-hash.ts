import { encodeTransactExternalData } from "./codecs/index.js";
import { addressBytes, copyBytes, fail, sha256, unsigned } from "./internal.js";
import type { Address, Bytes32, TransactExternalData } from "./types.js";
import { concatBytes } from "./bytes.js";

export interface SettlementAccounts {
  readonly asset: Address;
  readonly user: Address;
}

export interface ExternalDataHashInput extends TransactExternalData {
  readonly instructionDiscriminator: number;
  readonly settlementAccounts: readonly SettlementAccounts[];
  readonly resolvedOwnerTags: readonly Bytes32[];
}

export function externalDataHash(input: ExternalDataHashInput): Bytes32 {
  if (input.settlementAccounts.length !== input.interfaceTransfers.length) {
    fail("INTERFACE_INVALID_LENGTH", {
      name: "settlementAccounts",
      expected: input.interfaceTransfers.length,
      actual: input.settlementAccounts.length,
    });
  }
  if (input.resolvedOwnerTags.length !== input.outputs.length) {
    fail("INTERFACE_INVALID_LENGTH", {
      name: "resolvedOwnerTags",
      expected: input.outputs.length,
      actual: input.resolvedOwnerTags.length,
    });
  }
  const parts: Uint8Array[] = [
    Uint8Array.of(unsigned(input.instructionDiscriminator, 0xff, "instructionDiscriminator")),
    encodeTransactExternalData(input),
  ];
  input.settlementAccounts.forEach((accounts, index) => {
    const position = `settlementAccounts[${String(index)}]`;
    parts.push(
      addressBytes(accounts.asset, `${position}.asset`),
      addressBytes(accounts.user, `${position}.user`),
    );
  });
  input.outputs.forEach((output, index) => {
    if (output.ownerTag.kind !== "account") return;
    const position = `resolvedOwnerTags[${String(index)}]`;
    const resolved = input.resolvedOwnerTags[index];
    if (resolved === undefined) fail("INTERFACE_INVALID_LENGTH", { name: position });
    parts.push(copyBytes(resolved, 32, position));
  });
  const digest = sha256(concatBytes(...parts));
  digest[0] = 0;
  return digest as Bytes32;
}
