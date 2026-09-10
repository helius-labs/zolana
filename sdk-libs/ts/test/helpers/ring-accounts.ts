import { getAddressDecoder, getProgramDerivedAddress, type Address } from "@solana/kit";

import type { RpcAccount } from "../../src/client/rpc.js";
import { Writer, addressBytes } from "../../src/interface/internal.js";
import type { Bytes32 } from "../../src/interface/types.js";
import type { RingPolicyConfig, RingPolicySource } from "../../src/ring/codecs.js";
import {
  LIST_IDS,
  encodeRuleTable,
  policySourceOwners,
  referencedLists,
  ringPolicyHash,
  type RuleTable,
} from "../../src/ring/policy.js";
import { bigIntBytes } from "../../src/transaction/internal.js";

export const ZERO_ADDRESS = getAddressDecoder().decode(new Uint8Array(32));

/** Every referenced list sourced from `namespace`, the other slots empty. */
export function ownSources(table: RuleTable, namespace: Address): readonly RingPolicySource[] {
  const referenced = referencedLists(table.rules);
  return LIST_IDS.map((listId) =>
    referenced.includes(listId) ? { listId, namespace } : { listId: 0, namespace: ZERO_ADDRESS },
  );
}

/** The decoded policy config the table and sources pin. */
export function ringPolicyConfig(
  input: Readonly<{ table: RuleTable; sources: readonly RingPolicySource[]; entriesTree: Address }>,
): RingPolicyConfig {
  const encoded = encodeRuleTable(input.table);
  return {
    policyHash: ringPolicyHash(input.table, policySourceOwners(input.sources)),
    entriesTree: input.entriesTree,
    entriesTreeId: 0,
    namespaceBump: 0,
    bump: 0,
    sources: input.sources,
    ...encoded,
    generation: 1,
    generationSlot: 0n,
  };
}

/** Rust `PolicyConfig` bytes under the hash the table and sources pin. */
export function ringPolicyConfigData(
  input: Readonly<{
    table: RuleTable;
    sources: readonly RingPolicySource[];
    entriesTree: Address;
    entriesTreeId?: number;
    bump: number;
    namespaceBump?: number;
    policyHash?: Bytes32;
    generation?: number;
  }>,
): Uint8Array {
  const encoded = encodeRuleTable(input.table);
  const writer = new Writer()
    .u8(3, "discriminator")
    .bytes(input.policyHash ?? ringPolicyHash(input.table, policySourceOwners(input.sources)))
    .bytes(addressBytes(input.entriesTree))
    .u16(input.entriesTreeId ?? 0, "entriesTreeId")
    .u8(input.namespaceBump ?? 0, "namespaceBump")
    .u8(input.bump, "bump");
  for (const slot of input.sources) {
    writer.u8(slot.listId, "listId").bytes(addressBytes(slot.namespace));
  }
  writer.u8(encoded.ruleCount, "ruleCount");
  for (const row of encoded.rules) writer.bytes(row);
  writer.bytes(new Uint8Array(32 * (16 - encoded.ruleCount)));
  writer.u8(encoded.inlineCount, "inlineCount");
  for (const asset of encoded.inlineAssets) writer.bytes(asset);
  writer.bytes(new Uint8Array(32 * (8 - encoded.inlineCount)));
  for (const limit of encoded.inlineLimits) writer.bytes(bigIntBytes(limit, 8));
  writer.bytes(new Uint8Array(8 * (8 - encoded.inlineLimits.length)));
  return writer
    .u32(input.generation ?? 1, "generation")
    .u64(0n, "generationSlot")
    .finish();
}

/** Rust `RingProgramConfig` bytes. */
export function ringProgramConfigData(
  input: Readonly<{
    authority: Address;
    auditorPublicKey: Uint8Array;
    bump: number;
    hasPolicy: boolean;
  }>,
): Uint8Array {
  return new Writer()
    .u8(1, "discriminator")
    .bytes(addressBytes(input.authority))
    .bytes(input.auditorPublicKey, 33, "auditorPublicKey")
    .u8(input.bump, "bump")
    .u8(input.hasPolicy ? 1 : 0, "hasPolicy")
    .finish();
}

export async function policyConfigPda(ringProgramId: Address): Promise<readonly [Address, number]> {
  const [address, bump] = await getProgramDerivedAddress({
    programAddress: ringProgramId,
    seeds: [new TextEncoder().encode("policy")],
  });
  return [address, bump];
}

export function ownedAccount(owner: Address, data: Uint8Array): RpcAccount {
  return { owner, lamports: 1n, data };
}
