import { getAddressDecoder, type Address } from "@solana/kit";

import type { RpcAccount } from "../../src/client/rpc.js";
import { Writer, addressBytes } from "../../src/interface/internal.js";
import { ringAuthAddress } from "../../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../../src/interface/program.js";
import { StateDiscriminator } from "../../src/interface/state.js";
import { APPLY_BATCH, MEMBER_REGISTRY_ROOT_HISTORY } from "../../src/interface/member-registry.js";
import type { Bytes32 } from "../../src/interface/types.js";
import type {
  RingCoSigner,
  RingMode,
  RingSourceSlot,
  RingRootEntry,
} from "../../src/ring/codecs.js";
import { LIST_IDS, encodeRule, referencedLists, type RuleTable } from "../../src/ring/policy.js";
import { bigIntBytes } from "../../src/transaction/internal.js";

export const ZERO_ADDRESS = getAddressDecoder().decode(new Uint8Array(32));

const MODES: readonly RingMode[] = ["off", "registry", "anonymous"];

export function ownedAccount(owner: Address, data: Uint8Array): RpcAccount {
  return { owner, lamports: 1n, data };
}

/** Every referenced list read from the ring's own registry, the other slots empty. */
export function ownSources(table: RuleTable): readonly RingSourceSlot[] {
  const referenced = referencedLists(table.rules);
  return LIST_IDS.map((listId) =>
    referenced.includes(listId)
      ? { listId, registry: ZERO_ADDRESS }
      : { listId: 0, registry: ZERO_ADDRESS },
  );
}

/** SPP's `RingConfig` registration of `ringProgramId`, active unless told otherwise. */
export async function sppRingRegistration(
  input: Readonly<{
    authority: Address;
    ringProgramId: Address;
    activated?: boolean;
    paused?: boolean;
  }>,
): Promise<readonly [Address, RpcAccount]> {
  const data = new Uint8Array(69);
  data[0] = StateDiscriminator.ringConfig;
  data.set(addressBytes(input.authority), 1);
  data.set(addressBytes(input.ringProgramId), 33);
  data[66] = input.paused === true ? 1 : 0;
  data[67] = input.activated === false ? 0 : 1;
  return [await ringAuthAddress(input.ringProgramId), ownedAccount(SHIELDED_POOL_PROGRAM_ID, data)];
}

/** Rust `RingProgramConfig` bytes. */
export function ringProgramConfigData(
  input: Readonly<{
    authority: Address;
    auditorPublicKey: Uint8Array;
    bump: number;
    hasPolicy: boolean;
    mode?: RingMode;
    insertFee?: bigint;
    coSigner?: RingCoSigner;
    delegate?: Address;
    createdSlot?: bigint;
  }>,
): Uint8Array {
  const thresholds = input.coSigner?.thresholds ?? [];
  const writer = new Writer()
    .u8(10, "discriminator")
    .bytes(addressBytes(input.authority))
    .bytes(input.auditorPublicKey, 33, "auditorPublicKey")
    .u8(input.bump, "bump")
    .u8(input.hasPolicy ? 1 : 0, "hasPolicy")
    .u8(MODES.indexOf(input.mode ?? "off"), "mode")
    .u64(input.insertFee ?? 0n, "insertFee")
    .bytes(addressBytes(input.coSigner?.signer ?? ZERO_ADDRESS))
    .u8(input.coSigner?.scope ?? 0, "coSignScope")
    .u8(thresholds.length, "thresholdCount");
  for (let slot = 0; slot < 8; slot += 1) {
    const row = thresholds[slot];
    writer.bytes(addressBytes(row?.mint ?? ZERO_ADDRESS)).u64(row?.amount ?? 0n, "amount");
  }
  return writer
    .bytes(addressBytes(input.delegate ?? ZERO_ADDRESS))
    .u64(input.createdSlot ?? 0n, "createdSlot")
    .finish();
}

/** Rust `MemberRegistry` bytes, the newest root at `historyCursor`. */
export function memberRegistryData(
  input: Readonly<{
    bump: number;
    history: readonly (RingRootEntry | undefined)[];
    historyCursor?: number;
    nextIndex: number;
    floor?: bigint;
    priorFloor?: bigint;
    floorSlot?: bigint;
    policyHash?: Bytes32;
    sources?: readonly RingSourceSlot[];
    table?: RuleTable;
    generation?: number;
  }>,
): Uint8Array {
  const writer = new Writer()
    .u8(11, "discriminator")
    .u8(input.bump, "bump")
    .u8(input.historyCursor ?? 0, "historyCursor")
    .u32(input.nextIndex, "nextIndex")
    .u64(input.floor ?? 0n, "floor")
    .u64(input.priorFloor ?? 0n, "priorFloor")
    .u64(input.floorSlot ?? 0n, "floorSlot");
  for (let slot = 0; slot < MEMBER_REGISTRY_ROOT_HISTORY; slot += 1) {
    const entry = input.history[slot];
    writer
      .bytes(entry?.root ?? new Uint8Array(32))
      .u64(entry?.applied ?? 0n, "applied")
      .u64(entry?.slot ?? 0n, "slot");
  }
  writer.bytes(input.policyHash ?? new Uint8Array(32));
  const sources = input.sources ?? LIST_IDS.map(() => ({ listId: 0, registry: ZERO_ADDRESS }));
  for (const source of sources)
    writer.u8(source.listId, "listId").bytes(addressBytes(source.registry));
  const table = input.table ?? { rules: [], inlineAssets: [], inlineLimits: [], limits: [] };
  counted(writer, table.rules.map(encodeRule), 16);
  counted(writer, table.inlineAssets, 8);
  padded(writer, table.inlineLimits.map(be64), 8, 8);
  counted(
    writer,
    table.limits.map((limit) => limit.asset),
    8,
  );
  padded(
    writer,
    table.limits.map((limit) => be64(limit.cap)),
    8,
    8,
  );
  padded(
    writer,
    table.limits.map((limit) => be64(limit.cosignAbove)),
    8,
    8,
  );
  return writer
    .u32(input.generation ?? 0, "generation")
    .u64(0n, "generationSlot")
    .finish();
}

/** Rust `RecordQueue` bytes, every queued position's checkpoint at `position mod APPLY_BATCH`. */
export function recordQueueData(
  input: Readonly<{
    bump: number;
    head: bigint;
    tail: bigint;
    chainHead: Bytes32;
    checkpoints?: readonly Readonly<{ position: bigint; chain: Bytes32; slot: bigint }>[];
    nextApplySlot?: bigint;
  }>,
): Uint8Array {
  const writer = new Writer()
    .u8(12, "discriminator")
    .u8(input.bump, "bump")
    .u64(input.head, "head")
    .u64(input.tail, "tail")
    .bytes(input.chainHead, 32, "chainHead");
  for (let slot = 0; slot < APPLY_BATCH; slot += 1) {
    const checkpoint = input.checkpoints?.find(
      (entry) => entry.position % BigInt(APPLY_BATCH) === BigInt(slot),
    );
    writer.bytes(checkpoint?.chain ?? new Uint8Array(32)).u64(checkpoint?.slot ?? 0n, "slot");
  }
  return writer.u64(input.nextApplySlot ?? 0n, "nextApplySlot").finish();
}

function counted(writer: Writer, rows: readonly Uint8Array[], slots: number): void {
  writer.u8(rows.length, "count");
  padded(writer, rows, slots, 32);
}

function padded(writer: Writer, rows: readonly Uint8Array[], slots: number, width: number): void {
  for (const row of rows) writer.bytes(row, width);
  writer.bytes(new Uint8Array(width * (slots - rows.length)));
}

function be64(value: bigint): Uint8Array {
  return bigIntBytes(value, 8);
}
