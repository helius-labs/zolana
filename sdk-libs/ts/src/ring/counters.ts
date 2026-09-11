import type { Bytes16, Bytes32, MessageData } from "../interface/types.js";
import type { SpendSession } from "../transaction/wallet/authority.js";
import { RingError } from "./error.js";
import {
  type SpendCounters,
  decodeSpendCounters,
  encodeSpendCounters,
  spendCountersCommitment,
} from "./policy.js";

/** Mirrors Rust `SPEND_COUNTERS_SLOT_INDEX`, off every real output index. */
export const RING_SPEND_COUNTERS_SLOT_INDEX = 0xffff_ffff;

/** Mirrors Rust `counters_message`. */
export function spendCountersMessage(namespace: Bytes32, body: Uint8Array): MessageData {
  return { viewTag: namespace, data: body };
}

/** Mirrors Rust `find_counters_message`. */
export function findSpendCountersMessage(
  messages: readonly MessageData[],
  namespace: Bytes32,
): MessageData | undefined {
  return messages.find((message) =>
    message.viewTag.every((byte, index) => byte === namespace[index]),
  );
}

export function sealedSpendCounters(
  counters: SpendCounters,
  namespace: Bytes32,
): Readonly<{ viewTag: Bytes32; plaintext: Uint8Array; slotIndex: number }> {
  return {
    viewTag: namespace,
    plaintext: encodeSpendCounters(counters),
    slotIndex: RING_SPEND_COUNTERS_SLOT_INDEX,
  };
}

/** Kept only when the counters reproduce the record's commitment. */
export async function openSpendCounters(
  session: Pick<SpendSession, "openSealedMessage">,
  input: Readonly<{
    firstNullifier: Bytes32;
    salt: Bytes16;
    data: Uint8Array;
    commitment: Bytes32;
  }>,
): Promise<SpendCounters> {
  let counters: SpendCounters;
  try {
    const plaintext = await session.openSealedMessage({
      firstNullifier: input.firstNullifier,
      salt: input.salt,
      slotIndex: RING_SPEND_COUNTERS_SLOT_INDEX,
      data: input.data,
    });
    counters = decodeSpendCounters(plaintext);
  } catch (cause) {
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN", { cause });
  }
  const commitment = spendCountersCommitment(counters);
  if (!commitment.every((byte, index) => byte === input.commitment[index])) {
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN", {
      details: { reason: "commitmentMismatch" },
    });
  }
  return counters;
}
