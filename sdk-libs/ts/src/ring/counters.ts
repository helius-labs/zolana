import type { ViewingKey } from "../keypair/viewing-key.js";
import { hashBytes } from "../hasher/index.js";
import { checkedBytes, concatBytes } from "../keypair/bytes.js";
import { RING_SPEND_COUNTERS_SLOT_INDEX } from "../interface/constants.js";
import type { Bytes16, Bytes32, MessageData, RequestContext } from "../interface/types.js";
import { openSealedMessage, type SealedMessageInput } from "../transaction/wallet/encrypt-rails.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import { equalBytes } from "../wallet/internal.js";
import { withTransactionKey } from "../wallet/private-transaction.js";
import { RingError } from "./error.js";
import {
  type SpendCounters,
  decodeSpendCounters,
  encodeSpendCounters,
  spendCountersCommitment,
} from "./policy.js";

export { RING_SPEND_COUNTERS_SLOT_INDEX } from "../interface/constants.js";

/** Mirrors Rust `counters_message`. */
export function spendCountersMessage(namespace: Bytes32, body: Uint8Array): MessageData {
  return { viewTag: namespace, data: body };
}

/** Mirrors Rust `find_counters_message`. */
export function findSpendCountersMessage(
  messages: readonly MessageData[],
  namespace: Bytes32,
): MessageData | undefined {
  const matching = messages.filter((message) => equalBytes(message.viewTag, namespace));
  if (matching.length > 1) throw new RingError("RING_SPEND_COUNTERS_UNKNOWN");
  return matching[0];
}

export function sealedSpendCounters(
  counters: SpendCounters,
  namespace: Bytes32,
): Omit<SealedMessageInput, "slotIndex"> {
  return {
    viewTag: namespace,
    plaintext: encodeSpendCounters(counters),
  };
}

/** Kept only when the counters reproduce the record's commitment. */
export async function openSpendCounters(
  keys: ShieldedKeys,
  input: Readonly<{
    firstNullifier: Bytes32;
    salt: Bytes16;
    data: Uint8Array;
    commitment: Bytes32;
  }>,
  context?: RequestContext,
): Promise<SpendCounters> {
  try {
    return await withTransactionKey(
      keys,
      input.firstNullifier,
      (tx) => openSpendCountersWithKey(tx, input),
      context,
    );
  } catch (cause) {
    throw cause instanceof RingError
      ? cause
      : new RingError("RING_SPEND_COUNTERS_UNKNOWN", { cause });
  }
}

export function openSpendCountersWithKey(
  tx: ViewingKey,
  input: Readonly<{ salt: Bytes16; data: Uint8Array; commitment: Bytes32 }>,
): SpendCounters {
  if (
    input.data.length !== 385 ||
    !equalBytes(input.data.subarray(0, 33), tx.publicKey().toBytes())
  )
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN");
  const plaintext = openSealedMessage(tx, {
    salt: input.salt,
    slotIndex: RING_SPEND_COUNTERS_SLOT_INDEX,
    data: input.data,
  });
  try {
    return checkedSpendCounters(plaintext, input.commitment);
  } finally {
    plaintext.fill(0);
  }
}

export function checkedSpendCounters(plaintext: Uint8Array, commitment: Bytes32): SpendCounters {
  let counters: SpendCounters;
  try {
    counters = decodeSpendCounters(plaintext);
  } catch (cause) {
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN", { cause });
  }
  if (!equalBytes(spendCountersCommitment(counters), commitment)) {
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN", {
      details: { reason: "commitmentMismatch" },
    });
  }
  return counters;
}

export function spendCountersDisclosureHash(salt: Bytes16, body: Uint8Array): Bytes32 {
  return checkedBytes(
    hashBytes(
      concatBytes(
        new TextEncoder().encode("CRING/spend-counters/v1"),
        checkedBytes(salt, 16, "transaction salt"),
        checkedBytes(body, 385, "counter body"),
      ),
    ),
    32,
    "disclosure hash",
  ) as Bytes32;
}
