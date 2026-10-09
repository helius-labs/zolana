import type { Bytes32, RequestContext } from "../../interface/types.js";
import { decodeBatch } from "../../interface/decode.js";
import { DECRYPTED_MERGE_ENVELOPE_LENGTH } from "../../keypair/merge/index.js";
import type { ViewingKey } from "../../keypair/viewing-key.js";

import { TransactionError } from "../error.js";
import { copy } from "../internal.js";
import { deriveAnswers, destroyTransactionKeys, transactionKeyAnswers } from "./key-batch.js";
import type { DecryptRequest, DeriveRequest, ShieldedKeys, TransactionKeyRequest } from "./keys.js";
import { hex } from "./state.js";

/**
 * A merge envelope the key holder decrypted, or one it failed to decrypt. A
 * failure is final for that merge in this sync, never "ask again".
 */
export type MergeEnvelopeAnswer =
  | Readonly<{ kind: "decrypted"; plaintext: Uint8Array }>
  | Readonly<{ kind: "failed" }>;

/**
 * Synchronous view over a `ShieldedKeys` for code that decodes in one pass
 * and cannot await per item. A lookup that has no answer yet returns
 * `undefined` and is recorded; `resolve` fetches every recorded request in one
 * batched call per method, and the caller runs its pass again. A pass is a
 * pure function of its inputs and the answers, so repeating it is exact, and
 * the number of rounds is the depth of the dependency chain (plaintext, then
 * the nullifier over it), not the number of items.
 * @internal
 */
export class KeyMemo {
  readonly #keys: ShieldedKeys;
  readonly #decrypted = new Map<string, Uint8Array>();
  /** `null` marks a merge envelope the key holder failed to decrypt. */
  readonly #mergeEnvelopes = new Map<string, Uint8Array | null>();
  readonly #derived = new Map<string, Bytes32>();
  readonly #transactionKeys = new Map<string, ViewingKey>();
  readonly #pendingDecrypt = new Map<string, DecryptRequest>();
  readonly #pendingMergeEnvelopes = new Map<string, DecryptRequest>();
  readonly #pendingDerive = new Map<string, DeriveRequest>();
  readonly #pendingTransactionKeys = new Map<string, TransactionKeyRequest>();

  constructor(keys: ShieldedKeys) {
    this.#keys = keys;
  }

  decrypt(request: DecryptRequest): Uint8Array | undefined {
    const key = decryptKey(request);
    const known = this.#decrypted.get(key);
    if (known !== undefined) return copy(known);
    this.#pendingDecrypt.set(key, {
      ciphertext: copy(request.ciphertext),
      viewingPublicKey: request.viewingPublicKey,
      txViewingPublicKey: request.txViewingPublicKey,
      salt: copy(request.salt),
      slotIndex: request.slotIndex,
      label: request.label,
      ...(request.firstNullifier === undefined
        ? {}
        : { firstNullifier: copy(request.firstNullifier) }),
    });
    return undefined;
  }

  /**
   * Merge envelopes are decrypted one per key-holder call, apart from the
   * batch: a holder that fails one merge leaves that merge unread, not the
   * sync. The caller filters on the output view tag first, so the calls are
   * the wallet's own merges only.
   */
  decryptMergeEnvelope(
    request: Omit<DecryptRequest, "label" | "salt" | "slotIndex" | "firstNullifier"> &
      Readonly<{ firstNullifier: Bytes32 }>,
  ): MergeEnvelopeAnswer | undefined {
    const full: DecryptRequest = {
      ciphertext: copy(request.ciphertext),
      viewingPublicKey: request.viewingPublicKey,
      txViewingPublicKey: request.txViewingPublicKey,
      salt: new Uint8Array(16) as DecryptRequest["salt"],
      slotIndex: 0,
      label: "mergeEnvelope",
      firstNullifier: copy(request.firstNullifier),
    };
    const key = decryptKey(full);
    const known = this.#mergeEnvelopes.get(key);
    if (known === null) return { kind: "failed" };
    if (known !== undefined) return { kind: "decrypted", plaintext: copy(known) };
    this.#pendingMergeEnvelopes.set(key, full);
    return undefined;
  }

  derive(request: DeriveRequest): Bytes32 | undefined {
    const key = deriveKey(request);
    const known = this.#derived.get(key);
    if (known !== undefined) return copy(known);
    this.#pendingDerive.set(key, request);
    return undefined;
  }

  /** Owned by the memo until `destroy`; callers use it, they do not destroy it. */
  transactionKey(request: TransactionKeyRequest): ViewingKey | undefined {
    const key = `${hex(request.viewingPublicKey.toBytes())}|${hex(request.firstNullifier)}`;
    const known = this.#transactionKeys.get(key);
    if (known !== undefined) return known;
    this.#pendingTransactionKeys.set(key, {
      viewingPublicKey: request.viewingPublicKey,
      firstNullifier: copy(request.firstNullifier),
    });
    return undefined;
  }

  pending(): boolean {
    return (
      this.#pendingDecrypt.size > 0 ||
      this.#pendingMergeEnvelopes.size > 0 ||
      this.#pendingDerive.size > 0 ||
      this.#pendingTransactionKeys.size > 0
    );
  }

  async resolve(context?: RequestContext): Promise<void> {
    const decrypts = [...this.#pendingDecrypt.entries()];
    const derives = [...this.#pendingDerive.entries()];
    const transactionKeys = [...this.#pendingTransactionKeys.entries()];
    const mergeEnvelopes = [...this.#pendingMergeEnvelopes.entries()];
    this.#pendingDecrypt.clear();
    this.#pendingMergeEnvelopes.clear();
    this.#pendingDerive.clear();
    this.#pendingTransactionKeys.clear();
    // Settled, not raced: a rejection in one call must not lose the fresh keys
    // another call already handed out.
    const mergeAnswers = Promise.allSettled(
      mergeEnvelopes.map(async ([, request]) => this.#keys.decrypt([request], context)),
    );
    const settled = await Promise.allSettled([
      decrypts.length === 0
        ? []
        : this.#keys.decrypt(
            decrypts.map(([, request]) => request),
            context,
          ),
      derives.length === 0
        ? []
        : this.#keys.derive(
            derives.map(([, request]) => request),
            context,
          ),
      transactionKeys.length === 0
        ? []
        : this.#keys.transactionKeys(
            transactionKeys.map(([, request]) => request),
            context,
          ),
    ]);
    const minted = settled[2].status === "fulfilled" ? settled[2].value : [];
    try {
      const plaintexts = decodeBatch(
        fulfilled(settled[0]),
        decrypts.length,
        (value) => (value instanceof Uint8Array ? copy(value) : undefined),
        batchMismatch,
      );
      const derived = deriveAnswers(fulfilled(settled[1]), derives.length, batchMismatch);
      const keys = transactionKeyAnswers(
        fulfilled(settled[2]),
        transactionKeys.length,
        batchMismatch,
      );
      const envelopes = (await mergeAnswers).map((answer) => mergeEnvelopeAnswer(answer, context));
      plaintexts.forEach((plaintext, index) => {
        const request = decrypts[index];
        if (request !== undefined) this.#decrypted.set(request[0], plaintext);
      });
      envelopes.forEach((plaintext, index) => {
        const request = mergeEnvelopes[index];
        if (request !== undefined) this.#mergeEnvelopes.set(request[0], plaintext);
      });
      derived.forEach((value, index) => {
        const request = derives[index];
        if (request !== undefined) this.#derived.set(request[0], value);
      });
      keys.forEach((viewingKey, index) => {
        const request = transactionKeys[index];
        if (request !== undefined) this.#transactionKeys.set(request[0], viewingKey);
      });
    } catch (cause) {
      destroyTransactionKeys(minted);
      throw cause;
    }
  }

  destroy(): void {
    for (const key of this.#transactionKeys.values()) key.destroy();
    this.#transactionKeys.clear();
    for (const plaintext of this.#decrypted.values()) plaintext.fill(0);
    this.#decrypted.clear();
    for (const plaintext of this.#mergeEnvelopes.values()) plaintext?.fill(0);
    this.#mergeEnvelopes.clear();
    this.#derived.clear();
  }
}

function decryptKey(request: DecryptRequest): string {
  return [
    request.label,
    hex(request.viewingPublicKey.toBytes()),
    hex(request.txViewingPublicKey.toBytes()),
    hex(request.salt),
    String(request.slotIndex),
    hex(request.ciphertext),
    request.firstNullifier === undefined ? "" : hex(request.firstNullifier),
  ].join("|");
}

function deriveKey(request: DeriveRequest): string {
  switch (request.kind) {
    case "nullifier":
      return `nullifier|${hex(request.utxoHash)}|${hex(request.blinding)}`;
    case "mergeDummyNullifier":
      return `mergeDummy|${hex(request.firstNullifier)}|${String(request.slotIndex)}`;
    case "mergeOutputBlinding":
      return `mergeBlinding|${hex(request.firstNullifier)}`;
    case "mergePrivateTxBlinding":
      return `mergePrivateTxBlinding|${hex(request.firstNullifier)}`;
  }
}

function fulfilled<T>(result: PromiseSettledResult<T>): T {
  if (result.status === "rejected") {
    const cause: unknown = result.reason;
    throw cause;
  }
  return result.value;
}

/**
 * A rejection is the holder failing this one merge. A wrong-length answer is
 * a malformed response and fails the sync, as does a cancelled sync, which
 * must not read as a merge the holder could not decrypt.
 */
function mergeEnvelopeAnswer(
  answer: PromiseSettledResult<readonly Uint8Array[]>,
  context: RequestContext | undefined,
): Uint8Array | null {
  if (answer.status === "rejected") {
    if (context?.signal?.aborted === true) {
      const cause: unknown = answer.reason;
      throw cause;
    }
    return null;
  }
  const [plaintext] = decodeBatch(
    answer.value,
    1,
    (value) => (value instanceof Uint8Array ? value : undefined),
    batchMismatch,
  );
  if (plaintext === undefined) throw batchMismatch();
  if (plaintext.length !== DECRYPTED_MERGE_ENVELOPE_LENGTH) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "mergeEnvelope",
      expected: DECRYPTED_MERGE_ENVELOPE_LENGTH,
      actual: plaintext.length,
    });
  }
  return copy(plaintext);
}

function batchMismatch(): TransactionError {
  return new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH");
}
