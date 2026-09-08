import type { Bytes32, RequestContext } from "../../interface/types.js";
import { ViewingKey } from "../../keypair/viewing-key.js";

import { TransactionError } from "../error.js";
import { checked, copy } from "../internal.js";
import type { DecryptRequest, DeriveRequest, ShieldedKeys, TransactionKeyRequest } from "./keys.js";
import { hex } from "./state.js";

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
  readonly #derived = new Map<string, Bytes32>();
  readonly #transactionKeys = new Map<string, ViewingKey>();
  readonly #pendingDecrypt = new Map<string, DecryptRequest>();
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
    });
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
      this.#pendingDerive.size > 0 ||
      this.#pendingTransactionKeys.size > 0
    );
  }

  async resolve(context?: RequestContext): Promise<void> {
    const decrypts = [...this.#pendingDecrypt.entries()];
    const derives = [...this.#pendingDerive.entries()];
    const transactionKeys = [...this.#pendingTransactionKeys.entries()];
    this.#pendingDecrypt.clear();
    this.#pendingDerive.clear();
    this.#pendingTransactionKeys.clear();
    // Settled, not raced: a rejection in one call must not lose the fresh keys
    // another call already handed out.
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
      const plaintexts = checkedAnswers(fulfilled(settled[0]), decrypts.length, (value) =>
        value instanceof Uint8Array ? copy(value) : undefined,
      );
      const derived = checkedAnswers(fulfilled(settled[1]), derives.length, (value) =>
        value instanceof Uint8Array && value.length === 32
          ? copy(checked<Bytes32>(value, 32, "derived value"))
          : undefined,
      );
      const keys = checkedAnswers(fulfilled(settled[2]), transactionKeys.length, (value) =>
        value instanceof ViewingKey ? value : undefined,
      );
      plaintexts.forEach((plaintext, index) => {
        const request = decrypts[index];
        if (request !== undefined) this.#decrypted.set(request[0], plaintext);
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
      for (const key of minted) key.destroy();
      throw cause;
    }
  }

  destroy(): void {
    for (const key of this.#transactionKeys.values()) key.destroy();
    this.#transactionKeys.clear();
    for (const plaintext of this.#decrypted.values()) plaintext.fill(0);
    this.#decrypted.clear();
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
 * A batch answer read by index: the promised count, every entry of the
 * promised shape. A hole or a short answer is refused as a whole, because a
 * request left unanswered would be asked again forever. `every` and `forEach`
 * skip the holes of a sparse array, so the read is positional.
 */
function checkedAnswers<T>(
  values: readonly unknown[],
  count: number,
  answer: (value: unknown) => T | undefined,
): readonly T[] {
  if (values.length !== count) throw new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH");
  return Array.from({ length: count }, (_, index) => {
    const value = answer(values[index]);
    if (value === undefined) throw new TransactionError("TRANSACTION_KEYS_BATCH_MISMATCH");
    return value;
  });
}
