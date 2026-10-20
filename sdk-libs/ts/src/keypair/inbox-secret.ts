import { equalBytes } from "@noble/ciphers/utils.js";

import { type Bytes32, checkedBytes, copyBytes } from "./bytes.js";
import { checkedCounter, inboxViewTag } from "./derivation.js";
import type { ViewTag } from "./public-key.js";

/** Holding it lets a payer derive the recipient's inbox tags. */
export class InboxSecret {
  readonly #bytes: Bytes32;

  private constructor(bytes: Bytes32) {
    this.#bytes = bytes;
  }

  static fromBytes(bytes: Uint8Array): InboxSecret {
    return new InboxSecret(checkedBytes<Bytes32>(bytes, 32, "inbox secret"));
  }

  toBytes(): Bytes32 {
    return copyBytes(this.#bytes) as Bytes32;
  }

  equals(other: InboxSecret): boolean {
    return equalBytes(this.#bytes, other.#bytes);
  }

  /** Tag of the `j`th first payment to the address. */
  viewTag(j: bigint | number): ViewTag {
    return inboxViewTag(this.#bytes, checkedCounter(j, "j"));
  }
}
