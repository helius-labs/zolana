import {
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  STATE_HEIGHT,
  STATE_ROOT_OFFSET,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  UTXO_ROOT_HISTORY_CAPACITY,
  UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
  UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  UTXO_SUBTREES_LEN_OFFSET,
} from "../../src/interface/index.js";

export function filled(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte);
}

/** Roots in utxo slots `0..written`, every nullifier slot filled. */
export function treeAccount(
  input: Readonly<{ stateCursor: number; written: number; nullifierCursor: bigint }>,
): Uint8Array {
  const account = new Uint8Array(TREE_ACCOUNT_SIZE);
  account[0] = StateDiscriminator.treeAccount;
  account.set(
    Uint8Array.of(input.stateCursor & 0xff, input.stateCursor >> 8),
    UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  );
  account.set(
    Uint8Array.of(input.written & 0xff, input.written >> 8),
    UTXO_ROOT_HISTORY_LEN_OFFSET,
  );
  new DataView(account.buffer).setUint16(
    UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
    UTXO_ROOT_HISTORY_CAPACITY,
    true,
  );
  account[UTXO_SUBTREES_LEN_OFFSET] = STATE_HEIGHT;
  account.set(filled(0x10 + (input.stateCursor % 16)), STATE_ROOT_OFFSET);
  for (let index = 0; index < input.written; index += 1) {
    account.set(filled(0x10 + (index % 16)), UTXO_ROOT_HISTORY_OFFSET + index * 32);
  }
  let cursor = input.nullifierCursor;
  for (let index = 0; index < 8; index += 1) {
    account[NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET + index] = Number(cursor & 0xffn);
    cursor >>= 8n;
  }
  for (let index = 0; index < NULLIFIER_TREE_ROOT_HISTORY_CAPACITY; index += 1) {
    account.set(filled(0x20 + (index % 16)), NULLIFIER_ROOT_HISTORY_OFFSET + index * 32);
  }
  return account;
}
