import { type Bytes32, checkedBytes } from "../bytes.js";
import {
  DOMAIN_PRIVATE_TX_BLINDING_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
} from "../derivation.js";
import { poseidon } from "../poseidon.js";

/**
 * The transact-proof blinding family. A client samples one private
 * `blindingSeed` per proof; the circuit derives everything else from it and
 * the published nullifier of input slot 0, so a client can disclose
 * `outputBlindingSeed` to a reader without revealing `privateTxBlinding`.
 * Mirrors `zolana_program::derivation`.
 */

/** `Poseidon("TXOS", first_nullifier, blinding_seed)`. */
export function outputBlindingSeed(firstNullifier: Bytes32, blindingSeed: Bytes32): Bytes32 {
  return poseidon([
    fieldU32(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(blindingSeed, 32, "blinding seed"),
  ]) as Bytes32;
}

/**
 * `Poseidon("TXPB", first_nullifier, secret)`. The transact rails pass the
 * proof's `blindingSeed`; merge passes the owner's right-aligned nullifier
 * secret.
 */
export function privateTxBlinding(firstNullifier: Bytes32, secret: Bytes32): Bytes32 {
  return poseidon([
    fieldU32(DOMAIN_PRIVATE_TX_BLINDING_V1),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(secret, 32, "private tx blinding secret"),
  ]) as Bytes32;
}

/**
 * `Poseidon("TXOB", first_nullifier, output_blinding_seed, index)`: the
 * blinding of the output in slot `index`, padding slots included. The circuit
 * asserts this for every output, so a reader holding the derived seed and the
 * first nullifier recovers every output blinding.
 */
export function transactOutputBlinding(
  firstNullifier: Bytes32,
  outputBlindingSeed: Bytes32,
  index: number,
): Bytes32 {
  if (!Number.isInteger(index) || index < 0 || index > 0xffff_ffff) {
    throw new RangeError("transact output index must fit in u32");
  }
  return poseidon([
    fieldU32(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(outputBlindingSeed, 32, "output blinding seed"),
    fieldU32(index),
  ]) as Bytes32;
}

function fieldU32(value: number): Bytes32 {
  const field = new Uint8Array(32);
  new DataView(field.buffer).setUint32(28, value, false);
  return field as Bytes32;
}
