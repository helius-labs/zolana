import { type Bytes32, checkedBytes, u32Field } from "../bytes.js";
import {
  DOMAIN_PRIVATE_TX_BLINDING_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1,
  DOMAIN_TRANSACT_OUTPUT_BLINDING_V1,
  DOMAIN_TRANSACT_RING_OUTPUT_BLINDING_V1,
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
    u32Field(DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1, "domain"),
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
    u32Field(DOMAIN_PRIVATE_TX_BLINDING_V1, "domain"),
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
  return poseidon([
    u32Field(DOMAIN_TRANSACT_OUTPUT_BLINDING_V1, "domain"),
    checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(outputBlindingSeed, 32, "output blinding seed"),
    u32Field(index, "index"),
  ]) as Bytes32;
}

/** Rust `RingOutputBlinding`, the audit proof binds `ringSecret` to its slot and SPP never does. */
export interface RingOutputBlinding {
  readonly firstNullifier: Bytes32;
  readonly ringSecret: Bytes32;
  readonly outputIndex: number;
}

/** `Poseidon("TXRB", first_nullifier, ring_secret, index)`. */
export function ringOutputBlinding(input: RingOutputBlinding): Bytes32 {
  return poseidon([
    u32Field(DOMAIN_TRANSACT_RING_OUTPUT_BLINDING_V1, "domain"),
    checkedBytes<Bytes32>(input.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(input.ringSecret, 32, "ring secret"),
    u32Field(input.outputIndex, "outputIndex"),
  ]) as Bytes32;
}
