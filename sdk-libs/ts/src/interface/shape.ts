import { InterfaceError } from "./errors.js";

export type Shape = Readonly<{
  inputs: number;
  outputs: number;
}>;

function shape(inputs: number, outputs: number): Shape {
  return Object.freeze({ inputs, outputs });
}

/**
 * Shapes the SPP prover has keys for, ordered by proving cost so the first
 * shape that fits is the cheapest. Mirrors Rust `SPP_SUPPORTED_SHAPES`.
 */
export const SPP_SUPPORTED_SHAPES: readonly Shape[] = Object.freeze([
  shape(1, 2),
  shape(1, 4),
  shape(1, 8),
  shape(2, 2),
  shape(2, 4),
  shape(1, 16),
  shape(2, 8),
  shape(3, 2),
  shape(3, 4),
  shape(2, 16),
  shape(3, 8),
  shape(4, 2),
  shape(4, 4),
  shape(4, 8),
  shape(5, 2),
  shape(5, 4),
  shape(4, 16),
  shape(5, 8),
  shape(6, 2),
  shape(6, 4),
  shape(5, 16),
  shape(6, 8),
  shape(8, 2),
  shape(8, 4),
  shape(8, 8),
  shape(8, 16),
  shape(12, 2),
  shape(12, 4),
  shape(12, 8),
  shape(16, 2),
  shape(16, 4),
  shape(16, 8),
  shape(24, 2),
  shape(24, 4),
  shape(32, 2),
  shape(40, 2),
  shape(48, 2),
  shape(49, 2),
]);

/**
 * Shapes the in-circuit EdDSA confidential rail has keys for, ordered by
 * proving cost. Mirrors Rust `CONFIDENTIAL_EDDSA_SHAPES`.
 */
export const CONFIDENTIAL_EDDSA_SHAPES: readonly Shape[] = Object.freeze([
  shape(2, 8),
  shape(2, 16),
  shape(4, 8),
  shape(4, 16),
  shape(8, 8),
  shape(8, 16),
  shape(16, 8),
  shape(16, 16),
  shape(24, 8),
  shape(24, 16),
  shape(48, 8),
  shape(48, 16),
]);

function count(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", { [name]: value });
  }
  return value;
}

/** The widest input count of any supported shape, Rust `MAX_TRANSACT_INPUTS`. */
export const MAX_TRANSACT_INPUTS = Math.max(...SPP_SUPPORTED_SHAPES.map((entry) => entry.inputs));

/**
 * Square widths the ring authority rail has keys for, ascending, mirroring Rust
 * `RING_AUTHORITY_WIDTHS`.
 */
export const RING_AUTHORITY_WIDTHS: readonly number[] = Object.freeze([2, 4]);

/** The widest authority-rail transfer, inputs and outputs alike. */
export const RING_AUTHORITY_MAX_WIDTH = Math.max(...RING_AUTHORITY_WIDTHS);

/** The narrowest authority width holding `width` slots, undefined above the widest. */
export function ringAuthorityWidth(width: number): number | undefined {
  count(width, "width");
  return RING_AUTHORITY_WIDTHS.find((supported) => supported >= width);
}

/** Distinct addresses one transaction can carry, `solana_message::v1::MAX_ADDRESSES`. */
export const MAX_TRANSACTION_ADDRESSES = 64;

/**
 * Addresses every transact needs besides its nullifier accounts and owner
 * signers: payer, input tree (the output tree may coincide with it), the
 * shielded-pool program and the system program.
 */
export const FIXED_TRANSACT_ADDRESSES = 4;

/**
 * Owner signer slots the public signer vector reserves for `inputs` inputs: one
 * per input, capped by the addresses a transaction has left after the fixed
 * accounts and one nullifier account per input.
 */
export function ownerSignerSlots(inputs: number): number {
  count(inputs, "inputs");
  const remaining = Math.max(0, MAX_TRANSACTION_ADDRESSES - FIXED_TRANSACT_ADDRESSES - inputs);
  return Math.min(inputs, remaining);
}

/**
 * Slots in the public signer vector: the unique Ed25519 and PDA owners of
 * inputs and of outputs that carry data, zero padded. The payer holds no slot of its own; the extra slot covers an owner
 * that also pays, which costs no additional transaction address.
 */
export function signerWidth(shape: Shape): number {
  return ownerSignerSlots(shape.inputs) + 1;
}

export function selectSppShape(inputs: number, outputs: number): Shape {
  count(inputs, "inputs");
  count(outputs, "outputs");
  const selected = SPP_SUPPORTED_SHAPES.find(
    (candidate) => inputs <= candidate.inputs && outputs <= candidate.outputs,
  );
  if (selected === undefined) {
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", { inputs, outputs });
  }
  return selected;
}

/** Whether the in-circuit EdDSA rail has keys for `shape`, Rust `Shape::is_confidential_eddsa`. */
export function isConfidentialEddsaShape(shape: Shape): boolean {
  return CONFIDENTIAL_EDDSA_SHAPES.some(
    (candidate) => candidate.inputs === shape.inputs && candidate.outputs === shape.outputs,
  );
}

/** Whether the signer, ring and ring authority rails have keys for `shape`, Rust `Shape::is_supported`. */
export function isSppShape(shape: Shape): boolean {
  return SPP_SUPPORTED_SHAPES.some(
    (candidate) => candidate.inputs === shape.inputs && candidate.outputs === shape.outputs,
  );
}

/** Whether some transact rail has keys for `shape`, Rust `is_transact_shape`. */
export function isTransactShape(shape: Shape): boolean {
  return isSppShape(shape) || isConfidentialEddsaShape(shape);
}

/** The cheapest in-circuit EdDSA shape holding `inputs` and `outputs`. */
export function selectConfidentialEddsaShape(inputs: number, outputs: number): Shape {
  count(inputs, "inputs");
  count(outputs, "outputs");
  const selected = CONFIDENTIAL_EDDSA_SHAPES.find(
    (candidate) => inputs <= candidate.inputs && outputs <= candidate.outputs,
  );
  if (selected === undefined) {
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", { inputs, outputs });
  }
  return selected;
}

export function validateSppShape(inputs: number, outputs: number, declared: Shape): Shape {
  count(inputs, "inputs");
  count(outputs, "outputs");
  count(declared.inputs, "declaredInputs");
  count(declared.outputs, "declaredOutputs");
  const canonical = SPP_SUPPORTED_SHAPES.find(
    (candidate) => candidate.inputs === declared.inputs && candidate.outputs === declared.outputs,
  );
  if (canonical === undefined || inputs > declared.inputs || outputs > declared.outputs) {
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", {
      inputs,
      outputs,
      declaredInputs: declared.inputs,
      declaredOutputs: declared.outputs,
    });
  }
  return canonical;
}
