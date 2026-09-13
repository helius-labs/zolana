import { InterfaceError } from "./errors.js";

export type Shape = Readonly<{
  inputs: number;
  outputs: number;
}>;

function shape(inputs: number, outputs: number): Shape {
  return Object.freeze({ inputs, outputs });
}

export const SPP_SUPPORTED_SHAPES: readonly Shape[] = Object.freeze([
  shape(1, 1),
  shape(1, 2),
  shape(2, 2),
  shape(2, 3),
  shape(3, 3),
  shape(4, 3),
  shape(4, 4),
  shape(5, 3),
  shape(5, 4),
  shape(1, 8),
]);

function count(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", { [name]: value });
  }
  return value;
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

/** Slots in the public signer vector: the payer followed by the owner signer slots. */
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
