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
