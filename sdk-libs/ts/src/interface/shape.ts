import { InterfaceError } from "./errors.js";
import { SPP_SUPPORTED_SHAPES } from "./generated/shapes.js";

export { SPP_SUPPORTED_SHAPES };

export type Shape = Readonly<{
  inputs: number;
  outputs: number;
}>;

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
