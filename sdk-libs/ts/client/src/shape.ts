export interface Shape {
  nInputs: number;
  nOutputs: number;
}

export const SUPPORTED_SHAPES: readonly Shape[] = [
  { nInputs: 1, nOutputs: 1 },
  { nInputs: 1, nOutputs: 2 },
  { nInputs: 2, nOutputs: 2 },
  { nInputs: 2, nOutputs: 3 },
  { nInputs: 3, nOutputs: 3 },
  { nInputs: 4, nOutputs: 3 },
  { nInputs: 4, nOutputs: 4 },
  { nInputs: 5, nOutputs: 3 },
  { nInputs: 5, nOutputs: 4 },
  { nInputs: 1, nOutputs: 8 },
];

export function canonicalShape(nInputs: number, nOutputs: number): Shape {
  const shape = SUPPORTED_SHAPES.find(
    (candidate) => nInputs <= candidate.nInputs && nOutputs <= candidate.nOutputs,
  );
  if (!shape) throw new Error(`no supported circuit shape holds ${nInputs} inputs and ${nOutputs} outputs`);
  return shape;
}

export function resolveShape(declared: Shape | undefined, nInputs: number, nOutputs: number): Shape {
  if (!declared) return canonicalShape(nInputs, nOutputs);
  if (!SUPPORTED_SHAPES.some((shape) => shape.nInputs === declared.nInputs && shape.nOutputs === declared.nOutputs)) {
    throw new Error(`unsupported circuit shape ${declared.nInputs}x${declared.nOutputs}`);
  }
  if (nInputs > declared.nInputs) throw new Error(`too many inputs: got ${nInputs}, max ${declared.nInputs}`);
  if (nOutputs > declared.nOutputs) throw new Error(`too many outputs: got ${nOutputs}, max ${declared.nOutputs}`);
  return declared;
}
