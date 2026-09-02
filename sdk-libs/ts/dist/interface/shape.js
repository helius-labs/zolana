import { InterfaceError } from "./errors.js";
function shape(inputs, outputs) {
    return Object.freeze({ inputs, outputs });
}
export const SPP_SUPPORTED_SHAPES = Object.freeze([
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
function count(value, name) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new InterfaceError("INTERFACE_INVALID_SHAPE", { [name]: value });
    }
    return value;
}
export function selectSppShape(inputs, outputs) {
    count(inputs, "inputs");
    count(outputs, "outputs");
    const selected = SPP_SUPPORTED_SHAPES.find((candidate) => inputs <= candidate.inputs && outputs <= candidate.outputs);
    if (selected === undefined) {
        throw new InterfaceError("INTERFACE_INVALID_SHAPE", { inputs, outputs });
    }
    return selected;
}
export function validateSppShape(inputs, outputs, declared) {
    count(inputs, "inputs");
    count(outputs, "outputs");
    count(declared.inputs, "declaredInputs");
    count(declared.outputs, "declaredOutputs");
    const canonical = SPP_SUPPORTED_SHAPES.find((candidate) => candidate.inputs === declared.inputs && candidate.outputs === declared.outputs);
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
