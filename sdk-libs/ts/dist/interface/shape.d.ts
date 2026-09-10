export type Shape = Readonly<{
    inputs: number;
    outputs: number;
}>;
export declare const SPP_SUPPORTED_SHAPES: readonly Shape[];
export declare function selectSppShape(inputs: number, outputs: number): Shape;
export declare function validateSppShape(inputs: number, outputs: number, declared: Shape): Shape;
