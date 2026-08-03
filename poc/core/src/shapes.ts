/**
 * The transfer circuit shapes and the proving keys that back them.
 *
 * The shape list mirrors `SPP_SUPPORTED_SHAPES` in the SDK, `SupportedShapes` in
 * `prover-test/spp/protocol/shape.go`, and the on-chain verifier -- smallest
 * capacity first, so the order doubles as the smallest-fit search order.
 *
 * The sizes below exist only so the UI can total them before fetching anything.
 * `keys/manifest.json`, generated from `proving-keys.lock` by `just poc-keys`, is
 * what a downloaded key is actually validated against -- a key rotation changes
 * every size and digest, and a copy in source silently goes stale across a
 * rebase.
 */

export interface Shape {
  readonly inputs: number;
  readonly outputs: number;
}

export interface ShapeKey extends Shape {
  /** `<in>x<out>`, the label used in the UI and benchmark tables. */
  readonly label: string;
  /** Proving-key file name, matching the CloudFront/S3 object name. */
  readonly keyFile: string;
  /** Proving-key size in bytes, from the committed lockfile. */
  readonly keyBytes: number;
}

function entry(inputs: number, outputs: number, keyBytes: number): ShapeKey {
  return Object.freeze({
    inputs,
    outputs,
    label: `${String(inputs)}x${String(outputs)}`,
    keyFile: `transfer_confidential_${String(inputs)}_${String(outputs)}.key`,
    keyBytes,
  });
}

/**
 * The confidential (default transact) rail, which is what the SDK's wallet
 * actions use. The zone and zone-authority rails have their own keys but the
 * TypeScript SDK does not expose policy-zone instructions, so they are out of
 * scope here.
 */
export const TRANSFER_SHAPES: readonly ShapeKey[] = Object.freeze([
  entry(1, 1, 8_137_200),
  entry(1, 2, 8_670_630),
  entry(2, 2, 15_815_922),
  entry(2, 3, 16_353_833),
  entry(3, 3, 24_544_523),
  entry(4, 3, 30_647_356),
  entry(4, 4, 31_187_126),
  entry(5, 3, 36_748_624),
  entry(5, 4, 37_290_475),
  entry(1, 8, 12_940_377),
]);

export const MERGE_KEY_FILE = "merge_8_1.key";
export const MERGE_KEY_BYTES = 56_250_158;

/** The merge circuit as a ShapeKey, so one loader handles both proof kinds. */
export const MERGE_SHAPE: ShapeKey = Object.freeze({
  inputs: 8,
  outputs: 1,
  label: "merge 8x1",
  keyFile: MERGE_KEY_FILE,
  keyBytes: MERGE_KEY_BYTES,
});

/**
 * The proving key a `/prove` request needs, resolved from the request itself
 * rather than guessed ahead of time.
 *
 * The protocol derives the shape from the real input/output counts with a
 * smallest-fit rule, so a caller cannot reliably predict which key a given
 * transfer will use; reading it off the request is the only way to be right.
 * Mirrors the server's LazyKeyManager cache key.
 */
export function keyForProveRequest(
  circuitType: string,
  inputs: number,
  outputs: number,
): ShapeKey | undefined {
  if (circuitType === "merge" || circuitType === "merge-ring") return MERGE_SHAPE;
  if (circuitType !== "transfer-confidential") return undefined;
  return TRANSFER_SHAPES.find(
    (shape) => shape.inputs === inputs && shape.outputs === outputs,
  );
}

/** Smallest shape that holds `inputs`/`outputs`, matching `CanonicalShape`. */
export function canonicalShape(inputs: number, outputs: number): ShapeKey {
  const found = TRANSFER_SHAPES.find(
    (shape) => inputs <= shape.inputs && outputs <= shape.outputs,
  );
  if (found === undefined) {
    throw new Error(`no supported shape holds ${String(inputs)}x${String(outputs)}`);
  }
  return found;
}

export function shapeByLabel(label: string): ShapeKey {
  const found = TRANSFER_SHAPES.find((shape) => shape.label === label);
  if (found === undefined) throw new Error(`unknown shape ${label}`);
  return found;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${String(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
