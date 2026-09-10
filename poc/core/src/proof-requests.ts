import { keyForProveRequest, type ShapeKey } from "./shapes.js";
import { abortable } from "./abortable.js";

/** Observe only public circuit metadata; never retain the witness body. */
export function observeProofRequests(
  fetch: typeof globalThis.fetch,
  proverUrl: string,
  onShape: (shape: ShapeKey) => void,
): typeof globalThis.fetch {
  const endpoint = new URL(proverUrl);
  endpoint.pathname = `${endpoint.pathname.replace(/\/+$/u, "")}/prove`;
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin === endpoint.origin && url.pathname === endpoint.pathname) {
      const signal =
        init?.signal !== undefined
          ? (init.signal ?? undefined)
          : input instanceof Request
            ? input.signal
            : undefined;
      signal?.throwIfAborted();
      const body =
        typeof init?.body === "string"
          ? init.body
          : input instanceof Request
            ? await abortable(input.clone().text(), signal)
            : undefined;
      if (body !== undefined) {
        const shape = proofRequestShape(body);
        if (shape !== undefined) onShape(shape);
      }
    }
    return fetch(input, init);
  };
}

export function proofRequestShape(body: string): ShapeKey | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !("circuitType" in parsed) ||
      typeof parsed.circuitType !== "string"
    )
      return undefined;
    if (parsed.circuitType === "merge" || parsed.circuitType === "merge-ring") {
      return keyForProveRequest(parsed.circuitType, 8, 1);
    }
    if (
      !("nInputs" in parsed) ||
      !("nOutputs" in parsed) ||
      typeof parsed.nInputs !== "number" ||
      typeof parsed.nOutputs !== "number"
    )
      return undefined;
    return keyForProveRequest(parsed.circuitType, parsed.nInputs, parsed.nOutputs);
  } catch {
    return undefined;
  }
}
