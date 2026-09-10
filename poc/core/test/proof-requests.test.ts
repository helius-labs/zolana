import { expect, it, vi } from "vitest";
import { observeProofRequests, proofRequestShape } from "../src/proof-requests.js";

it.each(["string", "request"])(
  "records the actual circuit shape from a %s without consuming the request body",
  async (kind) => {
    const body = JSON.stringify({
      circuitType: "transfer-confidential",
      nInputs: 2,
      nOutputs: 3,
      secret: "never report this",
    });
    const shapes = vi.fn();
    const downstream = vi.fn<typeof globalThis.fetch>(async (input, init) => {
      expect(input instanceof Request ? await input.text() : init?.body).toBe(body);
      return Response.json({});
    });
    const fetch = observeProofRequests(downstream, "http://localhost/proxy/prover", shapes);
    if (kind === "request")
      await fetch(new Request("http://localhost/proxy/prover/prove", { method: "POST", body }));
    else await fetch("http://localhost/proxy/prover/prove", { method: "POST", body });
    expect(shapes).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ label: "2x3" }));
    expect(JSON.stringify(shapes.mock.calls)).not.toContain("secret");
    expect(downstream).toHaveBeenCalledTimes(1);
  },
);
it("does not attribute other services' prove requests to the benchmark", async () => {
  const shapes = vi.fn();
  const downstream = vi.fn<typeof globalThis.fetch>(async () => Response.json({}));
  const fetch = observeProofRequests(downstream, "http://localhost/prover", shapes);
  await fetch("http://localhost/other/prove", {
    method: "POST",
    body: '{"circuitType":"transfer-confidential","nInputs":5,"nOutputs":3}',
  });
  expect(shapes).not.toHaveBeenCalled();
  expect(downstream).toHaveBeenCalledTimes(1);
});
it("does not coerce malformed shape declarations", () => {
  expect(
    proofRequestShape('{"circuitType":"transfer-confidential","nInputs":"2","nOutputs":3}'),
  ).toBeUndefined();
  expect(proofRequestShape("null")).toBeUndefined();
  expect(proofRequestShape("{")).toBeUndefined();
});
