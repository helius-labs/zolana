import { describe, expect, it, vi } from "vitest";
import { ClientError } from "../src/client/error.js";
import { createIndexerPollConfig } from "../src/client/retry.js";
import {
  HEAD_MAP_PROJECTION_ERRORS,
  KEY_REGISTRY_PROJECTION_ERRORS,
  waitForRingProjection,
} from "../src/ring/projection.js";

const IMMEDIATE_POLL = createIndexerPollConfig(2, 0n, 0n);

describe("ring projection consistency", () => {
  it("retries head-map and key-registry races", async () => {
    for (const [code, errors] of [
      ["CLIENT_HEAD_MAP_OUT_OF_SYNC", HEAD_MAP_PROJECTION_ERRORS],
      ["CLIENT_HEAD_ROOT_CHANGED", HEAD_MAP_PROJECTION_ERRORS],
      ["CLIENT_KEY_REGISTRY_OUT_OF_SYNC", KEY_REGISTRY_PROJECTION_ERRORS],
      ["CLIENT_KEY_REGISTRY_ROOT_CHANGED", KEY_REGISTRY_PROJECTION_ERRORS],
    ] as const) {
      const read = vi
        .fn<() => Promise<number>>()
        .mockRejectedValueOnce(new ClientError(code, { details: { method: "projection" } }))
        .mockResolvedValue(7);
      await expect(waitForRingProjection(read, errors, undefined, IMMEDIATE_POLL)).resolves.toBe(7);
      expect(read).toHaveBeenCalledTimes(2);
    }
  });

  it("returns the last projection error after the bounded wait", async () => {
    const last = new ClientError("CLIENT_HEAD_MAP_OUT_OF_SYNC", {
      details: { method: "projection" },
    });
    const read = vi.fn<() => Promise<never>>().mockRejectedValue(last);
    await expect(
      waitForRingProjection(read, HEAD_MAP_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
    ).rejects.toBe(last);
    expect(read).toHaveBeenCalledTimes(3);
  });

  it("bounds a projection read that stops answering", async () => {
    const last = new ClientError("CLIENT_HEAD_MAP_OUT_OF_SYNC", {
      details: { method: "projection" },
    });
    const read = vi
      .fn<() => Promise<number>>()
      .mockRejectedValueOnce(last)
      .mockReturnValue(new Promise<never>(() => {}));
    await expect(
      waitForRingProjection(read, HEAD_MAP_PROJECTION_ERRORS, { timeoutMs: 10 }, IMMEDIATE_POLL),
    ).rejects.toBe(last);
    expect(read).toHaveBeenCalledTimes(2);
  });

  it("does not retry terminal projection answers", async () => {
    const terminal = new ClientError("CLIENT_HEAD_MEMBER_UNREGISTERED", {
      details: { method: "projection" },
    });
    const read = vi.fn<() => Promise<never>>().mockRejectedValue(terminal);
    await expect(
      waitForRingProjection(read, HEAD_MAP_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
    ).rejects.toBe(terminal);
    expect(read).toHaveBeenCalledOnce();
  });
});
