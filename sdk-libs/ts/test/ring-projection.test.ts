import { describe, expect, it, vi } from "vitest";
import { ClientError } from "../src/client/error.js";
import { createIndexerPollConfig, waitForProjection } from "../src/client/retry.js";
import { KEY_REGISTRY_PROJECTION_ERRORS } from "../src/ring/projection.js";

const IMMEDIATE_POLL = createIndexerPollConfig(2, 0n, 0n);

describe("ring projection consistency", () => {
  it("retries key-registry races", async () => {
    for (const code of [
      "CLIENT_KEY_REGISTRY_OUT_OF_SYNC",
      "CLIENT_KEY_REGISTRY_ROOT_CHANGED",
    ] as const) {
      const read = vi
        .fn<() => Promise<number>>()
        .mockRejectedValueOnce(new ClientError(code, { details: { method: "projection" } }))
        .mockResolvedValue(7);
      await expect(
        waitForProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
      ).resolves.toBe(7);
      expect(read).toHaveBeenCalledTimes(2);
    }
  });

  it("returns the last projection error after the bounded wait", async () => {
    const last = new ClientError("CLIENT_KEY_REGISTRY_OUT_OF_SYNC", {
      details: { method: "projection" },
    });
    const read = vi.fn<() => Promise<never>>().mockRejectedValue(last);
    await expect(
      waitForProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
    ).rejects.toBe(last);
    expect(read).toHaveBeenCalledTimes(3);
  });

  it("bounds a projection read that stops answering", async () => {
    const last = new ClientError("CLIENT_KEY_REGISTRY_OUT_OF_SYNC", {
      details: { method: "projection" },
    });
    const read = vi
      .fn<() => Promise<number>>()
      .mockRejectedValueOnce(last)
      .mockReturnValue(new Promise<never>(() => {}));
    await expect(
      waitForProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, { timeoutMs: 10 }, IMMEDIATE_POLL),
    ).rejects.toBe(last);
    expect(read).toHaveBeenCalledTimes(2);
  });

  it("does not retry terminal projection answers", async () => {
    const terminal = new ClientError("CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED", {
      details: { method: "projection" },
    });
    const read = vi.fn<() => Promise<never>>().mockRejectedValue(terminal);
    await expect(
      waitForProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
    ).rejects.toBe(terminal);
    expect(read).toHaveBeenCalledOnce();
  });

  it("allows a proof deadline longer than the projection deadline", async () => {
    vi.useFakeTimers();
    try {
      const read = vi.fn(async () => {
        await new Promise((resolve) => setTimeout(resolve, 130_000));
        return 7;
      });
      const result = expect(
        waitForProjection(
          read,
          new Set(["CLIENT_INDEXER_PROOF_DATA_NOT_READY"]),
          { timeoutMs: 180_000 },
          IMMEDIATE_POLL,
          180_000,
        ),
      ).resolves.toBe(7);
      await vi.advanceTimersByTimeAsync(130_000);
      await result;
      expect(read).toHaveBeenCalledOnce();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
