import { describe, expect, it, vi } from "vitest";
import { ClientError } from "../src/client/error.js";
import { createIndexerPollConfig } from "../src/client/retry.js";
import { KEY_REGISTRY_PROJECTION_ERRORS, waitForRingProjection } from "../src/ring/projection.js";

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
        waitForRingProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
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
      waitForRingProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
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
      waitForRingProjection(
        read,
        KEY_REGISTRY_PROJECTION_ERRORS,
        { timeoutMs: 10 },
        IMMEDIATE_POLL,
      ),
    ).rejects.toBe(last);
    expect(read).toHaveBeenCalledTimes(2);
  });

  it("does not retry terminal projection answers", async () => {
    const terminal = new ClientError("CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED", {
      details: { method: "projection" },
    });
    const read = vi.fn<() => Promise<never>>().mockRejectedValue(terminal);
    await expect(
      waitForRingProjection(read, KEY_REGISTRY_PROJECTION_ERRORS, undefined, IMMEDIATE_POLL),
    ).rejects.toBe(terminal);
    expect(read).toHaveBeenCalledOnce();
  });
});
