import { afterEach, describe, expect, it, vi } from "vitest";

import { noteTiming, resetTimingEnabledForTests, timePhase, timingEnabled } from "../src/timing.js";

afterEach(() => {
  delete process.env["ZOLANA_TIMING"];
  resetTimingEnabledForTests();
  vi.restoreAllMocks();
});

describe("timing", () => {
  it("stays off when ZOLANA_TIMING is unset", async () => {
    expect(timingEnabled()).toBe(false);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(timePhase("photon.getIndexerSlot", async () => 7)).resolves.toBe(7);
    noteTiming("ignored", 1);
    expect(error).not.toHaveBeenCalled();
  });

  it("prints phase ms when ZOLANA_TIMING is set", async () => {
    process.env["ZOLANA_TIMING"] = "1";
    resetTimingEnabledForTests();
    expect(timingEnabled()).toBe(true);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(timePhase("photon.getMerkleProofs", async () => "ok")).resolves.toBe("ok");
    expect(error).toHaveBeenCalledOnce();
    expect(String(error.mock.calls[0]?.[0])).toMatch(/^timing phase=photon\.getMerkleProofs ms=\d+ ok$/u);
  });

  it("prints err when the timed call throws", async () => {
    process.env["ZOLANA_TIMING"] = "";
    resetTimingEnabledForTests();
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(
      timePhase("photon.getUserRecords", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(String(error.mock.calls[0]?.[0])).toMatch(/^timing phase=photon\.getUserRecords ms=\d+ err$/u);
  });
});
