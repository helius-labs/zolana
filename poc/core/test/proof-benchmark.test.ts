import { describe, expect, it } from "vitest";
import { proofStatistics } from "../src/proof-benchmark.js";

describe("proof benchmark statistics", () => {
  it("retains the slow tail of a 30-proof session", () => {
    const samples = [...Array<number>(28).fill(100), 1400, 2500];
    expect(proofStatistics(samples)).toEqual({
      count: 30,
      p50Ms: 100,
      p95Ms: 1400,
      maxMs: 2500,
      underOneSecond: 28,
      p95UnderOneSecond: false,
    });
    expect(samples[29]).toBe(2500);
  });
  it("uses the midpoint for an even sample count and nearest rank for p95", () => {
    expect(proofStatistics([4, 1, 3, 2])).toMatchObject({ p50Ms: 2.5, p95Ms: 4 });
  });
  it("does not treat exactly one second as under one second", () => {
    expect(proofStatistics([1000])).toMatchObject({ p95UnderOneSecond: false, underOneSecond: 0 });
    expect(proofStatistics([999.9])).toMatchObject({ p95UnderOneSecond: true });
  });
  it.each([[], [-1], [NaN], [Infinity]].map((values) => ({ values })))(
    "rejects invalid timings: $values",
    ({ values }) => {
      expect(() => proofStatistics(values)).toThrow();
    },
  );
});
