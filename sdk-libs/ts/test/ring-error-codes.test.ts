import { describe, expect, it } from "vitest";

import { RING_ERROR_CODES } from "../src/ring/error.js";

describe("ring error codes", () => {
  it("pins the public codes and their order", () => {
    expect(new Set(RING_ERROR_CODES).size).toBe(RING_ERROR_CODES.length);
    expect(RING_ERROR_CODES).toMatchSnapshot();
  });
});
