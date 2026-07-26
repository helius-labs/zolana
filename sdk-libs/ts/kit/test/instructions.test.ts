import * as zolana from "@zolana/interface/instructions";
import { describe, expect, it } from "vitest";

import * as kit from "../src/instructions/index.js";

describe("instruction builder parity", () => {
  it("mirrors the builders @zolana/interface publishes", () => {
    expect(Object.keys(kit).sort()).toEqual(Object.keys(zolana).sort());
  });

  it("publishes seventeen callable builders", () => {
    const names = Object.keys(kit) as (keyof typeof kit)[];
    expect(names).toHaveLength(17);
    for (const name of names) {
      expect(typeof kit[name]).toBe("function");
    }
  });
});
