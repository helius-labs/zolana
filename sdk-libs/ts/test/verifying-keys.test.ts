import { readFileSync, readdirSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { PROVING_KEY_SHA256S } from "../src/interface/proving-keys.js";
import { VERIFYING_KEYS } from "../src/interface/verifying-keys.js";

const RUST = new URL("../../../program-libs/interface/src/verifying_keys/", import.meta.url);

function hexOf(source: string): string {
  return [...source.matchAll(/(\d+)u8/gu)]
    .map((match) => Number(match[1]).toString(16).padStart(2, "0"))
    .join("");
}

function field(source: string, name: string): string {
  const match = new RegExp(`\\b${name}: \\[([^\\]]*)\\]`, "u").exec(source);
  if (match?.[1] === undefined) throw new Error(`no ${name}`);
  return hexOf(match[1]);
}

/** The key a Rust verifying key module compiles, read straight from its source. */
function rustKey(file: string): unknown {
  const source = readFileSync(new URL(file, RUST), "utf8");
  const ic = /VERIFYINGKEY_VK_IC: &\[\[u8; 64\]\] = &\[([\s\S]*?)\];/u.exec(source)?.[1] ?? "";
  return {
    alphaG1: field(source, "vk_alpha_g1"),
    betaG2: field(source, "vk_beta_g2"),
    gammaG2: field(source, "vk_gamma_g2"),
    deltaG2: field(source, "vk_delta_g2"),
    ic: [...ic.matchAll(/\[([^\]]*)\]/gu)].map((match) => hexOf(match[1] ?? "")),
    ...(source.includes("vk_commitment: Some(")
      ? {
          commitment: {
            g2: field(source, "g2"),
            gSigmaNegG2: field(source, "g_sigma_neg_g2"),
          },
        }
      : {}),
  };
}

describe("VERIFYING_KEYS", () => {
  const files = readdirSync(RUST).filter(
    (file) => file.endsWith(".rs") && file !== "mod.rs" && file !== "circuit.rs",
  );

  it("equals the keys the Rust interface crate compiles in", () => {
    // `node scripts/generate-verifying-keys.mjs` rewrites the table from them.
    expect({ ...VERIFYING_KEYS }).toEqual(
      Object.fromEntries(files.map((file) => [file.replace(/\.rs$/u, ".key"), rustKey(file)])),
    );
  });

  it("holds a key for every transfer and merge proving key the SDK pins", () => {
    expect(Object.keys(VERIFYING_KEYS).sort()).toEqual(
      Object.keys(PROVING_KEY_SHA256S)
        .filter((name) => !name.startsWith("batch_address-append_"))
        .sort(),
    );
  });

  it("carries the BSB22 commitment key exactly on the in-circuit owner rails", () => {
    for (const [name, key] of Object.entries(VERIFYING_KEYS)) {
      const committed = /^transfer_(confidential_eddsa|eddsa_ring)_/u.test(name);
      expect(key.commitment !== undefined, name).toBe(committed);
      expect(key.ic, name).toHaveLength(committed ? 3 : 2);
    }
  });
});
