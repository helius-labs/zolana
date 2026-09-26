import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type Program = "escrow" | "withdraw";
export type KeyFormat = "arkworks" | "zkey";

export type OwnerTagJson = { kind: "inline"; value: number[] } | { kind: "account"; index: number };

export type Fixture = {
  inputs: Record<string, unknown>;
  sender: number[];
  payer: string;
  transaction: {
    finalizedTx: Record<string, unknown>;
    publicHash: number[];
  };
  proofInputsSha256: string;
  verifyingKey: number[];
  encrypted: {
    utxoHashes: number[][];
    ownerTags: OwnerTagJson[];
    resolvedOwnerTags: number[][];
    interfaceTransfers: unknown[];
  };
};

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

export function fixture(program: Program): Fixture {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, `${program}.json`), "utf8")) as Fixture;
}

export function keyUrl(program: Program, format: KeyFormat): string {
  return format === "zkey" ? `/keys/${program}.zkey` : `/keys/${program}.pk`;
}

export function zkeyVerifyingKeyUrl(program: Program): string {
  return `/keys/${program}.zkey.vk`;
}
