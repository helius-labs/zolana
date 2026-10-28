import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
export type Program = "escrow" | "withdraw";
export type KeyFormat = "streaming" | "resident";
export type Fixture = {
  inputs: Record<string, any>; records: Record<string, unknown>; sender: number[]; payer: string;
  transaction: { finalizedTx: Record<string, any>; proofInputs: Record<string, string>; publicHash: number[] };
  hashes: Record<string, string>; encrypted: { utxoHashes: number[][] };
};
export function fixture(program: Program): Fixture {
  return JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "fixtures", `${program}.json`), "utf8"));
}
export function keyUrl(program: Program, _format: KeyFormat): string { return `/keys/${program}/pk.bin`; }
