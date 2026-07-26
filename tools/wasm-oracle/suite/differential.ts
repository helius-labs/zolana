import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import fc from "fast-check";

import type { Outcome } from "./oracle.js";

const here = dirname(fileURLToPath(import.meta.url));
const reportDirectory = join(here, "..", "report");

/**
 * How the two sides failed to agree.
 *
 * `arm` means one side returned a value where the other rejected, which is the
 * class the oracle exists to find. `value` means both returned and the bytes
 * differ. `reason` means both rejected for reasons that may not correspond; it is
 * recorded rather than counted as a divergence, because a one-to-one error
 * taxonomy is W-00 and out of scope here.
 */
export type DivergenceKind = "arm" | "value";

export interface Divergence {
  readonly rustSymbol: string;
  readonly kind: DivergenceKind;
  readonly input: unknown;
  readonly rust: Outcome;
  readonly typescript: Outcome;
  /** How many of the sampled cases fell into this class. */
  readonly sampled: number;
}

export interface RejectionPair {
  readonly rustSymbol: string;
  readonly rustCode: string;
  readonly typescriptCode: string;
  readonly sampled: number;
}

export interface ProbeSummary {
  readonly rustSymbol: string;
  readonly cases: number;
  readonly agreed: number;
  readonly bothRejected: number;
  readonly boundaryRejected: number;
  readonly divergences: readonly Divergence[];
}

export interface Probe<Input> {
  /** Rust path and symbol the probe compares against. */
  readonly rustSymbol: string;
  readonly arbitrary: fc.Arbitrary<Input>;
  readonly rust: (input: Input) => Outcome;
  readonly typescript: (input: Input) => Outcome;
  /** Serializable rendering of the input, used as the report's minimal case. */
  readonly render: (input: Input) => unknown;
  readonly cases?: number;
}

const summaries: ProbeSummary[] = [];
const rejectionPairs = new Map<string, { pair: RejectionPair; count: number }>();

/**
 * Samples the input space, tallies how the two sides compared, then shrinks one
 * minimal counterexample per divergence class.
 *
 * Sampling and shrinking are separate passes on purpose. Sampling reports how
 * wide a divergence is, which a first failing case cannot; shrinking reduces
 * each class to the smallest input that still diverges, which is what makes the
 * cause legible and the case worth promoting into a fixture.
 */
export function probe<Input>(spec: Probe<Input>): ProbeSummary {
  const cases = spec.cases ?? 600;
  const classes = new Map<string, { divergence: Divergence; count: number }>();
  let agreed = 0;
  let bothRejected = 0;
  let boundaryRejected = 0;

  for (const input of fc.sample(spec.arbitrary, cases)) {
    const rust = spec.rust(input);
    const typescript = spec.typescript(input);
    if (rust.arm === "err" && rust.code.startsWith("Oracle")) boundaryRejected += 1;
    if (rust.arm === "err" && typescript.arm === "err") {
      bothRejected += 1;
      recordRejectionPair(spec.rustSymbol, rust.code, typescript.code);
    }
    const kind = classify(rust, typescript);
    if (kind === undefined) {
      agreed += 1;
      continue;
    }
    const key = classKey(kind, rust, typescript);
    const existing = classes.get(key);
    if (existing) {
      existing.count += 1;
      continue;
    }
    classes.set(key, {
      count: 1,
      divergence: {
        rustSymbol: spec.rustSymbol,
        kind,
        input: spec.render(input),
        rust,
        typescript,
        sampled: 0,
      },
    });
  }

  const divergences = [...classes.entries()].map(([key, entry]) => {
    const shrunk = shrink(spec, key);
    const source = shrunk ?? entry.divergence;
    return { ...source, sampled: entry.count };
  });

  const summary: ProbeSummary = {
    rustSymbol: spec.rustSymbol,
    cases,
    agreed,
    bothRejected,
    boundaryRejected,
    divergences,
  };
  summaries.push(summary);
  return summary;
}

/** Reduces one divergence class to its smallest input. */
function shrink<Input>(spec: Probe<Input>, key: string): Divergence | undefined {
  const result = fc.check(
    fc.property(spec.arbitrary, (input) => {
      const rust = spec.rust(input);
      const typescript = spec.typescript(input);
      const kind = classify(rust, typescript);
      return kind === undefined || classKey(kind, rust, typescript) !== key;
    }),
    { numRuns: spec.cases ?? 600, endOnFailure: false },
  );
  const counterexample = result.counterexample?.[0] as Input | undefined;
  if (!result.failed || counterexample === undefined) return undefined;
  const rust = spec.rust(counterexample);
  const typescript = spec.typescript(counterexample);
  const kind = classify(rust, typescript);
  if (kind === undefined) return undefined;
  return {
    rustSymbol: spec.rustSymbol,
    kind,
    input: spec.render(counterexample),
    rust,
    typescript,
    sampled: 0,
  };
}

/**
 * Compares outcomes at arm level first. Two rejections agree here even when
 * their codes differ, because the current Rust-to-TypeScript error mapping is
 * many-to-one and fixing it is W-00.
 */
function classify(rust: Outcome, typescript: Outcome): DivergenceKind | undefined {
  if (rust.arm !== typescript.arm) return "arm";
  if (rust.arm === "err") return undefined;
  const left = stableJson(rust.value);
  const right = stableJson(typescript.arm === "ok" ? typescript.value : undefined);
  return left === right ? undefined : "value";
}

/**
 * Key-order independent rendering. `serde_json` sorts object keys and the
 * TypeScript objects keep insertion order, so a plain `JSON.stringify`
 * comparison reports every structured result as a divergence.
 */
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function classKey(kind: DivergenceKind, rust: Outcome, typescript: Outcome): string {
  const rustSide = rust.arm === "err" ? `err:${rust.code}` : "ok";
  const tsSide = typescript.arm === "err" ? `err:${typescript.code}` : "ok";
  return `${kind}|${rustSide}|${tsSide}`;
}

function recordRejectionPair(rustSymbol: string, rustCode: string, typescriptCode: string): void {
  const key = `${rustSymbol}|${rustCode}|${typescriptCode}`;
  const existing = rejectionPairs.get(key);
  if (existing) {
    existing.count += 1;
    return;
  }
  rejectionPairs.set(key, {
    count: 1,
    pair: { rustSymbol, rustCode, typescriptCode, sampled: 0 },
  });
}

export function writeReport(packet: string): void {
  const report = {
    packet,
    generatedAt: new Date().toISOString(),
    note: "Reconnaissance output. Not a parity verdict and not wired into any gate.",
    probes: summaries,
    rejectionPairs: [...rejectionPairs.values()].map((entry) => ({
      ...entry.pair,
      sampled: entry.count,
    })),
  };
  mkdirSync(reportDirectory, { recursive: true });
  writeFileSync(join(reportDirectory, `${packet}.json`), `${JSON.stringify(report, null, 2)}\n`);
  summaries.length = 0;
  rejectionPairs.clear();
}
