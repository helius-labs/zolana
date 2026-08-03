/**
 * The benchmark model both the web page and the mobile screen render.
 *
 * Timings come from `performance.now()`, which is monotonic and unaffected by
 * clock adjustments; wall-clock dates are recorded separately and only for
 * labelling a run. Every measurement carries the environment it was taken in,
 * because a browser number and a phone number are not comparable and a table
 * that mixes them silently is worse than no table.
 */

export type ProverKind = "remote" | "wasm" | "native";

export type StepName =
  | "poseidon-init"
  | "key-fetch"
  | "key-load"
  | "wallet-sync"
  | "shield-build"
  | "shield-submit"
  | "transfer-build"
  | "transfer-prove"
  | "transfer-submit"
  | "unshield-build"
  | "unshield-prove"
  | "unshield-submit";

export interface Measurement {
  readonly step: StepName;
  readonly ms: number;
  /** Bytes moved, for steps whose cost is dominated by transfer size. */
  readonly bytes?: number;
  readonly note?: string;
}

export interface RunResult {
  readonly shape: string;
  readonly prover: ProverKind;
  readonly measurements: readonly Measurement[];
  readonly totalMs: number;
  readonly ok: boolean;
  readonly error?: string;
}

export interface Environment {
  readonly platform: string;
  readonly runtime: string;
  /** `navigator.hardwareConcurrency`, or the device core count on mobile. */
  readonly cores?: number;
  /** Whether the proving path can use more than one thread. */
  readonly threaded: boolean;
}

export interface BenchReport {
  readonly startedAt: string;
  readonly environment: Environment;
  readonly runs: readonly RunResult[];
}

/**
 * Accumulates measurements for one run. Kept deliberately dumb: it records what
 * it is told and never infers a total from the sum of its parts, because steps
 * can overlap (a key download runs while the wallet syncs) and a summed total
 * would overstate wall-clock.
 */
export class RunRecorder {
  readonly #measurements: Measurement[] = [];
  readonly #start: number;

  constructor(
    readonly shape: string,
    readonly prover: ProverKind,
    private readonly now: () => number = () => performance.now(),
  ) {
    this.#start = now();
  }

  /** Times `fn`, records it under `step`, and returns whatever `fn` returned. */
  async step<T>(
    step: StepName,
    fn: () => Promise<T> | T,
    detail?: Readonly<{ bytes?: number; note?: string }>,
  ): Promise<T> {
    const started = this.now();
    try {
      return await fn();
    } finally {
      this.#measurements.push(
        Object.freeze({
          step,
          ms: this.now() - started,
          ...(detail?.bytes === undefined ? {} : { bytes: detail.bytes }),
          ...(detail?.note === undefined ? {} : { note: detail.note }),
        }),
      );
    }
  }

  /** Records a measurement taken elsewhere, e.g. inside a worker. */
  record(measurement: Measurement): void {
    this.#measurements.push(Object.freeze({ ...measurement }));
  }

  finish(error?: unknown): RunResult {
    return Object.freeze({
      shape: this.shape,
      prover: this.prover,
      measurements: Object.freeze([...this.#measurements]),
      totalMs: this.now() - this.#start,
      ok: error === undefined,
      ...(error === undefined ? {} : { error: describeError(error) }),
    });
  }
}

/**
 * Flattens an error into something diagnosable on a page.
 *
 * The SDK's errors carry the useful part outside `message`: the code, the lifted
 * `causeCode`, `details`, and a `cause` chain. `name: message` alone reduces every
 * failure to a wrapper label like "WalletError: WALLET_BUILD_TRANSFER", which
 * names the step that failed and nothing about why.
 */
export function describeError(error: unknown, depth = 0): string {
  if (depth > 4) return "...";
  if (!(error instanceof Error)) {
    // A structured RPC error is a plain object, and String() yields
    // "[object Object]". Show its own properties instead.
    if (typeof error === "object" && error !== null) {
      const own = Object.getOwnPropertyNames(error)
        .map((key) => `${key}=${String((error as Record<string, unknown>)[key])}`)
        .join(" ");
      return own === "" ? String(error) : own;
    }
    return String(error);
  }

  const extra = error as Error & {
    code?: unknown;
    causeCode?: unknown;
    details?: unknown;
  };
  const parts = [`${error.name}: ${error.message}`];
  if (typeof extra.causeCode === "string" && extra.causeCode !== error.message) {
    parts.push(`causeCode=${extra.causeCode}`);
  }
  if (extra.details !== undefined) {
    parts.push(`details=${safeJson(extra.details)}`);
  }
  const cause: unknown = (error as { cause?: unknown }).cause;
  if (cause !== undefined && cause !== null) {
    parts.push(`<- ${describeError(cause, depth + 1)}`);
  }
  return parts.join(" ");
}

/** Details can hold bigints, which JSON.stringify refuses outright. */
function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value, (_key, entry) =>
      typeof entry === "bigint" ? `${entry.toString()}n` : entry,
    );
  } catch {
    return String(value);
  }
}

export function formatMs(ms: number): string {
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 1_000) return `${ms.toFixed(0)} ms`;
  return `${(ms / 1_000).toFixed(2)} s`;
}

/** The measurement for `step`, or undefined if the run never reached it. */
export function measurementFor(run: RunResult, step: StepName): Measurement | undefined {
  return run.measurements.find((entry) => entry.step === step);
}

/**
 * Total time attributable to proving, which is the number that actually decides
 * whether local proving is viable on a given device.
 */
export function proveMs(run: RunResult): number {
  return run.measurements
    .filter((entry) => entry.step === "transfer-prove" || entry.step === "unshield-prove")
    .reduce((total, entry) => total + entry.ms, 0);
}

export function describeEnvironment(): Environment {
  const nav: unknown = globalThis.navigator;
  const cores =
    typeof nav === "object" && nav !== null && "hardwareConcurrency" in nav
      ? (nav as { hardwareConcurrency?: number }).hardwareConcurrency
      : undefined;
  const agent =
    typeof nav === "object" && nav !== null && "userAgent" in nav
      ? String((nav as { userAgent?: unknown }).userAgent)
      : "unknown";
  return Object.freeze({
    platform: agent,
    runtime: typeof globalThis.WebAssembly === "object" ? "wasm-capable" : "no-wasm",
    ...(cores === undefined ? {} : { cores }),
    // Go's js/wasm has no thread support, so a wasm proof is single-threaded
    // regardless of how many cores the host reports.
    threaded: false,
  });
}

/** CSV so a run can be pasted straight into a spreadsheet or a PR comment. */
export function toCsv(report: BenchReport): string {
  const header = "shape,prover,step,ms,bytes,note,ok,error";
  const rows = report.runs.flatMap((run) =>
    run.measurements.map((entry) =>
      [
        run.shape,
        run.prover,
        entry.step,
        entry.ms.toFixed(3),
        entry.bytes === undefined ? "" : String(entry.bytes),
        entry.note === undefined ? "" : entry.note.replaceAll(",", ";"),
        String(run.ok),
        run.error === undefined ? "" : run.error.replaceAll(",", ";"),
      ].join(","),
    ),
  );
  return [header, ...rows].join("\n");
}
