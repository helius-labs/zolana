import {
  automaticProvingThreads,
  proofStatistics,
  shapeByLabel,
  WasmProver,
} from "@zolana/poc-core";
import ProverWorker from "./prover.worker.ts?worker";
import "./device-benchmark.css";

const WARMUPS = 3;
const SAMPLES = 30;
const base = import.meta.env.BASE_URL;
const shape = shapeByLabel("2x3");
function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing element ${id}`);
  return found as T;
}
const controls = element<HTMLFormElement>("controls");
const device = element<HTMLInputElement>("device");
const threads = element<HTMLInputElement>("threads");
const runButton = element<HTMLButtonElement>("run");
const progress = element("progress");
const error = element("error");
const result = element("result");
const queryThreads = Number(new URLSearchParams(location.search).get("threads"));
threads.value = String(
  Number.isInteger(queryThreads) && queryThreads >= 1 && queryThreads <= 64
    ? queryThreads
    : automaticProvingThreads(),
);
let abort: AbortController | undefined;
let report: object | undefined;
// Read-only automation hook. Reports contain the public sample's proofs, never its witness.
Object.defineProperty(globalThis, "__zolanaDeviceBenchmark", { get: () => report });
function cancel(reason: string) {
  abort?.abort(new Error(reason));
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible")
    cancel("Run cancelled because the tab became hidden. Keep it visible and retry.");
});
window.addEventListener("pagehide", () => cancel("Page closed"));
function timings(rows: [string, number][]) {
  const list = element("timings");
  list.replaceChildren();
  for (const [label, value] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = `${value.toFixed(1)} ms`;
    list.append(dt, dd);
  }
}
async function sha256(bytes: Uint8Array<ArrayBuffer>) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
controls.addEventListener("submit", (event) => {
  event.preventDefault();
  if (abort) {
    cancel("Cancelled");
    return;
  }
  void run();
});
async function run() {
  const count = Number(threads.value);
  if (!Number.isInteger(count) || count < 1 || count > 64) return;
  abort = new AbortController();
  const controller = abort;
  const { signal } = controller;
  let prover: WasmProver | undefined;
  let wakeLock: WakeLockSentinel | undefined;
  report = undefined;
  result.hidden = true;
  error.hidden = true;
  threads.disabled = device.disabled = true;
  runButton.textContent = "Cancel";
  const startedAt = new Date().toISOString();
  const measurements: { step: string; ms: number }[] = [];
  try {
    if (!crossOriginIsolated)
      throw new Error("This page needs HTTPS and cross-origin isolation for threaded proving.");
    if (document.visibilityState !== "visible")
      throw new Error("Keep the tab visible while benchmarking.");
    if ("wakeLock" in navigator) {
      try {
        wakeLock = await navigator.wakeLock.request("screen");
      } catch {
        /* Visibility changes still cancel the run. */
      }
    }
    progress.textContent = "Loading sample…";
    const response = await fetch(`${base}fixtures/transfer-2x3.json`, { signal });
    if (!response.ok) throw new Error(`Sample fetch failed (${response.status})`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const request = new TextDecoder().decode(bytes);
    const input = JSON.parse(request);
    if (
      input.circuitType !== "transfer-confidential" ||
      input.nInputs !== 2 ||
      input.nOutputs !== 3
    ) {
      throw new Error("Expected the transfer-confidential 2×3 sample");
    }
    const fixtureSha256 = await sha256(bytes);
    const keyBase = import.meta.env.VITE_ZOLANA_KEYS_URL ?? `${base}keys`;
    const manifestResponse = await fetch(`${keyBase}/manifest.json`, { signal });
    if (!manifestResponse.ok) throw new Error("Key manifest fetch failed");
    const manifest = await manifestResponse.json();
    const buildResponse = await fetch(`${base}build-info.json`, { signal });
    const build =
      buildResponse.ok && buildResponse.headers.get("content-type")?.includes("application/json")
        ? await buildResponse.json()
        : null;
    signal.throwIfAborted();
    prover = new WasmProver({
      wasmUrl: `${import.meta.env.VITE_ZOLANA_WASM_URL ?? `${base}prover`}/zolana-prover.wasm`,
      keyBaseUrl: keyBase,
      proverUrl: new URL("prove", location.href).href,
      threads: count,
      onMeasurement: (m) => {
        if (m.ms > 0) measurements.push({ step: m.step, ms: m.ms });
      },
    });
    signal.addEventListener("abort", () => prover?.terminate(), { once: true });
    progress.textContent = "Starting prover…";
    const startupStart = performance.now();
    await prover.start(() => new ProverWorker());
    const startupMs = performance.now() - startupStart;
    signal.throwIfAborted();
    progress.textContent = "Preparing key…";
    await prover.ensureKey(shape, signal);
    type Sample = Awaited<ReturnType<WasmProver["proveRequest"]>> & {
      requestAndVerificationMs: number;
    };
    const warmups: Sample[] = [],
      samples: Sample[] = [];
    for (let i = 0; i < WARMUPS + SAMPLES; i++) {
      signal.throwIfAborted();
      progress.textContent =
        i < WARMUPS ? `Warmup ${i + 1} of ${WARMUPS}…` : `Proof ${i - WARMUPS + 1} of ${SAMPLES}…`;
      const start = performance.now();
      const proof = await prover.proveRequest(request, signal);
      const sample = { ...proof, requestAndVerificationMs: performance.now() - start };
      (i < WARMUPS ? warmups : samples).push(sample);
    }
    signal.throwIfAborted();
    const proof = proofStatistics(samples.map((x) => x.proveMs));
    const verification = proofStatistics(samples.map((x) => x.verifyMs));
    const measurement = (step: string) => measurements.find((m) => m.step === step)?.ms ?? 0;
    const setup = {
      startupMs,
      keyFetchAndCheckMs: measurement("key-fetch"),
      keyPreparationMs: measurement("key-load"),
    };
    report = {
      schemaVersion: 1,
      startedAt,
      finishedAt: new Date().toISOString(),
      circuit: {
        name: "transfer-confidential",
        inputs: 2,
        outputs: 3,
        expectedConstraints: 54031,
        fixtureSha256,
        key: manifest[shape.keyFile],
      },
      build,
      environment: {
        deviceLabel: device.value.trim(),
        userAgent: navigator.userAgent,
        reportedThreads: navigator.hardwareConcurrency,
        workers: prover.threads,
        crossOriginIsolated,
        foreground: true,
      },
      method: {
        warmups: WARMUPS,
        samples: SAMPLES,
        percentile: "nearest-rank",
        targetMs: 1000,
        preparationIncluded: false,
        verificationIncluded: false,
      },
      setup,
      proof,
      verification,
      warmups,
      samples,
    };
    element("verdict").textContent = proof.p95UnderOneSecond
      ? "p95 under 1 second in this run"
      : "Target not reached in this run";
    timings([
      ["First proof after preparation", warmups[0]!.proveMs],
      ["Proof p50", proof.p50Ms],
      ["Proof p95", proof.p95Ms],
      ["Slowest proof", proof.maxMs],
      ["Verification p95", verification.p95Ms],
      ["Key preparation", setup.keyPreparationMs],
      ["Key fetch and check", setup.keyFetchAndCheckMs],
      ["Startup", setup.startupMs],
    ]);
    result.hidden = false;
    progress.textContent = `${SAMPLES} measured proofs verified. ${proof.underOneSecond} under one second.`;
  } catch (reason) {
    report = undefined;
    error.textContent = signal.aborted
      ? String(signal.reason?.message ?? "Cancelled")
      : reason instanceof Error
        ? reason.message
        : String(reason);
    error.hidden = false;
    progress.textContent = "Run incomplete.";
  } finally {
    prover?.terminate();
    await wakeLock?.release().catch(() => {});
    if (abort === controller) abort = undefined;
    threads.disabled = device.disabled = false;
    runButton.textContent = "Run benchmark";
  }
}
element("download").addEventListener("click", () => {
  if (!report) return;
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = "transfer-2x3-benchmark.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
