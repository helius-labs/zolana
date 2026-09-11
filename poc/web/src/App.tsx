/**
 * The PoC page.
 *
 * Two benchmarks, deliberately separate because they need different things:
 *
 *  - "Benchmark proving keys" needs only the key files. It fetches and
 *    deserializes each shape's key in the wasm instance and reports the
 *    cold-start cost of local proving. Runs with no validator.
 *  - "Run shield -> transfer -> unshield" needs a live localnet, indexer, and a
 *    funded tree, and produces real proofs.
 *
 * The prover toggle picks where transfer proofs come from. "local (wasm)" routes
 * the SDK's prove request into the Go wasm module through an injected `fetch`;
 * "remote" leaves it pointed at the prover server. Nothing else changes, which
 * is the point: the two paths speak the same JSON.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  TRANSFER_SHAPES,
  WasmProver,
  automaticProvingThreads,
  benchmarkShapeKeys,
  describeEnvironment,
  formatBytes,
  proverMeasurementSink,
  type Measurement,
  type ProverKind,
  type RunResult,
} from "@zolana/poc-core";

import { BenchTable } from "./BenchTable.js";
import {
  ENDPOINT_LABELS,
  loadConfig,
  preset,
  withEndpoint,
  withEndpoints,
  type EndpointName,
  type PresetName,
} from "./config.js";
import { forgetFundingWallet, fundingSigner } from "./funding.js";
import ProverWorker from "./prover.worker.ts?worker";
import { RUN_LAMPORTS, formatSol, runBrowserFlow } from "./run-flow.js";
import { createSolanaRpc, type KeyPairSigner } from "@solana/kit";

/** Note counts to sweep; each maps to the shape its transfer leg lands on. */
const NOTE_COUNTS: readonly number[] = [1, 2, 3, 4, 5];

type Status = "idle" | "starting" | "ready" | "running" | "error";

export function App(): React.ReactElement {
  const [config, setConfig] = useState(loadConfig);
  const environment = useMemo(describeEnvironment, []);

  const [automaticThreads] = useState(automaticProvingThreads);
  const [threadMode, setThreadMode] = useState<"auto" | "custom" | "go">("auto");
  const [customThreads, setCustomThreads] = useState(automaticThreads);
  const threads = threadMode === "auto" ? automaticThreads : threadMode === "go" ? 0 : customThreads;
  const [activeThreads, setActiveThreads] = useState<number | undefined>();
  const [request, setRequest] = useState("");
  const [proof, setProof] = useState("");
  const [proofMs, setProofMs] = useState<number | undefined>();
  const [verifyMs, setVerifyMs] = useState<number | undefined>();
  const [prepareMs, setPrepareMs] = useState<number | undefined>();
  const [samples, setSamples] = useState<readonly number[]>([]);
  const [proofError, setProofError] = useState("");
  const [prover, setProver] = useState<ProverKind>("wasm");
  const [status, setStatus] = useState<Status>("idle");
  const [log, setLog] = useState<readonly string[]>([]);
  const [runs, setRuns] = useState<readonly RunResult[]>([]);
  const [expanded, setExpanded] = useState(true);
  const [live, setLive] = useState<Measurement | undefined>(undefined);
  const [funding, setFunding] = useState<KeyPairSigner | undefined>(undefined);
  const [fundingBalance, setFundingBalance] = useState<bigint | undefined>(undefined);

  const wasmRef = useRef<WasmProver | undefined>(undefined);

  const append = useCallback((line: string) => {
    setLog((previous) => [...previous, line]);
  }, []);

  /** Boots the wasm instance. Idempotent, so the button can be hit twice. */
  const startWasm = useCallback(async (): Promise<WasmProver> => {
    if (wasmRef.current !== undefined) {
      await wasmRef.current.start(() => new ProverWorker());
      setActiveThreads(wasmRef.current.threads);
      return wasmRef.current;
    }
    setStatus("starting");
    const instance = new WasmProver({
      wasmUrl: `${config.wasmBaseUrl}/zolana-prover.wasm`,
      keyBaseUrl: config.keyBaseUrl,
      threads,
      proverUrl: config.proverUrl,
      onMeasurement: (measurement) => {
        setLive(measurement);
        if (measurement.step === "key-load" && measurement.ms > 0) setPrepareMs(measurement.ms);
        proverMeasurementSink(measurement);
        // Prover failures are reported as a measurement note because the SDK
        // discards the response body and surfaces only the HTTP status. Route
        // them into the log too: `live` shows one measurement at a time and a
        // sweep scrolls past the interesting one immediately.
        const note = measurement.note;
        if (note !== undefined && (note.startsWith("wasm prover") || note.includes("failed"))) {
          append(`  ${measurement.step}: ${note}`);
        }
      },
    });
    // Vite's ?worker import is a Worker subclass constructor, so it is handed
    // over as a factory. Passing a URL derived from it would not resolve.
    await instance.start(() => new ProverWorker());
    wasmRef.current = instance;
    setActiveThreads(instance.threads);
    append(instance.threads === 0 ? "Original Go prover ready" : `Mopro Arkworks ready: ${String(instance.threads)} proving threads`);
    return instance;
  }, [append, config, threads]);

  useEffect(
    () => () => {
      wasmRef.current?.terminate();
    },
    [],
  );

  /** The wasm shim intercepts the prover URL it was started with, so a new URL needs a new instance. */
  const resetWasm = useCallback(() => {
    wasmRef.current?.terminate();
    wasmRef.current = undefined;
    setActiveThreads(undefined);
    setPrepareMs(undefined);
    setStatus("idle");
  }, []);
  const resetProof = useCallback(() => {
    resetWasm();
    setProof(""); setProofError(""); setProofMs(undefined); setVerifyMs(undefined); setSamples([]);
  }, [resetWasm]);
  const setEndpoint = useCallback(
    (name: EndpointName, value: string) => {
      setConfig((previous) => withEndpoint(previous, name, value));
      resetWasm();
    },
    [resetWasm],
  );
  const applyPreset = useCallback(
    (name: PresetName) => {
      setConfig((previous) => withEndpoints(previous, preset(name)));
      resetWasm();
    },
    [resetWasm],
  );

  const refreshBalance = useCallback(async () => {
    if (funding === undefined) return;
    try {
      const { value } = await createSolanaRpc(config.solanaRpcUrl)
        .getBalance(funding.address)
        .send();
      setFundingBalance(value);
    } catch (error) {
      setFundingBalance(undefined);
      append(`balance lookup failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }, [append, config.solanaRpcUrl, funding]);

  useEffect(() => {
    void fundingSigner().then(setFunding);
  }, []);
  useEffect(() => {
    void refreshBalance();
  }, [refreshBalance]);

  const newFundingWallet = useCallback(() => {
    forgetFundingWallet();
    setFundingBalance(undefined);
    void fundingSigner().then(setFunding);
  }, []);

  const benchmarkKeys = useCallback(async () => {
    setStatus("running");
    setRuns([]);
    try {
      const instance = await startWasm();
      setStatus("running");
      append(`sweeping ${String(TRANSFER_SHAPES.length)} shapes from ${config.keyBaseUrl}`);
      await benchmarkShapeKeys(instance, TRANSFER_SHAPES, "wasm", (run) => {
        setRuns((previous) => [...previous, run]);
        append(
          run.ok
            ? `${run.shape}: key ready`
            : `${run.shape}: FAILED -- ${run.error ?? "unknown error"}`,
        );
      });
      append("key sweep complete");
      setStatus("ready");
    } catch (error) {
      append(`key sweep aborted: ${error instanceof Error ? error.message : String(error)}`);
      setStatus("error");
    }
  }, [append, config.keyBaseUrl, startWasm]);

  /**
   * Runs the real round trip once per note count. Sequential and never aborted
   * on failure: a shape that cannot prove locally is the result worth seeing,
   * and stopping the sweep would discard the ones that already worked.
   */
  const runFlows = useCallback(async () => {
    if (funding === undefined) return;
    setStatus("running");
    setRuns([]);
    try {
      const instance = prover === "wasm" ? await startWasm() : undefined;
      setStatus("running");
      for (const notes of NOTE_COUNTS) {
        append(`--- ${String(notes)} note(s): shield -> transfer -> unshield`);
        const run = await runBrowserFlow({
          config,
          funding,
          prover,
          notes,
          ...(instance === undefined ? {} : { wasm: instance }),
          onMeasurement: (measurement) => {
            setLive(measurement);
            // Every step, not just failures: knowing which leg the run reached is
            // most of the diagnosis, and the table only shows it after the run
            // ends -- too late when the run dies partway.
            append(
              `  ${measurement.step} ${measurement.ms.toFixed(0)}ms${
                measurement.note === undefined ? "" : ` (${measurement.note})`
              }`,
            );
          },
          onLog: append,
        });
        setRuns((previous) => [...previous, run]);
        append(
          run.ok
            ? `${run.shape}: ok in ${run.totalMs.toFixed(0)}ms`
            : `${run.shape}: FAILED -- ${run.error ?? "unknown error"}`,
        );
        // No step reached means the stack itself failed, later note counts would too.
        if (!run.ok && run.measurements.length === 0) break;
      }
      setStatus("ready");
    } catch (error) {
      append(`flow sweep aborted: ${error instanceof Error ? error.message : String(error)}`);
      setStatus("error");
    } finally {
      void refreshBalance();
    }
  }, [append, config, funding, prover, refreshBalance, startWasm]);

  const busy = status === "starting" || status === "running";
  const loadSample = useCallback(async () => {
    const response = await fetch(`${import.meta.env.BASE_URL}fixtures/transfer-2x3.json`);
    if (!response.ok) throw new Error("Sample request is missing. Run the demo staging script.");
    const text = await response.text();
    JSON.parse(text);
    setRequest(text);
    setProof("");
    setProofError("");
  }, []);
  useEffect(() => { void loadSample().catch(error => setProofError(String(error))); }, [loadSample]);

  const runSample = useCallback(async (count: number) => {
    setStatus("running");
    setProof(""); setProofError(""); setSamples([]);
    setProofMs(undefined); setVerifyMs(undefined);
    try {
      JSON.parse(request);
      const instance = await startWasm();
      setStatus("running");
      const timings: number[] = [];
      for (let i = 0; i < count; i++) {
        const result = await instance.proveRequest(request);
        timings.push(result.proveMs);
        setProof(result.proof); setVerifyMs(result.verifyMs);
        setSamples([...timings]);
        const sorted = [...timings].sort((a, b) => a - b);
        setProofMs(sorted[Math.floor(sorted.length / 2)]);
        append(`Proof ${i + 1}/${count}: ${result.proveMs.toFixed(1)} ms; verified in ${result.verifyMs.toFixed(1)} ms`);
      }
      setStatus("ready");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setProofError(message); append(message); setStatus("error");
    }
  }, [append, request, startWasm]);

  const downloadProof = () => {
    const url = URL.createObjectURL(new Blob([proof], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "zolana-proof.json";
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const totalKeyBytes = useMemo(
    () => TRANSFER_SHAPES.reduce((total, shape) => total + shape.keyBytes, 0),
    [],
  );

  return (
    <main>
      <header className="demo-header">
        <div className="eyebrow">ZOLANA / MOPRO</div>
        <h1>Prove it in your browser.</h1>
        <p>A real Zolana confidential-transfer proof, generated locally with Mopro’s Arkworks accelerator and verified by gnark.</p>
        <div className="runtime-pill"><span className="dot" />{activeThreads === undefined ? "Ready to initialize" : activeThreads === 0 ? "Go fallback · 1 thread" : `Mopro Arkworks · ${activeThreads} workers`} <span>·</span> {crossOriginIsolated ? "Cross-origin isolated" : "Isolation unavailable"}</div>
      </header>

      <section className="panel proof-panel" aria-label="Local proof playground">
        <div className="section-top"><div><div className="eyebrow">LOCAL PROOF PLAYGROUND</div><h2>Confidential transfer · 2 inputs / 3 outputs</h2></div><span className="tag">No validator required</span></div>
        <p className="hint">The sample comes from a localnet transfer. This test generates and verifies a proof without sending a transaction. Inputs stay in your browser.</p>
        <div className="prover-controls">
          <label>Proving threads
            <select aria-label="Proving threads" value={threadMode} disabled={busy} onChange={event => { setThreadMode(event.target.value as "auto" | "custom" | "go"); resetProof(); }}>
              <option value="auto">Automatic · {automaticThreads} threads</option>
              <option value="custom">Custom thread count</option>
              <option value="go">Original Go prover · 1 thread</option>
            </select>
          </label>
          {threadMode === "custom" && <label>Thread count
            <input aria-label="Thread count" type="number" min="1" max="64" step="1" value={customThreads} disabled={busy} onChange={event => { const value = Number(event.target.value); if (Number.isInteger(value) && value >= 1 && value <= 64) { setCustomThreads(value); resetProof(); } }} />
          </label>}
          <span className="hint">{threadMode === "auto" ? `Chosen from the CPU threads your browser reports, up to 18. You can just press Generate.` : threadMode === "custom" ? "More threads can speed up proof calculations, but use more CPU. Changing this prepares the key again." : "The original single-threaded Go prover, for comparison."}</span>
        </div>
        <div className="metrics" aria-live="polite">
          <div><span>Key preparation</span><strong>{prepareMs === undefined ? "—" : `${(prepareMs / 1000).toFixed(2)} s`}</strong><small>Once per shape</small></div>
          <div><span>{samples.length > 1 ? "Median proving time" : "Proving time"}</span><strong>{proofMs === undefined ? "—" : `${proofMs.toFixed(1)} ms`}</strong><small>{samples.length ? `${samples.length} proof${samples.length === 1 ? "" : "s"} generated` : "Measured in the worker"}</small></div>
          <div><span>Verification</span><strong className={proof ? "verified" : ""}>{proof ? "Verified ✓" : "—"}</strong><small>{verifyMs === undefined ? "Checked by native gnark code in WASM" : `${verifyMs.toFixed(1)} ms · gnark verification`}</small></div>
        </div>
        <div className="row actions">
          <button className="primary" type="button" disabled={busy || request === ""} onClick={() => void runSample(1)}>{busy ? "Working…" : "Generate & verify proof"}</button>
          <button type="button" disabled={busy || request === ""} onClick={() => void runSample(5)}>Benchmark 5 proofs</button>
          <button type="button" disabled={busy} onClick={resetProof}>Reset prover</button>
        </div>
        <p className="status" role="status">{busy ? status === "starting" ? "Starting the prover and its workers…" : "Preparing the key or generating a proof. You can keep using this page." : proof ? "Proof generated and verified locally." : "Ready to generate a proof. The first proof also prepares the key; later proofs reuse it."}</p>
        {proofError && <pre className="proof-error" role="alert">{proofError}</pre>}
        <details className="request-editor"><summary>Edit the proof request</summary><p className="hint">Changing constrained values can make the witness invalid. Load the sample to restore a valid request.</p><textarea aria-label="Proof request JSON" spellCheck={false} value={request} disabled={busy} onChange={event => { setRequest(event.target.value); setProof(""); }} /><button type="button" disabled={busy} onClick={() => void loadSample().catch(error => setProofError(String(error)))}>Load sample request</button></details>
        {proof && <details className="proof-output" open><summary>Generated proof</summary><pre>{proof}</pre><button type="button" onClick={downloadProof}>Download proof JSON</button></details>}
      </section>
      <details className="advanced"><summary>Localnet transfers, key benchmarks &amp; connection settings</summary>

      <section className="panel">
        <h2>Environment</h2>
        <dl>
          <dt>Runtime</dt>
          <dd>{environment.runtime}</dd>
          <dt>Cores reported</dt>
          <dd>{environment.cores ?? "unknown"}</dd>
          <dt>Proving threads</dt>
          <dd>{activeThreads === undefined ? "Not initialized" : activeThreads === 0 ? "Go fallback (1 thread)" : `${activeThreads} Mopro workers`}</dd>
          <dt>Platform</dt>
          <dd className="wrap">{environment.platform}</dd>
        </dl>
      </section>

      <section className="panel">
        <h2>Endpoints</h2>
        <div className="row presets">
          <button type="button" onClick={() => applyPreset("localnet")} disabled={busy}>
            Localnet preset
          </button>
          <button type="button" onClick={() => applyPreset("devnet")} disabled={busy}>
            Devnet preset
          </button>
        </div>
        <div className="endpoints">
          {(Object.keys(ENDPOINT_LABELS) as EndpointName[]).map((name) => (
            <label key={name}>
              {ENDPOINT_LABELS[name]}
              <input
                type="url"
                value={config[name]}
                disabled={busy}
                onChange={(event) => setEndpoint(name, event.target.value)}
              />
            </label>
          ))}
        </div>
        <dl>
          <dt>Proving keys</dt>
          <dd>
            {config.keyBaseUrl} — {TRANSFER_SHAPES.length} shapes,{" "}
            {formatBytes(totalKeyBytes)} total
          </dd>
        </dl>
      </section>

      <section className="panel">
        <h2>Funding wallet</h2>
        <p className="hint">
          Generated in this browser and kept in its storage, test funds only. Each run
          pays {formatSol(RUN_LAMPORTS)} from it for a fresh sender and recipient. On a
          localnet it tops itself up by airdrop; on devnet send SOL to it from{" "}
          <a href="https://faucet.solana.com" target="_blank" rel="noreferrer">
            faucet.solana.com
          </a>
          .
        </p>
        <dl>
          <dt>Address</dt>
          <dd className="wrap">
            <code>{funding?.address ?? "generating…"}</code>
          </dd>
          <dt>Balance</dt>
          <dd>{fundingBalance === undefined ? "unknown" : formatSol(fundingBalance)}</dd>
        </dl>
        <div className="row">
          <button type="button" onClick={() => void refreshBalance()} disabled={funding === undefined}>
            Refresh balance
          </button>
          <button type="button" onClick={newFundingWallet} disabled={busy}>
            New wallet
          </button>
        </div>
      </section>

      <section className="panel">
        <h2>Prover</h2>
        <div className="row">
          <label>
            <input
              type="radio"
              name="prover"
              checked={prover === "wasm"}
              onChange={() => setProver("wasm")}
            />
            local (Mopro) — threaded browser proving, locally verified
          </label>
          <label>
            <input
              type="radio"
              name="prover"
              checked={prover === "remote"}
              onChange={() => setProver("remote")}
            />
            remote — the prover server at {config.proverUrl}
          </label>
        </div>
        <p className="hint">
          Mopro uses published Arkworks crates for curve arithmetic and FFTs. Go solves the witness. Zolana keeps its existing witnesses, proof format and on-chain verification.
        </p>
      </section>

      <section className="panel">
        <h2>Benchmarks</h2>
        <div className="row">
          <button type="button" onClick={() => void benchmarkKeys()} disabled={busy}>
            Benchmark proving keys (no validator needed)
          </button>
          <button
            type="button"
            onClick={() => void runFlows()}
            disabled={busy || funding === undefined}
          >
            Run shield → transfer → unshield (needs a funded stack)
          </button>
          <label className="inline">
            <input
              type="checkbox"
              checked={expanded}
              onChange={(event) => setExpanded(event.target.checked)}
            />
            show steps
          </label>
        </div>
        <p className="status">
          status: <strong>{status}</strong>
          {live === undefined
            ? ""
            : ` — last: ${live.step} ${live.ms.toFixed(0)}ms${
                live.note === undefined ? "" : ` (${live.note})`
              }`}
        </p>
        <BenchTable runs={runs} expanded={expanded} />
      </section>

      <section className="panel">
        <h2>Shapes</h2>
        <table className="bench">
          <thead>
            <tr>
              <th>Shape</th>
              <th className="num">Inputs</th>
              <th className="num">Outputs</th>
              <th className="num">Proving key</th>
              <th>Key file</th>
            </tr>
          </thead>
          <tbody>
            {TRANSFER_SHAPES.map((shape) => (
              <tr key={shape.label}>
                <td>
                  <strong>{shape.label}</strong>
                </td>
                <td className="num">{shape.inputs}</td>
                <td className="num">{shape.outputs}</td>
                <td className="num">{formatBytes(shape.keyBytes)}</td>
                <td className="note">{shape.keyFile}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Log</h2>
        <pre className="log">{log.length === 0 ? "(nothing yet)" : log.join("\n")}</pre>
      </section>
      </details>
    </main>
  );
}
