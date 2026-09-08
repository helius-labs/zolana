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
    if (wasmRef.current !== undefined) return wasmRef.current;
    setStatus("starting");
    const instance = new WasmProver({
      wasmUrl: `${config.wasmBaseUrl}/zolana-prover.wasm`,
      keyBaseUrl: config.keyBaseUrl,
      proverUrl: config.proverUrl,
      onMeasurement: (measurement) => {
        setLive(measurement);
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
    setStatus("ready");
    append("wasm prover instantiated");
    return instance;
  }, [append, config]);

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
    setStatus("idle");
  }, []);
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

  const totalKeyBytes = useMemo(
    () => TRANSFER_SHAPES.reduce((total, shape) => total + shape.keyBytes, 0),
    [],
  );

  return (
    <main>
      <h1>Zolana PoC — browser proving &amp; benchmarks</h1>

      <section className="panel">
        <h2>Environment</h2>
        <dl>
          <dt>Runtime</dt>
          <dd>{environment.runtime}</dd>
          <dt>Cores reported</dt>
          <dd>{environment.cores ?? "unknown"}</dd>
          <dt>Proving threads</dt>
          <dd>1 (Go js/wasm has no thread support)</dd>
          <dt>Platform</dt>
          <dd className="wrap">{environment.platform}</dd>
        </dl>
      </section>

      <section className="panel">
        <h2>Endpoints</h2>
        <div className="row presets">
          <button type="button" onClick={() => applyPreset("localnet")} disabled={status === "running"}>
            Localnet preset
          </button>
          <button type="button" onClick={() => applyPreset("devnet")} disabled={status === "running"}>
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
                disabled={status === "running"}
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
          <button type="button" onClick={newFundingWallet} disabled={status === "running"}>
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
            local (wasm) — gnark Groth16 compiled to js/wasm, in a Web Worker
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
          mopro is not on this path: its gnark adapter is compiled out for wasm32
          and its wasm adapters cover circom/halo2/noir only. It remains the right
          tool for the native iOS/Android app, where the cgo gnark binding works.
        </p>
      </section>

      <section className="panel">
        <h2>Benchmarks</h2>
        <div className="row">
          <button type="button" onClick={() => void benchmarkKeys()} disabled={status === "running"}>
            Benchmark proving keys (no validator needed)
          </button>
          <button
            type="button"
            onClick={() => void runFlows()}
            disabled={status === "running" || funding === undefined}
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
    </main>
  );
}
