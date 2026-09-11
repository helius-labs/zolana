import { useEffect, useRef, useState } from "react";
import { automaticProvingThreads, WasmProver } from "@zolana/poc-core";
import ProverWorker from "./prover.worker.ts?worker";

type Mode = "proof" | "benchmark";
type ThreadMode = "auto" | "custom" | "go";
type Phase = "loading" | "idle" | "starting" | "preparing" | "proving";
type ProofResult = Awaited<ReturnType<WasmProver["proveRequest"]>>;

function median(values: readonly number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
    : (sorted[middle] ?? 0);
}

export function App(): React.ReactElement {
  const [mode, setMode] = useState<Mode>("proof");
  const [threadMode, setThreadMode] = useState<ThreadMode>("auto");
  const [automaticThreads] = useState(automaticProvingThreads);
  const [customThreads, setCustomThreads] = useState(String(automaticThreads));
  const [request, setRequest] = useState("");
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState("");
  const [results, setResults] = useState<readonly ProofResult[]>([]);
  const [preparationMs, setPreparationMs] = useState<number>();
  const [activeThreads, setActiveThreads] = useState<number>();
  const [completed, setCompleted] = useState(0);
  const runtime = useRef<WasmProver | undefined>(undefined);
  const runId = useRef(0);
  const options = useRef<HTMLDialogElement>(null);
  const proofDialog = useRef<HTMLDialogElement>(null);
  const customValid =
    Number.isInteger(Number(customThreads)) &&
    Number(customThreads) >= 1 &&
    Number(customThreads) <= 64;
  const threads =
    threadMode === "go" ? 0 : threadMode === "auto" ? automaticThreads : Number(customThreads);
  const busy = phase !== "idle" && phase !== "loading";
  const latest = results.at(-1);
  const provingMs = results.length ? median(results.map((result) => result.proveMs)) : undefined;
  const verificationMs = results.length
    ? median(results.map((result) => result.verifyMs))
    : undefined;

  useEffect(() => {
    const abort = new AbortController();
    void fetch(`${import.meta.env.BASE_URL}fixtures/transfer-2x3.json`, { signal: abort.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error("The sample could not be loaded. Refresh to try again.");
        const text = await response.text();
        JSON.parse(text);
        if (!abort.signal.aborted) {
          setRequest(text);
          setPhase("idle");
        }
      })
      .catch((reason: unknown) => {
        if (!abort.signal.aborted) {
          setError(reason instanceof Error ? reason.message : "The sample could not be loaded.");
          setPhase("idle");
        }
      });
    return () => {
      abort.abort();
      runId.current++;
      runtime.current?.terminate();
      runtime.current = undefined;
    };
  }, []);

  const clearResult = () => {
    setResults([]);
    setError("");
    setCompleted(0);
  };
  const resetRuntime = () => {
    runId.current++;
    runtime.current?.terminate();
    runtime.current = undefined;
    setPreparationMs(undefined);
    setActiveThreads(undefined);
    setPhase("idle");
    clearResult();
  };

  const run = async () => {
    if (busy || request === "" || (threadMode === "custom" && !customValid)) return;
    const id = ++runId.current;
    const count = mode === "benchmark" ? 5 : 1;
    clearResult();
    setPhase("starting");
    try {
      try {
        JSON.parse(request);
      } catch {
        throw new Error(
          "The proof input isn't valid JSON. Check it in Options or restore the sample.",
        );
      }
      if (threads > 0 && !globalThis.crossOriginIsolated) {
        throw new Error(
          "Parallel proving isn't available in this browser. Choose Go baseline in Options.",
        );
      }
      let instance = runtime.current;
      if (instance === undefined) {
        instance = new WasmProver({
          wasmUrl: `${import.meta.env.VITE_ZOLANA_WASM_URL ?? `${import.meta.env.BASE_URL}prover`}/zolana-prover.wasm`,
          keyBaseUrl: import.meta.env.VITE_ZOLANA_KEYS_URL ?? `${import.meta.env.BASE_URL}keys`,
          // Required by the shared transport; this page calls proveRequest directly.
          proverUrl: new URL("prove", location.href).href,
          threads,
          onMeasurement: (measurement) => {
            if (measurement.step === "key-fetch") setPhase("preparing");
            if (measurement.step === "key-load") {
              if (measurement.ms > 0) setPreparationMs(measurement.ms);
              setPhase("proving");
            }
          },
        });
        runtime.current = instance;
      }
      await instance.start(() => new ProverWorker());
      if (runId.current !== id) return;
      setActiveThreads(instance.threads);
      setPhase("preparing");
      const samples: ProofResult[] = [];
      for (let i = 0; i < count; i++) {
        const result = await instance.proveRequest(request);
        if (runId.current !== id) return;
        samples.push(result);
        setCompleted(samples.length);
      }
      setResults(samples);
    } catch (reason) {
      if (runId.current === id)
        setError(reason instanceof Error ? reason.message : "Something went wrong. Try again.");
    } finally {
      if (runId.current === id) setPhase("idle");
    }
  };

  const restoreSample = async () => {
    try {
      const response = await fetch(`${import.meta.env.BASE_URL}fixtures/transfer-2x3.json`);
      if (!response.ok) throw new Error("The sample could not be loaded. Try again.");
      const text = await response.text();
      JSON.parse(text);
      setRequest(text);
      clearResult();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The sample could not be loaded.");
    }
  };

  const downloadProof = () => {
    if (!latest) return;
    const url = URL.createObjectURL(new Blob([latest.proof], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "proof.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const progress =
    phase === "starting"
      ? "Starting prover…"
      : phase === "preparing"
        ? "Preparing key…"
        : mode === "benchmark"
          ? `Proving ${completed + 1} of 5…`
          : "Generating proof…";

  return (
    <main className="app">
      <header className="masthead">
        <h1>Prover</h1>
        <button
          type="button"
          className="secondary-button"
          aria-label="Options"
          disabled={busy || phase === "loading"}
          onClick={() => options.current?.showModal()}
        >
          Options
        </button>
      </header>
      <section className="prover-card" aria-label="Prover">
        <div className="mode-tabs" role="group" aria-label="Test mode">
          <button
            type="button"
            aria-pressed={mode === "proof"}
            disabled={busy}
            onClick={() => {
              setMode("proof");
              clearResult();
            }}
          >
            Single proof
          </button>
          <button
            type="button"
            aria-pressed={mode === "benchmark"}
            disabled={busy}
            onClick={() => {
              setMode("benchmark");
              clearResult();
            }}
          >
            Benchmark
          </button>
        </div>
        <div
          className={`result-area ${busy ? "is-running" : ""}`}
          aria-live="polite"
          aria-atomic="true"
          role="status"
        >
          <div>
            <p className="result-label">
              {mode === "benchmark" ? "Median proving time" : "Proving time"}
            </p>
            <div className="timing">
              <span>{provingMs === undefined ? "—" : provingMs.toFixed(1)}</span>
              {provingMs !== undefined && <span className="timing-unit">ms</span>}
            </div>
          </div>
          <div>
            <p className="result-label">
              {mode === "benchmark" ? "Median verification" : "Verification"}
            </p>
            <div className="verification-timing">
              <span className="verify-time">
                {verificationMs === undefined ? "—" : `${verificationMs.toFixed(1)} ms`}
              </span>
            </div>
            {latest && (
              <p className="verified">{results.length > 1 ? "5 proofs verified" : "Verified"}</p>
            )}
          </div>
        </div>
        {error && (
          <div className="error-message" role="alert">
            {error}
          </div>
        )}
        <div className="main-action">
          <button
            type="button"
            className="primary-button"
            disabled={
              phase === "loading" ||
              request === "" ||
              (!busy && threadMode === "custom" && !customValid)
            }
            onClick={() => (busy ? resetRuntime() : void run())}
          >
            {busy ? "Cancel" : mode === "benchmark" ? "Run benchmark" : "Generate proof"}
          </button>
          {(busy || phase === "loading") && (
            <span className="progress" role="status">
              {busy ? progress : "Loading input…"}
            </span>
          )}
          {latest && (
            <div className="result-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => proofDialog.current?.showModal()}
              >
                View proof
              </button>
              <button type="button" className="secondary-button" onClick={downloadProof}>
                Download
              </button>
            </div>
          )}
        </div>
      </section>

      <dialog
        className="sheet"
        ref={options}
        aria-labelledby="options-title"
        onClick={(event) => {
          if (event.target === event.currentTarget) options.current?.close();
        }}
      >
        <div className="sheet-content">
          <div className="sheet-heading">
            <h2 id="options-title">Options</h2>
            <button
              type="button"
              className="icon-button close-button"
              aria-label="Close options"
              onClick={() => options.current?.close()}
            >
              ×
            </button>
          </div>
          <div className="settings-group">
            <label className="settings-row" htmlFor="proving-mode">
              <span>Proving mode</span>
              <select
                id="proving-mode"
                value={threadMode}
                onChange={(event) => {
                  setThreadMode(event.target.value as ThreadMode);
                  resetRuntime();
                }}
              >
                <option value="auto">Automatic</option>
                <option value="custom">Custom threads</option>
                <option value="go">Go baseline</option>
              </select>
            </label>
            {threadMode === "custom" && (
              <label className="settings-row" htmlFor="thread-count">
                <span>Threads</span>
                <input
                  id="thread-count"
                  type="number"
                  min="1"
                  max="64"
                  inputMode="numeric"
                  value={customThreads}
                  aria-invalid={!customValid}
                  onChange={(event) => {
                    setCustomThreads(event.target.value);
                    resetRuntime();
                  }}
                />
              </label>
            )}
          </div>
          {threadMode === "custom" && !customValid && (
            <p className="field-error">Choose between 1 and 64 threads.</p>
          )}
          {threadMode === "auto" && <p className="settings-note">{automaticThreads} threads</p>}
          <details className="input-details">
            <summary>Proof input</summary>
            <label className="sr-only" htmlFor="proof-input">
              Proof input JSON
            </label>
            <textarea
              id="proof-input"
              spellCheck={false}
              value={request}
              onChange={(event) => {
                setRequest(event.target.value);
                clearResult();
              }}
            />
            <button type="button" className="text-button" onClick={() => void restoreSample()}>
              Restore sample
            </button>
          </details>
          <button type="button" className="text-button reset-button" onClick={resetRuntime}>
            Reset prover
          </button>
        </div>
      </dialog>

      <dialog
        className="sheet proof-sheet"
        ref={proofDialog}
        aria-labelledby="proof-title"
        onClick={(event) => {
          if (event.target === event.currentTarget) proofDialog.current?.close();
        }}
      >
        <div className="sheet-content">
          <div className="sheet-heading">
            <h2 id="proof-title">Verified proof</h2>
            <button
              type="button"
              className="icon-button close-button"
              aria-label="Close proof"
              onClick={() => proofDialog.current?.close()}
            >
              ×
            </button>
          </div>
          <dl className="proof-facts">
            <div>
              <dt>{results.length > 1 ? "Median proving" : "Proving"}</dt>
              <dd>{provingMs?.toFixed(1)} ms</dd>
            </div>
            <div>
              <dt>{results.length > 1 ? "Median verification" : "Verification"}</dt>
              <dd>{verificationMs?.toFixed(1)} ms</dd>
            </div>
            <div>
              <dt>Key preparation</dt>
              <dd>
                {preparationMs === undefined ? "—" : `${(preparationMs / 1000).toFixed(2)} s`}
              </dd>
            </div>
            <div>
              <dt>Engine</dt>
              <dd>{activeThreads === 0 ? "Go" : `Arkworks · ${activeThreads} threads`}</dd>
            </div>
          </dl>
          <pre className="proof-json">
            {latest ? JSON.stringify(JSON.parse(latest.proof), null, 2) : ""}
          </pre>
          <button type="button" className="primary-button" onClick={downloadProof}>
            Download JSON
          </button>
        </div>
      </dialog>
    </main>
  );
}
