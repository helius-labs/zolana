import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { TimedTransport } from "./transport.mjs";
import { writeReports } from "./report.mjs";

export const FAMILIES = Object.freeze([
  "transfer-confidential",
  "transfer-ring",
  "transfer-ring-authority",
  "transfer-p256-ring",
  "merge",
  "merge-ring",
  "custom-ring-base",
  "custom-ring-policy",
]);

export function matrix() {
  const pair = (family, repetition) =>
    ["baseline", "candidate"].map((deployment) => ({
      family,
      deployment,
      repetition,
      source: deployment === "candidate" && !family.startsWith("custom-ring") ? "prover" : "client",
    }));
  return [
    ...FAMILIES.flatMap((family) => pair(family, 1)),
    ...FAMILIES.slice(0, 6).flatMap((family) => pair(family, 2)),
    ...["transfer-confidential", "merge"].map((family) => ({
      family,
      deployment: "candidate",
      repetition: 3,
      source: "client",
    })),
  ];
}

export class Budget {
  static async acquire(directory, maxAttempts = 30) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const lock = join(directory, "sweep.lock");
    await mkdir(lock);
    try {
      const path = join(directory, "budget.json");
      let state;
      try {
        state = JSON.parse(await readFile(path, "utf8"));
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        state = {
          attempts: 0,
          maxAttempts,
          startedAt: Date.now(),
          lastCompletedAt: 0,
          stopped: null,
        };
      }
      state.maxAttempts ??= 30;
      if (
        ![8, 30].includes(maxAttempts) ||
        state.maxAttempts !== maxAttempts ||
        !Number.isInteger(state.attempts) ||
        state.attempts < 0 ||
        state.attempts > maxAttempts ||
        !Number.isFinite(state.startedAt) ||
        !Number.isFinite(state.lastCompletedAt)
      ) {
        throw new Error("Invalid sweep budget");
      }
      const budget = new Budget(path, lock, state);
      await budget.persist();
      return budget;
    } catch (error) {
      await rm(lock, { recursive: true });
      throw error;
    }
  }

  constructor(path, lock, state) {
    this.path = path;
    this.lock = lock;
    this.state = state;
  }
  remainingMs() {
    return Math.max(0, this.state.startedAt + 600_000 - Date.now());
  }
  async persist() {
    const temporary = `${this.path}.tmp`;
    const file = await open(temporary, "w", 0o600);
    try {
      await file.writeFile(JSON.stringify(this.state));
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, this.path);
  }
  async claim() {
    if (this.state.stopped || this.state.attempts >= this.state.maxAttempts || !this.remainingMs())
      throw new Error("Sweep budget exhausted");
    this.state.attempts++;
    // 1. Save the attempt before any proof request can leave the process.
    await this.persist();
    return this.state.attempts;
  }
  async beginPhase(phase, identity) {
    if (!["public", "private"].includes(phase)) throw new Error("Invalid campaign phase");
    const phases = this.state.phases ?? {};
    if (
      typeof identity !== "string" ||
      !identity ||
      (this.state.campaignIdentity && this.state.campaignIdentity !== identity)
    )
      throw new Error("Campaign fixture identity changed");
    const expectedAttempts = phase === "public" ? 0 : 4;
    if (
      this.state.stopped ||
      phases[phase] ||
      this.state.attempts !== expectedAttempts ||
      (phase === "private" && phases.public?.status !== "complete")
    ) {
      throw new Error("Campaign phase cannot start or resume");
    }
    this.state.campaignIdentity = identity;
    this.state.phases = {
      ...phases,
      [phase]: { status: "running", firstAttempt: expectedAttempts + 1 },
    };
    this.state.startedAt = Date.now();
    await this.persist();
  }
  async finishPhase(phase) {
    const current = this.state.phases[phase];
    if (this.state.stopped || this.state.attempts !== current.firstAttempt + 3) {
      throw new Error("Campaign phase did not complete four proofs");
    }
    current.status = "complete";
    current.completedAt = new Date().toISOString();
    await this.persist();
  }
  async stop(reason) {
    this.state.stopped = reason;
    await this.persist();
  }
  async complete() {
    this.state.lastCompletedAt = Date.now();
    await this.persist();
  }
  async close() {
    await rm(this.lock, { recursive: true });
  }
}

export async function sweep({
  directory,
  deployments,
  indexer,
  fixtures,
  metadata = {},
  entries = matrix(),
  campaign,
}) {
  if (
    !Array.isArray(entries) ||
    entries.length === 0 ||
    entries.length > 30 ||
    entries.some(
      (entry) =>
        !entry ||
        typeof entry.family !== "string" ||
        !deployments[entry.deployment] ||
        !["client", "prover"].includes(entry.source) ||
        !Number.isInteger(entry.repetition) ||
        entry.repetition < 1,
    )
  ) {
    throw new Error("Invalid proof matrix");
  }
  if (
    campaign &&
    (entries.length !== 4 ||
      !campaign.directory ||
      !["public", "private"].includes(campaign.phase) ||
      new Set(entries.map((entry) => `${entry.variant}:${entry.repetition}`)).size !== 4 ||
      entries.some((entry) => {
        const fixture = fixtures[entry.fixture ?? entry.family];
        return (
          entry.family !== "transfer-confidential" ||
          entry.deployment !== "candidate" ||
          entry.source !== "prover" ||
          entry.route !== campaign.phase ||
          !["padded", "compact"].includes(entry.variant) ||
          entry.fixture !== entry.variant ||
          ![1, 2].includes(entry.repetition) ||
          !fixture ||
          typeof fixture.verify !== "function" ||
          fixture.blocked ||
          fixture.blockedDeployments?.[entry.deployment]
        );
      }))
  )
    throw new Error("Campaign requires four available proof entries");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const budget = await Budget.acquire(campaign?.directory ?? directory, campaign ? 8 : 30);
  const transport = new TimedTransport();
  const results = [];
  try {
    if (campaign) await budget.beginPhase(campaign.phase, campaign.identity);
    else if (budget.state.attempts) throw new Error("Existing sweep cannot be resumed");
    for (const entry of entries) {
      const fixture = fixtures[entry.fixture ?? entry.family];
      const blocked = fixture?.blocked ?? fixture?.blockedDeployments?.[entry.deployment];
      if (!fixture || blocked) {
        results.push({
          ...entry,
          status: "blocked",
          reason: blocked ?? "fixture_unavailable",
        });
        continue;
      }
      if (typeof fixture.verify !== "function") throw new Error("A proof verifier is required");
      if (!budget.remainingMs() || budget.state.stopped) break;
      await delay(Math.max(0, budget.state.lastCompletedAt + 1000 - Date.now()));
      if (!budget.remainingMs()) break;
      const attempt = await budget.claim();
      const origin = performance.now();
      const abort = new AbortController();
      const signal = AbortSignal.any([
        abort.signal,
        AbortSignal.timeout(Math.min(60_000, budget.remainingMs())),
      ]);
      const result = {
        ...entry,
        attempt,
        submitted: false,
        shape: fixture.shape,
        status: "running",
        spans: [],
        requests: [],
        startedAt: new Date().toISOString(),
      };
      results.push(result);
      let submitted = false;
      const wire = [];
      const span = async (name, action) => {
        const row = { name, startMs: performance.now() - origin };
        result.spans.push(row);
        try {
          return await action();
        } finally {
          row.endMs = performance.now() - origin;
          row.durationMs = row.endMs - row.startMs;
        }
      };
      const fetch = async (input, init = {}) => {
        signal.throwIfAborted();
        const url = new URL(String(input));
        const prover = new URL(deployments[entry.deployment]);
        const photon = new URL(indexer);
        const isProver = url.origin === prover.origin;
        if (!isProver && url.origin !== photon.origin)
          throw new Error("Request destination is outside the sweep");
        const proof = isProver && init.method?.toUpperCase() === "POST";
        const headers = new Headers(init.headers);
        if (proof) {
          if (submitted) {
            abort.abort();
            throw new Error("Proof retries are disabled");
          }
          const body = JSON.parse(String(init.body));
          const payload = body.prepared ?? body;
          if (
            campaign &&
            (!Number.isInteger(payload.nInputs) || !Number.isInteger(payload.nOutputs))
          ) {
            abort.abort();
            throw new Error("Campaign proof shape is missing");
          }
          if (Number.isInteger(payload.nInputs) && Number.isInteger(payload.nOutputs)) {
            result.actualShape = `${payload.nInputs}x${payload.nOutputs}`;
            if (result.actualShape !== fixture.shape) {
              abort.abort();
              throw new Error("Proof request shape does not match fixture");
            }
          }
          submitted = true;
          result.submitted = true;
          headers.delete("x-async");
          headers.set("x-sync", "true");
          if (entry.deployment === "candidate") headers.set("x-prover-timing", "true");
        }
        let rpc;
        if (!isProver) {
          try {
            rpc = JSON.parse(String(init.body)).method;
          } catch {
            rpc = "unknown";
          }
        }
        try {
          let requestRow;
          const response = await transport.request({
            url,
            init: { ...init, headers },
            signal: AbortSignal.any([signal, ...(init.signal ? [init.signal] : [])]),
            origin,
            record: (row) => {
              requestRow = Object.assign(row, {
                lane: isProver ? "prover" : "indexer",
                operation: isProver ? url.pathname : rpc,
              });
              result.requests.push(requestRow);
            },
          });
          if (!response.ok) {
            abort.abort();
            throw new Error(`HTTP ${response.status}`);
          }
          const text = await response.clone().text();
          let value;
          try {
            value = JSON.parse(text);
          } catch {
            throw new Error("Invalid JSON response");
          }
          if (!isProver && value.error !== undefined) {
            requestRow.rpcError = true;
            abort.abort();
            throw new Error("Indexer RPC failed");
          }
          if (!isProver && value.result?.context?.slot !== undefined)
            requestRow.contextSlot = value.result.context.slot;
          if (proof) wire.push({ request: JSON.parse(String(init.body)), response: value });
          if (isProver && !proof && value.status === "completed") {
            wire.at(-1).response = value.result ?? value;
          }
          return response;
        } catch (error) {
          abort.abort();
          throw error;
        }
      };
      try {
        const proof = await bounded(signal, () =>
          fixture.prove({
            ...entry,
            url: deployments[entry.deployment],
            indexer,
            fetch,
            signal,
            span,
          }),
        );
        if (!submitted) throw new Error("No proof request was sent");
        result.sdkReadyMs = performance.now() - origin;
        result.proofReceivedMs = result.requests.findLast(
          (request) => request.lane === "prover",
        ).endMs;
        const verified = await span("verification", () =>
          bounded(signal, () => fixture.verify({ proof, wire, entry, signal })),
        );
        if (verified !== true) throw new Error("Proof verification failed");
        result.verified = true;
        result.status = "ok";
      } catch {
        result.status = signal.aborted ? "stopped" : "failed";
        result.error = signal.aborted ? "request_aborted" : "preparation_or_verification_failed";
        await budget.stop(result.error);
      } finally {
        result.totalMs = performance.now() - origin;
        await budget.complete();
        await writeReports({ directory, metadata, results, budget: budget.state });
      }
      if (budget.state.stopped) break;
    }
    if (campaign && !budget.state.stopped) {
      if (results.length === 4 && results.every((result) => result.status === "ok"))
        await budget.finishPhase(campaign.phase);
      else await budget.stop("campaign_incomplete");
    }
    await writeReports({ directory, metadata, results, budget: budget.state });
    return results;
  } finally {
    transport.close();
    await budget.close();
  }
}

function bounded(signal, action) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve()
      .then(action)
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [adapterPath, output] = process.argv.slice(2);
  if (!adapterPath || !output) throw new Error("Usage node sweep.mjs ADAPTER.mjs OUTPUT_DIRECTORY");
  const adapter = await import(pathToFileURL(resolve(adapterPath)).href);
  const config = await adapter.prepare();
  await sweep({ ...config, directory: resolve(output) });
}
