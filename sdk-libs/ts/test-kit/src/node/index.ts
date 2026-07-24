/// <reference types="node" />

import { spawn, type ChildProcess } from "node:child_process";
import { access, mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SHIELDED_POOL_PROGRAM_ID } from "@zolana/interface";
import { SMART_ACCOUNT_PROGRAM_ID } from "@zolana/smart-account-client";

import { TestKitError } from "../error.js";
import type { LocalStack } from "../index.js";
import { ZONE_TEST_PROGRAM_ID } from "../instructions.js";
import { writeProgramConfigFixture } from "../standard-accounts.js";

export * from "../admin.js";
export * from "../events.js";
export * from "../harness.js";
export * from "../indexer.js";
export * from "../instructions.js";
export * from "../paths.js";
export * from "../proofless.js";
export * from "../prover.js";
export * from "../rpc.js";
export * from "../spl.js";
export * from "../standard-accounts.js";
export * from "../user-registry.js";
export * from "../wallet-data.js";
export * from "../zone.js";

const DEFAULT_RPC_PORT = 8899;
const DEFAULT_INDEXER_PORT = 8784;
const DEFAULT_PROVER_PORT = 3001;
const DEFAULT_METRICS_PORT = 9998;
const DEFAULT_TIMEOUT_MS = 120_000;
const USER_REGISTRY_PROGRAM_ID = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc";

interface StackUrls {
  readonly rpcUrl: URL;
  readonly indexerUrl: URL;
  readonly proverUrl: URL;
  readonly external: Readonly<{ rpc: boolean; indexer: boolean; prover: boolean }>;
}

interface OwnedProcess {
  readonly child: ChildProcess;
  readonly name: string;
  readonly diagnostics: () => string;
  readonly spawnError: () => string | undefined;
}

export function localStackUrls(input: Readonly<{ portOffset?: number }> = {}): StackUrls {
  const offset = input.portOffset ?? environmentOffset();
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 900) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "portOffset", min: 0, max: 900 },
    });
  }
  return Object.freeze({
    rpcUrl: configuredUrl("ZOLANA_LOCALNET_URL", DEFAULT_RPC_PORT + offset),
    indexerUrl: configuredUrl("ZOLANA_INDEXER_URL", DEFAULT_INDEXER_PORT + offset),
    proverUrl: configuredUrl("ZOLANA_PROVER_URL", DEFAULT_PROVER_PORT + offset),
    external: Object.freeze({
      rpc: hasEnvironmentValue("ZOLANA_LOCALNET_URL"),
      indexer: hasEnvironmentValue("ZOLANA_INDEXER_URL"),
      prover: hasEnvironmentValue("ZOLANA_PROVER_URL"),
    }),
  });
}

export async function startLocalStack(
  input: Readonly<{
    programPath?: string;
    portOffset?: number;
    signal?: AbortSignal;
  }> = {},
): Promise<LocalStack> {
  throwIfAborted(input.signal);
  const urls = localStackUrls(input);
  const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "zolana-ts-"));
  const owned: OwnedProcess[] = [];
  let stopped = false;

  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    await Promise.allSettled([...owned].reverse().map(stopOwnedProcess));
    await rm(temporaryDirectory, { recursive: true, force: true });
  };

  try {
    if (urls.external.rpc) {
      await waitForRpc(urls.rpcUrl, "validator", input.signal);
    } else {
      const programPath =
        input.programPath ?? path.join(workspace, "target/deploy/shielded_pool_program.so");
      const programs = [
        [SHIELDED_POOL_PROGRAM_ID, programPath],
        [USER_REGISTRY_PROGRAM_ID, path.join(workspace, "target/deploy/zolana_user_registry.so")],
        [
          SMART_ACCOUNT_PROGRAM_ID,
          path.join(workspace, "target/deploy/squads_smart_account_program.so"),
        ],
        [ZONE_TEST_PROGRAM_ID, path.join(workspace, "target/deploy/zone_test_program.so")],
      ] as const;
      await Promise.all(
        programs.map(([, file], index) =>
          requireFile(file, index === 0 ? "programPath" : `programPath[${String(index)}]`),
        ),
      );
      const accountDirectory = path.join(temporaryDirectory, "accounts");
      await writeProgramConfigFixture(accountDirectory);
      await assertPortAvailable(urls.rpcUrl);
      owned.push(
        spawnOwned(
          process.env["SOLANA_TEST_VALIDATOR_BIN"] ?? "solana-test-validator",
          [
            "--reset",
            "--limit-ledger-size=10000",
            `--rpc-port=${String(port(urls.rpcUrl))}`,
            "--bind-address=127.0.0.1",
            "--quiet",
            "--ledger",
            path.join(temporaryDirectory, "ledger"),
            ...programs.flatMap(([programId, file]) => ["--bpf-program", programId, file]),
            "--account-dir",
            accountDirectory,
          ],
          "validator",
          workspace,
        ),
      );
      await waitForRpc(urls.rpcUrl, "validator", input.signal, owned.at(-1));
    }

    if (urls.external.prover) {
      await waitForHttp(urls.proverUrl, "/health", "prover", input.signal);
    } else {
      await assertPortAvailable(urls.proverUrl);
      const proverPort = port(urls.proverUrl);
      const metricsPort = DEFAULT_METRICS_PORT + (proverPort - DEFAULT_PROVER_PORT);
      await assertPortAvailable(new URL(`http://127.0.0.1:${String(metricsPort)}`));
      const proverBinary =
        process.env["ZOLANA_PROVER_BIN"] ?? path.join(workspace, "target/prover-server");
      await requireFile(proverBinary, "proverBinary");
      owned.push(
        spawnOwned(
          proverBinary,
          [
            "start",
            "--keys-dir",
            `${path.join(workspace, "prover/server/proving-keys")}${path.sep}`,
            "--prover-address",
            `127.0.0.1:${String(proverPort)}`,
            "--metrics-address",
            `127.0.0.1:${String(metricsPort)}`,
            "--auto-download=true",
          ],
          "prover",
          workspace,
        ),
      );
      await waitForHttp(urls.proverUrl, "/health", "prover", input.signal, owned.at(-1));
    }

    if (urls.external.indexer) {
      await waitForHttp(urls.indexerUrl, "/readiness", "Photon", input.signal);
    } else {
      await assertPortAvailable(urls.indexerUrl);
      const photonBinary =
        process.env["ZOLANA_PHOTON_BIN"] ?? path.join(workspace, "target/debug/photon");
      await requireFile(photonBinary, "photonBinary");
      owned.push(
        spawnOwned(
          photonBinary,
          [
            "--rpc-url",
            urls.rpcUrl.toString(),
            "--port",
            String(port(urls.indexerUrl)),
            "--start-slot",
            "latest",
            "--db-url",
            `sqlite://${path.join(temporaryDirectory, "photon.db")}`,
          ],
          "Photon",
          workspace,
        ),
      );
      await waitForHttp(urls.indexerUrl, "/readiness", "Photon", input.signal, owned.at(-1));
    }

    return Object.freeze({
      rpcUrl: new URL(urls.rpcUrl),
      indexerUrl: new URL(urls.indexerUrl),
      proverUrl: new URL(urls.proverUrl),
      stop,
    });
  } catch (cause) {
    await stop();
    if (cause instanceof TestKitError) throw cause;
    throw new TestKitError("TEST_KIT_PROCESS", { cause: safeCause(cause) });
  }
}

function environmentOffset(): number {
  const value = process.env["ZOLANA_PORT_OFFSET"];
  if (value === undefined || value === "") return 0;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: "ZOLANA_PORT_OFFSET" },
    });
  }
  return parsed;
}

function configuredUrl(variable: string, fallbackPort: number): URL {
  const value = process.env[variable];
  const url = new URL(
    value && value.trim() !== "" ? value : `http://127.0.0.1:${String(fallbackPort)}`,
  );
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field: variable, protocol: url.protocol },
    });
  }
  return url;
}

function hasEnvironmentValue(variable: string): boolean {
  const value = process.env[variable];
  return value !== undefined && value.trim() !== "";
}

function port(url: URL): number {
  if (url.port !== "") return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

async function requireFile(file: string, field: string): Promise<void> {
  try {
    await access(file);
  } catch {
    throw new TestKitError("TEST_KIT_INVALID_CONFIG", {
      details: { field, reason: "missing" },
    });
  }
}

async function assertPortAvailable(url: URL): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", () => {
      reject(
        new TestKitError("TEST_KIT_PROCESS", {
          details: { service: "port", host: url.hostname, port: port(url), reason: "inUse" },
        }),
      );
    });
    server.listen({ host: url.hostname, port: port(url) }, () => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
  });
}

function spawnOwned(
  command: string,
  args: readonly string[],
  name: string,
  cwd: string,
): OwnedProcess {
  const child = spawn(command, args, {
    cwd,
    detached: process.platform !== "win32",
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let spawnError: string | undefined;
  const collect = (chunk: Uint8Array): void => {
    output = redactDiagnostic(`${output}${new TextDecoder().decode(chunk)}`).slice(-8_192);
  };
  child.on("error", (error) => {
    spawnError = error.name;
  });
  child.stdout.on("data", collect);
  child.stderr.on("data", collect);
  return { child, name, diagnostics: () => output, spawnError: () => spawnError };
}

async function stopOwnedProcess(processHandle: OwnedProcess): Promise<void> {
  const child = processHandle.child;
  if (child.exitCode !== null || child.pid === undefined) return;
  try {
    if (process.platform === "win32") child.kill("SIGTERM");
    else globalThis.process.kill(-child.pid, "SIGTERM");
  } catch {
    return;
  }
  const exited = await waitForExit(child, 3_000);
  if (!exited) {
    try {
      if (process.platform === "win32") child.kill("SIGKILL");
      else globalThis.process.kill(-child.pid, "SIGKILL");
    } catch {
      return;
    }
    await waitForExit(child, 2_000);
  }
}

function waitForExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve(false);
    }, timeoutMs);
    timeout.unref();
    child.once("exit", () => {
      clearTimeout(timeout);
      resolve(true);
    });
  });
}

async function waitForRpc(
  url: URL,
  service: string,
  signal?: AbortSignal,
  owned?: OwnedProcess,
): Promise<void> {
  await waitUntilReady(service, signal, owned, async (requestSignal) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"jsonrpc":"2.0","id":1,"method":"getHealth"}',
      signal: requestSignal,
    });
    return response.ok && ((await response.json()) as { result?: unknown }).result === "ok";
  });
}

async function waitForHttp(
  baseUrl: URL,
  pathname: string,
  service: string,
  signal?: AbortSignal,
  owned?: OwnedProcess,
): Promise<void> {
  const url = new URL(pathname, baseUrl);
  await waitUntilReady(
    service,
    signal,
    owned,
    async (requestSignal) => (await fetch(url, { signal: requestSignal })).ok,
  );
}

async function waitUntilReady(
  service: string,
  signal: AbortSignal | undefined,
  owned: OwnedProcess | undefined,
  probe: (signal: AbortSignal) => Promise<boolean>,
): Promise<void> {
  const deadline = Date.now() + DEFAULT_TIMEOUT_MS;
  let stable = 0;
  while (Date.now() < deadline) {
    throwIfAborted(signal);
    if (owned?.spawnError() !== undefined) {
      throw new TestKitError("TEST_KIT_PROCESS", {
        details: { service, reason: owned.spawnError() },
      });
    }
    if (owned?.child.exitCode !== null && owned?.child.exitCode !== undefined) {
      throw new TestKitError("TEST_KIT_PROCESS", {
        details: {
          service,
          exitCode: owned.child.exitCode,
          diagnostics: owned.diagnostics(),
        },
      });
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, 1_000);
    timeout.unref();
    try {
      stable = (await probe(controller.signal)) ? stable + 1 : 0;
      if (stable >= 2) return;
    } catch {
      stable = 0;
    } finally {
      clearTimeout(timeout);
    }
    await delay(250, signal);
  }
  throw new TestKitError("TEST_KIT_READINESS", {
    details: {
      service,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      diagnostics: owned?.diagnostics() ?? "",
    },
  });
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(resolve, milliseconds);
    timeout.unref();
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        reject(new TestKitError("TEST_KIT_ABORTED"));
      },
      { once: true },
    );
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new TestKitError("TEST_KIT_ABORTED");
}

export function redactDiagnostic(value: string): string {
  return value
    .replaceAll(/([?&](?:api[_-]?key|token|secret)=)[^&\s]+/giu, "$1[REDACTED]")
    .replaceAll(/(authorization:\s*)\S+/giu, "$1[REDACTED]")
    .replaceAll(/[0-9a-f]{64,}/giu, "[REDACTED]");
}

function safeCause(cause: unknown): unknown {
  return cause instanceof Error ? Object.freeze({ name: cause.name }) : undefined;
}
