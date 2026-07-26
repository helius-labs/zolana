import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");

export function proverUrlFromEnv(): URL {
  const explicit = process.env["ZOLANA_PROVER_URL"];
  if (explicit !== undefined && explicit !== "") return new URL(explicit);
  const offset = Number(process.env["ZOLANA_PORT_OFFSET"] ?? "0");
  return new URL(`http://127.0.0.1:${String(3001 + offset)}`);
}

async function portFree(port: number): Promise<boolean> {
  return await new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(false));
    server.listen(port, "127.0.0.1", () => {
      server.close(() => resolve(true));
    });
  });
}

async function healthy(url: URL): Promise<boolean> {
  try {
    const response = await fetch(new URL("/health", url), { signal: AbortSignal.timeout(2_000) });
    return response.ok;
  } catch {
    return false;
  }
}

export interface OwnedProver {
  readonly url: URL;
  stop(): Promise<void>;
}

/// Start the pinned local prover if it is not already healthy at the offset URL.
/// Keys load lazily on first proof request (`--auto-download=true`).
export async function ensureLocalProver(): Promise<OwnedProver> {
  const url = proverUrlFromEnv();
  if (await healthy(url)) {
    return {
      url,
      stop: async () => {},
    };
  }
  const port = Number(url.port);
  if (!(await portFree(port))) {
    throw new Error(`prover port ${String(port)} is busy but /health failed`);
  }
  const binary = process.env["ZOLANA_PROVER_BIN"] ?? path.join(workspaceRoot, "target/prover-server");
  const keysDir = path.join(workspaceRoot, "prover/server/proving-keys");
  const metricsPort = port + 1;
  const child: ChildProcess = spawn(
    binary,
    [
      "start",
      "--keys-dir",
      `${keysDir}${path.sep}`,
      "--prover-address",
      `127.0.0.1:${String(port)}`,
      "--metrics-address",
      `127.0.0.1:${String(metricsPort)}`,
      "--auto-download=true",
    ],
    { cwd: workspaceRoot, stdio: "ignore" },
  );
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`prover exited early with code ${String(child.exitCode)}`);
    }
    if (await healthy(url)) {
      return {
        url,
        stop: async () => {
          child.kill("SIGTERM");
          await new Promise<void>((resolve) => {
            child.once("exit", () => resolve());
            setTimeout(resolve, 2_000);
          });
        },
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  child.kill("SIGTERM");
  throw new Error(`prover failed to become healthy at ${url.href}`);
}
