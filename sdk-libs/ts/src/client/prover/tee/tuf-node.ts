import { randomUUID } from "node:crypto";
import { mkdir, open, readdir, rename, unlink, writeFile, mkdtemp, rm } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { Updater, type Fetcher } from "tuf-js";
// The published custom-fetcher error type is not re-exported by tuf-js 5's barrel.
import { DownloadHTTPError } from "tuf-js/dist/error.js";

import { readBoundedBody } from "../../../services/transport.js";
import { composeSignal, requestError, sleep, type ComposedSignal } from "../../internal.js";
import { identifier, teeFleetPolicyFromJson } from "./fleet.js";
import { invalidPolicy, policyDecode, refused } from "./platform.js";
import { TeePolicySource, type TeePolicyDocument } from "./source.js";
import {
  LIMITS,
  MAX_POLICY_BYTES,
  checkAbort,
  digest,
  parseJson,
  repositoryUrl,
  sourceFetch,
} from "./repository.js";
const ROLES = ["root", "timestamp", "snapshot", "targets"] as const;

export interface TufTeePolicyOptions {
  readonly network: string;
  /** Reviewed bootstrap root JSON, obtained independently of the serving repository. */
  readonly rootJson: string;
  readonly metadataUrl: string | URL;
  readonly targetsUrl: string | URL;
  /** Absolute, trusted local directory. Concurrent processes serialize through a lock. */
  readonly cacheDirectory: string;
  readonly refreshIntervalMs?: number;
  readonly fetch?: typeof globalThis.fetch;
}

/** Node-only reference TUF client, serving the <network>/fleet.json target. */
export function tufTeePolicy(options: TufTeePolicyOptions): TeePolicySource {
  policyDecode.record(options, "source");
  const network = identifier(options.network, "network");
  if (typeof options.rootJson !== "string" || Buffer.byteLength(options.rootJson) > LIMITS.root) {
    throw invalidPolicy("source.rootJson");
  }
  if (typeof options.cacheDirectory !== "string" || !isAbsolute(options.cacheDirectory)) {
    throw invalidPolicy("source.cacheDirectory");
  }
  const metadataUrl = repositoryUrl(options.metadataUrl);
  const targetsUrl = repositoryUrl(options.targetsUrl);
  const fetch = sourceFetch(options.fetch);
  const rootJson = options.rootJson;
  const namespace = digest(JSON.stringify([network, metadataUrl.href, targetsUrl.href, rootJson]));
  const directory = join(options.cacheDirectory, namespace);
  const targetPath = `${network}/fleet.json`;

  return new TeePolicySource({
    network,
    ...(options.refreshIntervalMs === undefined
      ? {}
      : { refreshIntervalMs: options.refreshIntervalMs }),
    load: async (context): Promise<TeePolicyDocument> => {
      const request = composeSignal(context, "attest");
      try {
        await mkdir(directory, { recursive: true, mode: 0o700 });
        const release = await lock(directory, request);
        try {
          return await loadPolicy(request);
        } finally {
          await release();
        }
      } catch {
        if (request.signal.aborted) throw requestError("attest", request);
        throw refused("policy_repository");
      } finally {
        request.cleanup();
      }
    },
  });

  async function loadPolicy(request: ComposedSignal): Promise<TeePolicyDocument> {
    checkAbort(request);
    const files = await readdir(directory);
    if (!files.includes("root.json")) {
      // A missing root in a populated cache is damage, never a fresh bootstrap.
      if (files.some((name) => name !== "lock")) throw refused("policy_storage");
      await writeFile(join(directory, "root.json"), rootJson, { flag: "wx", mode: 0o600 });
    }
    // Corrupt persisted JSON must not cause the updater to silently reset its floors.
    for (const role of ROLES) {
      if (role === "root" || files.includes(`${role}.json`)) {
        metadataExpiry(await localBytes(join(directory, `${role}.json`), LIMITS[role]));
      }
    }
    const updater = new Updater({
      metadataDir: directory,
      metadataBaseUrl: metadataUrl.href,
      targetDir: directory,
      targetBaseUrl: targetsUrl.href,
      fetcher: new PolicyFetcher(fetch, request, metadataUrl, targetsUrl, directory),
      config: {
        maxRootRotations: 32,
        // This repository contract publishes the fleet directly in top-level targets.
        maxDelegations: 0,
        rootMaxLength: LIMITS.root,
        timestampMaxLength: LIMITS.timestamp,
        snapshotMaxLength: LIMITS.snapshot,
        targetsMaxLength: LIMITS.targets,
        fetchRetry: false,
      },
    });
    await updater.refresh();
    checkAbort(request);
    const info = await updater.getTargetInfo(targetPath);
    if (
      info === undefined ||
      !Number.isSafeInteger(info.length) ||
      info.length <= 0 ||
      info.length > MAX_POLICY_BYTES
    ) {
      throw refused("policy_target");
    }
    const hashes = Object.entries(info.hashes);
    if (
      hashes.length === 0 ||
      hashes.some(([algorithm, value]) => {
        const length = algorithm === "sha256" ? 64 : algorithm === "sha512" ? 128 : 0;
        return length === 0 || value.length !== length || !/^[a-f0-9]+$/u.test(value);
      })
    )
      throw refused("policy_target");
    const cached = await updater.findCachedTarget(info);
    const target = cached ?? (await updater.downloadTarget(info));
    const bytes = await localBytes(target, MAX_POLICY_BYTES);
    const policyJson = parseJson(bytes);
    const policy = teeFleetPolicyFromJson(policyJson, network);
    const expires = await Promise.all(
      ROLES.map(async (role) =>
        metadataExpiry(await localBytes(join(directory, `${role}.json`), LIMITS[role])),
      ),
    );
    const validUntil = Math.min(policy.expiresAt, ...expires);
    if (Date.now() >= validUntil * 1000) throw refused("policy_expired");
    const hash = digest(bytes);
    const floorPath = join(directory, "fleet-floor.json");
    const existing = await optionalBytes(floorPath, 1024);
    if (existing !== undefined) {
      const floor = policyDecode.record(parseJson(existing), "source.floor");
      const revision = floor["revision"];
      const previousHash = floor["sha256"];
      if (
        typeof revision !== "number" ||
        !Number.isSafeInteger(revision) ||
        revision <= 0 ||
        typeof previousHash !== "string" ||
        !/^[a-f0-9]{64}$/u.test(previousHash)
      ) {
        throw refused("policy_storage");
      }
      if (policy.revision < revision || (policy.revision === revision && previousHash !== hash)) {
        throw refused("policy_rollback");
      }
    }
    checkAbort(request);
    const temporary = join(directory, `${randomUUID()}.floor.tmp`);
    try {
      await writeFile(temporary, JSON.stringify({ revision: policy.revision, sha256: hash }), {
        flag: "wx",
        mode: 0o600,
      });
      checkAbort(request);
      await rename(temporary, floorPath);
    } finally {
      await rm(temporary, { force: true });
    }
    checkAbort(request);
    return { policy: policyJson, validUntil };
  }
}

class PolicyFetcher implements Fetcher {
  constructor(
    private readonly fetch: typeof globalThis.fetch,
    private readonly request: ComposedSignal,
    private readonly metadata: URL,
    private readonly targets: URL,
    private readonly directory: string,
  ) {}

  async downloadBytes(url: string, maxLength: number): Promise<Buffer> {
    const bytes = await this.bytes(url, Math.min(maxLength, LIMITS.targets));
    metadataExpiry(bytes);
    return bytes;
  }

  async downloadFile<T>(
    url: string,
    maxLength: number,
    handler: (file: string) => Promise<T>,
  ): Promise<T> {
    const bytes = await this.bytes(url, Math.min(maxLength, MAX_POLICY_BYTES));
    const temporary = await mkdtemp(join(this.directory, "target-"));
    try {
      const path = join(temporary, "target");
      await writeFile(path, bytes, { mode: 0o600 });
      checkAbort(this.request);
      return await handler(path);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }

  private async bytes(address: string, limit: number): Promise<Buffer> {
    checkAbort(this.request);
    const url = new URL(address);
    if (
      ![this.metadata, this.targets].some(
        (base) => url.origin === base.origin && url.pathname.startsWith(base.pathname),
      ) ||
      url.search !== "" ||
      url.hash !== "" ||
      url.username !== "" ||
      url.password !== ""
    ) {
      throw refused("policy_url");
    }
    const response = await this.fetch(url, {
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      signal: this.request.signal,
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new DownloadHTTPError("Policy metadata download failed", response.status);
    }
    const body = await readBoundedBody(response, limit);
    checkAbort(this.request);
    return Buffer.from(body);
  }
}

async function lock(directory: string, request: ComposedSignal): Promise<() => Promise<void>> {
  const path = join(directory, "lock");
  for (;;) {
    checkAbort(request);
    try {
      const handle = await open(path, "wx", 0o600);
      await handle.close();
      return async () => {
        await unlink(path);
      };
    } catch (error) {
      if (!hasErrorCode(error, "EEXIST")) throw error;
      // Never break an apparently stale lock: another process may still own it.
      await sleep(25n, { signal: request.signal });
    }
  }
}

async function localBytes(path: string, limit: number): Promise<Buffer> {
  const file = await open(path, "r");
  try {
    const bytes = Buffer.alloc(limit + 1);
    let length = 0;
    for (;;) {
      const { bytesRead } = await file.read(bytes, length, bytes.length - length, null);
      if (bytesRead === 0) return bytes.subarray(0, length);
      length += bytesRead;
      if (length > limit) throw refused("policy_storage");
    }
  } finally {
    await file.close();
  }
}

async function optionalBytes(path: string, limit: number): Promise<Buffer | undefined> {
  try {
    return await localBytes(path, limit);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return undefined;
    throw error;
  }
}

function hasErrorCode(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

function metadataExpiry(bytes: Uint8Array): number {
  const signed = policyDecode.record(
    policyDecode.record(parseJson(bytes), "source.metadata")["signed"],
    "source.metadata.signed",
  );
  const version = signed["version"];
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version <= 0)
    throw refused("policy_metadata");
  const expires = Date.parse(policyDecode.string(signed["expires"], "source.metadata.expires"));
  if (!Number.isSafeInteger(expires) || expires <= 0) throw refused("policy_metadata");
  // Fleet timestamps are whole seconds; never round past authenticated expiry.
  return Math.floor(expires / 1000);
}
