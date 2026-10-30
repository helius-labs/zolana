import { utf8ToBytes } from "@noble/hashes/utils.js";
import { readBoundedBody } from "../../../services/transport.js";
import { ClientError } from "../../error.js";
import { composeSignal, requestError, type ComposedSignal } from "../../internal.js";
import { identifier, teeFleetPolicyFromJson } from "./fleet.js";
import { invalidPolicy, policyDecode, refused } from "./platform.js";
import { TeePolicySource, type TeePolicyDocument } from "./source.js";
import { BrowserTrust, type MetadataFiles, type Role } from "./browser/core.js";
import { uniqueJson } from "./json.js";
import { openPolicyDatabase, readPolicyState, writePolicyState } from "./browser/storage.js";
import {
  LIMITS,
  MAX_POLICY_BYTES,
  checkAbort,
  digest,
  parseJson,
  repositoryUrl,
  sourceFetch,
  text,
} from "./repository.js";

export interface BrowserTufTeePolicyOptions {
  readonly network: string;
  /** Independently reviewed bootstrap root; never fetched from the serving prover. */
  readonly rootJson: string;
  readonly metadataUrl: string | URL;
  readonly targetsUrl: string | URL;
  /** Origin-local IndexedDB database; default zolana-tee-policy-v1. */
  readonly databaseName?: string;
  readonly refreshIntervalMs?: number;
  readonly fetch?: typeof globalThis.fetch;
}

type Cache = Readonly<{
  schemaVersion: 1;
  files: MetadataFiles;
  revision: number;
  sha256: string | null;
}>;

/** Browser TUF provider: Ed25519/SHA-256, IndexedDB checkpoints and cross-tab Web Locks. */
export function tufTeePolicy(options: BrowserTufTeePolicyOptions): TeePolicySource {
  policyDecode.record(options, "source");
  const network = identifier(options.network, "network");
  const root = options.rootJson;
  if (typeof root !== "string" || utf8ToBytes(root).length > LIMITS.root)
    throw invalidPolicy("source.rootJson");
  try {
    new BrowserTrust({ root, timestamp: null, snapshot: null, targets: null });
  } catch {
    throw invalidPolicy("source.rootJson");
  }
  const metadata = repositoryUrl(options.metadataUrl);
  const targets = repositoryUrl(options.targetsUrl);
  const databaseName = options.databaseName ?? "zolana-tee-policy-v1";
  if (typeof databaseName !== "string" || !/^[a-zA-Z0-9_.-]{1,128}$/u.test(databaseName))
    throw invalidPolicy("source.databaseName");
  const fetch = sourceFetch(options.fetch);
  const namespace = digest(JSON.stringify([network, metadata.href, targets.href, root]));
  const targetPath = `${network}/fleet.json`;

  return new TeePolicySource({
    network,
    ...(options.refreshIntervalMs === undefined
      ? {}
      : { refreshIntervalMs: options.refreshIntervalMs }),
    load: async (context): Promise<TeePolicyDocument> => {
      const request = composeSignal(context, "attest");
      try {
        if (
          typeof globalThis.indexedDB === "undefined" ||
          typeof globalThis.navigator?.locks?.request !== "function"
        ) {
          throw refused("policy_storage");
        }
        checkAbort(request);
        return await navigator.locks.request(
          `zolana-tee-policy:${databaseName}:${namespace}`,
          { signal: request.signal },
          async () => {
            const db = await openPolicyDatabase(databaseName, request.signal);
            try {
              return await load(db, request);
            } finally {
              db.close();
            }
          },
        );
      } catch (error) {
        if (request.signal.aborted) throw requestError("attest", request);
        if (error instanceof ClientError) throw error;
        throw refused("policy_repository");
      } finally {
        request.cleanup();
      }
    },
  });

  async function load(db: IDBDatabase, request: ComposedSignal): Promise<TeePolicyDocument> {
    const stored = await readPolicyState(db, namespace);
    let cache: Cache;
    if (stored.marker === undefined && stored.data === undefined) {
      cache = {
        schemaVersion: 1,
        files: { root, timestamp: null, snapshot: null, targets: null },
        revision: 0,
        sha256: null,
      };
    } else {
      if (stored.marker !== 1) throw refused("policy_storage");
      try {
        cache = checkedCache(stored.data);
      } catch {
        throw refused("policy_storage");
      }
    }
    let trust: BrowserTrust;
    try {
      trust = new BrowserTrust(cache.files);
    } catch {
      throw refused("policy_storage");
    }
    const checkpoint = async (): Promise<void> => {
      cache = { ...cache, files: trust.files };
      await writePolicyState(db, namespace, { ...cache, checksum: checksum(cache) });
    };
    await checkpoint();
    try {
      for (let count = 0; count < 32; count++) {
        const version = trust.rootVersion + 1;
        if (!Number.isSafeInteger(version)) throw refused("policy_metadata");
        const next = await download(metadata, `${version}.root.json`, LIMITS.root, request, true);
        if (next === undefined) break;
        trust.root(text(next));
        await checkpoint();
        if (count === 31) throw refused("policy_root_limit");
      }
      trust.restoreTimestamp();
      const timestamp = await required(metadata, "timestamp.json", LIMITS.timestamp, request);
      trust.timestamp(text(timestamp));
      await checkpoint();
      trust.restoreSnapshot();
      const snapshot = trust.snapshotReference();
      trust.snapshot(
        text(
          await required(
            metadata,
            `${trust.consistentSnapshot ? `${snapshot.version}.` : ""}snapshot.json`,
            Math.min(snapshot.length, LIMITS.snapshot),
            request,
          ),
        ),
      );
      await checkpoint();
      const info = trust.targetsReference();
      trust.targets(
        text(
          await required(
            metadata,
            `${trust.consistentSnapshot ? `${info.version}.` : ""}targets.json`,
            Math.min(info.length, LIMITS.targets),
            request,
          ),
        ),
      );
      await checkpoint();
      const target = trust.target(targetPath);
      if (target.length > MAX_POLICY_BYTES) throw refused("policy_target");
      const path = trust.consistentSnapshot ? `${network}/${target.sha256}.fleet.json` : targetPath;
      const bytes = await required(targets, path, target.length, request);
      trust.verifyTarget(targetPath, bytes);
      const json = parseJson(bytes);
      const policy = teeFleetPolicyFromJson(json, network);
      const validUntil = Math.min(policy.expiresAt, trust.validUntil());
      if (Date.now() >= validUntil * 1000) throw refused("policy_expired");
      const hash = digest(bytes);
      if (
        policy.revision < cache.revision ||
        (policy.revision === cache.revision && hash !== cache.sha256)
      )
        throw refused("policy_rollback");
      checkAbort(request);
      cache = { ...cache, revision: policy.revision, sha256: hash };
      await checkpoint();
      checkAbort(request);
      return { policy: json, validUntil };
    } finally {
      // Preserve authenticated partial progress if a later role/target fails.
      // Caller cancellation never releases the lock ahead of this transaction.
      await checkpoint();
    }
  }

  async function required(
    base: URL,
    path: string,
    limit: number,
    request: ComposedSignal,
  ): Promise<Uint8Array> {
    const bytes = await download(base, path, limit, request, false);
    if (bytes === undefined) throw refused("policy_repository");
    return bytes;
  }

  async function download(
    base: URL,
    path: string,
    limit: number,
    request: ComposedSignal,
    rootProbe: boolean,
  ): Promise<Uint8Array | undefined> {
    checkAbort(request);
    const response = await fetch(new URL(path, base), {
      signal: request.signal,
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) {
      await response.body?.cancel();
      if (rootProbe && (response.status === 403 || response.status === 404)) return undefined;
      throw refused("policy_repository");
    }
    const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (mediaType !== "application/json") {
      await response.body?.cancel();
      throw refused("policy_content_type");
    }
    const bytes = await readBoundedBody(response, limit);
    checkAbort(request);
    return bytes;
  }
}

function checkedCache(value: unknown): Cache {
  const row = policyDecode.record(value, "source.cache");
  const files = policyDecode.record(row["files"], "source.cache.files");
  if (
    Object.keys(row).length !== 5 ||
    Object.keys(files).length !== 4 ||
    row["schemaVersion"] !== 1
  )
    throw refused("policy_storage");
  const file = (role: Role): string | null => {
    const raw = files[role];
    if (role !== "root" && raw === null) return null;
    if (typeof raw !== "string" || utf8ToBytes(raw).length > LIMITS[role])
      throw refused("policy_storage");
    // Syntax/integrity damage is never treated as a cold cache.
    uniqueJson(raw);
    return raw;
  };
  const root = file("root");
  const revision = row["revision"];
  const sha256 = row["sha256"];
  if (
    root === null ||
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    (revision === 0
      ? sha256 !== null
      : typeof sha256 !== "string" || !/^[0-9a-f]{64}$/u.test(sha256))
  )
    throw refused("policy_storage");
  const cache: Cache = {
    schemaVersion: 1,
    files: {
      root,
      timestamp: file("timestamp"),
      snapshot: file("snapshot"),
      targets: file("targets"),
    },
    revision,
    sha256: typeof sha256 === "string" ? sha256 : null,
  };
  if (row["checksum"] !== checksum(cache)) throw refused("policy_storage");
  return cache;
}

function checksum(cache: Cache): string {
  return digest(
    JSON.stringify([
      cache.schemaVersion,
      cache.files.root,
      cache.files.timestamp,
      cache.files.snapshot,
      cache.files.targets,
      cache.revision,
      cache.sha256,
    ]),
  );
}
