import { createHash, createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import {
  Key,
  Metadata,
  MetaFile,
  Root,
  Signature,
  Snapshot,
  TargetFile,
  Targets,
  Timestamp,
} from "@tufjs/models";
import vector from "../../../../test-vectors/tee_fleet_policy.json" with { type: "json" };

type TestKey = Readonly<{ public: Key; secret: KeyObject }>;
const NOW = Math.floor(Date.now() / 1000);

/** Deterministic test keys only; no fixture key is a production trust anchor. */
function key(seed: number): TestKey {
  const secret = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, seed),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const raw = createPublicKey(secret).export({ format: "der", type: "spki" }).subarray(-32);
  return {
    public: new Key({
      keyID: hash(raw),
      keyType: "ed25519",
      scheme: "ed25519",
      keyVal: { public: raw.toString("hex") },
    }),
    secret,
  };
}

const OLD = { root: key(1), targets: key(2), snapshot: key(3), timestamp: key(4) };
const NEW = { root: key(5), targets: key(6), snapshot: key(7), timestamp: key(8) };

function root(version: number, keys: typeof OLD): Root {
  const root = new Root(common(version, NOW + 7200));
  for (const [role, key] of Object.entries(keys)) root.addKey(key.public, role);
  return root;
}

function common(version: number, expires: number) {
  return { version, expires: new Date(expires * 1000).toISOString(), specVersion: "1.0.31" };
}

function envelope<T extends Root | Targets | Snapshot | Timestamp>(
  signed: T,
  ...keys: TestKey[]
): Buffer {
  const metadata = new Metadata(signed);
  for (const key of keys) {
    metadata.sign(
      (bytes) =>
        new Signature({
          keyID: key.public.keyID,
          sig: sign(null, bytes, key.secret).toString("hex"),
        }),
    );
  }
  return Buffer.from(JSON.stringify(metadata.toJSON()));
}

function meta(version: number, bytes: Buffer): MetaFile {
  return new MetaFile({ version, length: bytes.length, hashes: { sha256: hash(bytes) } });
}

export function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function tufRepository(
  options: Readonly<{
    revision?: number;
    metadataVersion?: number;
    rotatedRoot?: boolean;
    timestampExpires?: number;
    policy?: unknown;
    policyJson?: string;
    targetHashAlgorithm?: "sha256" | "sha512" | "md5" | "none";
  }> = {},
) {
  const revision = options.revision ?? 1;
  const version = options.metadataVersion ?? revision;
  const keys = options.rotatedRoot === true ? NEW : OLD;
  const rootJson = envelope(root(1, OLD), OLD.root).toString("utf8");
  const policy = options.policy ?? { ...vector.policy, revision };
  const payload = Buffer.from(options.policyJson ?? JSON.stringify(policy));
  const algorithm = options.targetHashAlgorithm ?? "sha256";
  const hashes =
    algorithm === "none"
      ? {}
      : { [algorithm]: createHash(algorithm).update(payload).digest("hex") };
  const target = new TargetFile({
    path: "fixture/fleet.json",
    length: payload.length,
    hashes,
  });
  const targets = envelope(
    new Targets({ ...common(version, NOW + 3600), targets: { [target.path]: target } }),
    keys.targets,
  );
  const snapshot = envelope(
    new Snapshot({
      ...common(version, NOW + 3600),
      meta: { "targets.json": meta(version, targets) },
    }),
    keys.snapshot,
  );
  const timestampExpires = options.timestampExpires ?? NOW + 1800;
  const timestamp = envelope(
    new Timestamp({ ...common(version, timestampExpires), snapshotMeta: meta(version, snapshot) }),
    keys.timestamp,
  );
  const targetUrl = `/targets/fixture/${Object.values(hashes)[0]}.fleet.json`;
  const files = new Map<string, Buffer>([
    ["/metadata/timestamp.json", timestamp],
    [`/metadata/${version}.snapshot.json`, snapshot],
    [`/metadata/${version}.targets.json`, targets],
    [targetUrl, payload],
  ]);
  if (options.rotatedRoot === true)
    files.set("/metadata/2.root.json", envelope(root(2, NEW), OLD.root, NEW.root));
  return { rootJson, files, targetUrl, timestampExpires, policy };
}
