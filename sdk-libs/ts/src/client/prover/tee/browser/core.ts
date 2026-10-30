import { TrustedMetadataStore } from "tuf-js/dist/store.js";
import { BadVersionError, EqualVersionError, ExpiredMetadataError } from "tuf-js/dist/error.js";
import { MetaFile } from "@tufjs/models";
import { wireDecoder } from "../../../../interface/decode.js";
import { uniqueJson } from "./json.js";

export type Role = "root" | "timestamp" | "snapshot" | "targets";
export type MetadataFiles = {
  root: string;
  timestamp: string | null;
  snapshot: string | null;
  targets: string | null;
};
export type FileReference = Readonly<{ version: number; length: number; sha256: string }>;
const roles: readonly Role[] = ["root", "timestamp", "snapshot", "targets"];
const decode = wireDecoder(() => new Error("unsupported TUF policy metadata"));

function positive(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
    throw new Error("invalid metadata integer");
  return value;
}

function hash(value: unknown): string {
  const hashes = decode.record(value, "hashes");
  const digest = hashes["sha256"];
  if (
    Object.keys(hashes).length !== 1 ||
    typeof digest !== "string" ||
    !/^[0-9a-f]{64}$/u.test(digest)
  ) {
    throw new Error("policy repositories require SHA-256");
  }
  return digest;
}

function reference(value: unknown): FileReference {
  const info = decode.record(value, "file");
  return {
    version: positive(info["version"]),
    length: positive(info["length"]),
    sha256: hash(info["hashes"]),
  };
}

/** Restrict the browser port to the publisher's top-level Ed25519/SHA-256 profile. */
function metadata(text: string, role: Role): void {
  const raw = decode.record(uniqueJson(text), "metadata");
  const signed = decode.record(raw["signed"], "signed");
  if (
    signed["_type"] !== role ||
    !/^1\.\d+\.\d+$/u.test(decode.string(signed["spec_version"], "spec_version"))
  ) {
    throw new Error("unsupported metadata type or version");
  }
  positive(signed["version"]);
  const expires = decode.string(signed["expires"], "expires");
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(expires) ||
    !Number.isSafeInteger(Date.parse(expires)) ||
    new Date(Date.parse(expires)).toISOString().slice(0, 19) !== expires.slice(0, 19)
  ) {
    throw new Error("invalid metadata expiry");
  }
  const signatures = decode.list(raw["signatures"], "signatures");
  const seen = new Set<string>();
  for (const item of signatures) {
    const sig = decode.record(item, "signature");
    const id = decode.string(sig["keyid"], "keyid");
    if (
      !/^[0-9a-f]{64}$/u.test(id) ||
      !/^[0-9a-f]{128}$/u.test(decode.string(sig["sig"], "sig")) ||
      seen.has(id)
    ) {
      throw new Error("invalid signature encoding");
    }
    seen.add(id);
  }
  if (role === "root") {
    const keys = decode.record(signed["keys"], "keys");
    for (const [id, item] of Object.entries(keys)) {
      const key = decode.record(item, "key");
      const keyval = decode.record(key["keyval"], "keyval");
      if (
        !/^[0-9a-f]{64}$/u.test(id) ||
        key["keytype"] !== "ed25519" ||
        key["scheme"] !== "ed25519" ||
        Object.keys(keyval).length !== 1 ||
        !/^[0-9a-f]{64}$/u.test(decode.string(keyval["public"], "public"))
      ) {
        throw new Error("policy repositories require Ed25519");
      }
    }
    const definitions = decode.record(signed["roles"], "roles");
    if (
      Object.keys(definitions).length !== roles.length ||
      typeof signed["consistent_snapshot"] !== "boolean"
    )
      throw new Error("unsupported root");
    for (const name of roles) {
      const definition = decode.record(definitions[name], "role");
      const ids = decode
        .list(definition["keyids"], "keyids")
        .map((id) => decode.string(id, "keyid"));
      if (
        positive(definition["threshold"]) > new Set(ids).size ||
        new Set(ids).size !== ids.length ||
        ids.some((id) => !Object.hasOwn(keys, id))
      )
        throw new Error("invalid role threshold");
    }
  } else if (role === "timestamp" || role === "snapshot") {
    const entries = decode.record(signed["meta"], "meta");
    const expected = role === "timestamp" ? "snapshot.json" : "targets.json";
    if (Object.keys(entries).length !== 1 || !Object.hasOwn(entries, expected))
      throw new Error("unsupported delegated metadata");
    reference(entries[expected]);
  } else {
    if (Object.hasOwn(signed, "delegations"))
      throw new Error("delegations are outside the policy profile");
    for (const item of Object.values(decode.record(signed["targets"], "targets"))) {
      const target = decode.record(item, "target");
      positive(target["length"]);
      hash(target["hashes"]);
    }
  }
}

/** Private bundle boundary: no Node/model types escape into the SDK declarations. */
export class BrowserTrust {
  readonly #store: TrustedMetadataStore;
  readonly #files: MetadataFiles;

  constructor(files: MetadataFiles) {
    metadata(files.root, "root");
    this.#store = new TrustedMetadataStore(Buffer.from(files.root));
    this.#files = { ...files };
  }

  get files(): MetadataFiles {
    return { ...this.#files };
  }
  get rootVersion(): number {
    return this.#store.root.signed.version;
  }
  get consistentSnapshot(): boolean {
    return this.#store.root.signed.consistentSnapshot;
  }

  #onlineKeys(): string {
    return JSON.stringify(
      ["timestamp", "snapshot"].map((name) => {
        const role = this.#store.root.signed.roles[name];
        if (role === undefined) throw new Error("missing online role");
        return [
          role.threshold,
          [...role.keyIDs].sort().map((id) => {
            const key = this.#store.root.signed.keys[id];
            if (key === undefined) throw new Error("missing online key");
            return [id, key.keyType, key.scheme, key.keyVal];
          }),
        ];
      }),
    );
  }

  root(text: string): void {
    metadata(text, "root");
    const keys = this.#onlineKeys();
    this.#store.updateRoot(Buffer.from(text));
    this.#files.root = text;
    // TUF 5.3.11: root-authorized online-key rotation resets compromised
    // timestamp/snapshot fast-forward floors, never the semantic fleet floor.
    if (keys !== this.#onlineKeys()) {
      this.#files.timestamp = null;
      this.#files.snapshot = null;
      this.#files.targets = null;
    }
  }

  timestamp(text: string): void {
    metadata(text, "timestamp");
    const before = this.#store.timestamp;
    try {
      this.#store.updateTimestamp(Buffer.from(text));
    } catch (error) {
      if (!(error instanceof EqualVersionError)) throw error;
    } finally {
      if (this.#store.timestamp !== before) this.#files.timestamp = text;
    }
  }

  restoreTimestamp(): void {
    if (this.#files.timestamp === null) return;
    try {
      this.timestamp(this.#files.timestamp);
    } catch (error) {
      if (!(error instanceof ExpiredMetadataError) || this.#store.timestamp === undefined)
        throw error;
    }
  }

  restoreSnapshot(): void {
    if (this.#files.snapshot === null) return;
    metadata(this.#files.snapshot, "snapshot");
    try {
      this.#store.updateSnapshot(Buffer.from(this.#files.snapshot), true);
    } catch (error) {
      if (
        !(error instanceof BadVersionError || error instanceof ExpiredMetadataError) ||
        this.#store.snapshot === undefined
      )
        throw error;
    }
  }

  snapshot(text: string): void {
    metadata(text, "snapshot");
    const before = this.#store.snapshot;
    try {
      this.#store.updateSnapshot(Buffer.from(text));
    } finally {
      if (this.#store.snapshot !== before) this.#files.snapshot = text;
    }
  }

  targets(text: string): void {
    metadata(text, "targets");
    this.#store.updateDelegatedTargets(Buffer.from(text), "targets", "root");
    this.#files.targets = text;
  }

  snapshotReference(): FileReference {
    const info = this.#store.timestamp?.signed.snapshotMeta;
    if (info === undefined) throw new Error("missing timestamp");
    return reference(info.toJSON());
  }

  targetsReference(): FileReference {
    const info = this.#store.snapshot?.signed.meta["targets.json"];
    if (info === undefined) throw new Error("missing snapshot");
    return reference(info.toJSON());
  }

  target(path: string): Readonly<{ length: number; sha256: string }> {
    const info = this.#store.targets?.signed.targets[path];
    if (info === undefined) throw new Error("missing policy target");
    return { length: positive(info.length), sha256: hash(info.hashes) };
  }

  verifyTarget(path: string, bytes: Uint8Array): void {
    const info = this.target(path);
    new MetaFile({ version: 1, length: info.length, hashes: { sha256: info.sha256 } }).verify(
      Buffer.from(bytes),
    );
  }

  validUntil(): number {
    const files = [
      this.#store.root,
      this.#store.timestamp,
      this.#store.snapshot,
      this.#store.targets,
    ];
    return Math.min(
      ...files.map((file) => {
        if (file === undefined) throw new Error("incomplete trusted metadata");
        return Math.floor(Date.parse(file.signed.expires) / 1000);
      }),
    );
  }
}
