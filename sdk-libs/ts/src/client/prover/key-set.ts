import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

import { isLowercaseHex, wireDecoder, type WireDecoder } from "../../interface/decode.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../../interface/program.js";
import { PROVING_KEY_SHA256S, type ExpectedProvingKey } from "../../interface/proving-keys.js";
import { isLoopbackHost } from "../../services/transport.js";

import { ClientError } from "../error.js";

/**
 * The proof-input contract of the confidential signer and merge circuits,
 * Rust `PROVING_KEY_ABI`. A release that changes a witness field, a public
 * input or a solver feature changes it, and this SDK refuses its keys.
 */
const PROVING_KEY_ABI = "spr-confidential-v1";

const MAX_DOWNLOAD_SIZE = 0xffff_ffff;
const G1_BYTES = 64;
const G2_BYTES = 128;
const SHA256_BYTES = 32;

/** One key of a `ProvingKeySet`, with the download of its zopro conversion. */
export type ProvingKeySetKey = Readonly<{
  /** The zopro file name: the key name with `.key` replaced by `.zopro`. */
  file: string;
  /** Size in bytes of the zopro download. */
  size: number;
  /** SHA-256 of the zopro download, 64 lowercase hex digits. */
  sha256: string;
  /** SHA-256 of the gnark proving key the on-chain verifying key belongs to. */
  keySha256: string;
  url: string;
}>;

const CREATE = Symbol("ProvingKeySet");
/** Every set the parser issued, with its keys; nothing else is a `ProvingKeySet`. */
const issued = new WeakMap<ProvingKeySet, ReadonlyMap<string, ProvingKeySetKey>>();
let issue: ((keys: ReadonlyMap<string, ProvingKeySetKey>) => ProvingKeySet) | undefined;

/**
 * The confidential signer and merge keys of one protocol release, read from
 * the `/proving-keys` answer of an attested prover by
 * `SprClient.fetchProvingKeySet`. Only that call creates one. Pass it as
 * `provingKeys` so every proof comes from these keys; a client holds one set
 * for its lifetime, so a rotation never mixes releases.
 */
export class ProvingKeySet {
  /** SHA-256 over the names, gnark digests and zopro downloads of the set, 64 lowercase hex digits. */
  readonly cacheKey: string;
  readonly #keys: ReadonlyMap<string, ProvingKeySetKey>;

  private constructor(token: symbol, keys: ReadonlyMap<string, ProvingKeySetKey>) {
    if (token !== CREATE) throw new ClientError("CLIENT_INVALID_CONFIG");
    this.#keys = keys;
    this.cacheKey = cacheKey(keys);
    Object.freeze(this);
  }

  /** The key `name`, such as `transfer_confidential_2_2.key`. A name outside the set throws `CLIENT_PROVING_KEY_SET`. */
  key(name: string): ProvingKeySetKey {
    const key = typeof name === "string" ? this.#keys.get(name) : undefined;
    if (key === undefined) throw refused("unsupported_circuit");
    return key;
  }

  static {
    issue = (keys) => {
      const set = new ProvingKeySet(CREATE, keys);
      issued.set(set, keys);
      return set;
    };
  }
}

/** `value` if the parser issued it, else `CLIENT_INVALID_CONFIG` naming `field`. */
export function checkedProvingKeySet(value: unknown, field: string): ProvingKeySet {
  if (typeof value !== "object" || value === null || !issued.has(value as ProvingKeySet)) {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field } });
  }
  // Only the parser adds to `issued`.
  return value as ProvingKeySet;
}

/**
 * The key of `set` a proof for `key` must come from. A circuit outside the
 * set fails: its compiled pin may belong to another release.
 */
export function expectedFromSet(set: ProvingKeySet, key: ExpectedProvingKey): ExpectedProvingKey {
  return Object.freeze({ name: key.name, sha256: set.key(key.name).keySha256 });
}

/**
 * The gnark digest of each key of `set`, by name. A prover check under a set
 * compares only these: the set refuses every other circuit, so a rotated key
 * outside it does not matter.
 */
export function setPins(set: ProvingKeySet): Readonly<Record<string, string>> {
  const keys = issued.get(set);
  if (keys === undefined) throw new ClientError("CLIENT_INVALID_CONFIG");
  return Object.freeze(Object.fromEntries([...keys].map(([name, key]) => [name, key.keySha256])));
}

/**
 * The keys a runtime set replaces: every confidential signer transfer and
 * merge key the SDK pins, as Rust `runtime_names`.
 */
function runtimeName(name: string): boolean {
  return /^transfer_confidential_\d+_\d+\.key$/u.test(name) || /^merge_\d+_1\.key$/u.test(name);
}

const RUNTIME_NAMES: readonly string[] = Object.freeze(
  Object.keys(PROVING_KEY_SHA256S).filter(runtimeName).sort(byteOrder),
);

function byteOrder(left: string, right: string): number {
  if (left < right) return -1;
  return left > right ? 1 : 0;
}

/** A refused runtime key set, `check` naming why, as Rust `ClientError::ProvingKeySet`. */
export function refused(check: string): ClientError {
  return new ClientError("CLIENT_PROVING_KEY_SET", { details: { check } });
}

const decode = wireDecoder(() => refused("malformed"));

type Artifact = Readonly<{ format: "gnark" | "zopro"; sha256: string; size: number; url: string }>;
export type CatalogKey = Readonly<{ name: string; artifacts: readonly Artifact[] }>;
type VerifyingKey = Readonly<{
  provingKeySha256: string;
  alphaG1: string;
  betaG2: string;
  gammaG2: string;
  deltaG2: string;
  ic: readonly [string, string];
}>;
type Runtime = Readonly<{
  abi: string;
  programId: string;
  verifyingKeys: ReadonlyMap<string, VerifyingKey>;
}>;

/**
 * Parse the decrypted `/proving-keys` answer of an attested prover, as Rust
 * `ProvingKeySet::from_attested_response`. The set covers every confidential
 * signer and merge key the SDK pins; verifying keys of other circuits are
 * ignored. Every refusal is `CLIENT_PROVING_KEY_SET`.
 */
export function provingKeySetFromCatalog(value: unknown): ProvingKeySet {
  const body = decode.record(value, "$");
  const keys = decode
    .list(body["keys"], "$.keys")
    .map((key) => decodeCatalogKey(key, decode, () => refused("malformed")));
  const rawRuntime = body["runtime"];
  const runtime =
    rawRuntime === undefined || rawRuntime === null ? undefined : runtimeBlock(rawRuntime);
  if (runtime === undefined) throw refused("runtime_missing");
  if (runtime.abi !== PROVING_KEY_ABI || runtime.programId !== SHIELDED_POOL_PROGRAM_ID) {
    throw refused("incompatible");
  }
  const set = new Map<string, ProvingKeySetKey>();
  for (const name of RUNTIME_NAMES) {
    const verifier = runtime.verifyingKeys.get(name);
    if (verifier === undefined) throw refused("incompatible");
    const entry = only(keys.filter((key) => key.name === name));
    const gnark = only(entry.artifacts.filter((artifact) => artifact.format === "gnark"));
    const zopro = only(entry.artifacts.filter((artifact) => artifact.format === "zopro"));
    if (gnark.sha256 !== verifier.provingKeySha256) throw refused("source_mismatch");
    checkDownload(zopro);
    for (const [point, length] of [
      [verifier.provingKeySha256, SHA256_BYTES],
      [verifier.alphaG1, G1_BYTES],
      [verifier.betaG2, G2_BYTES],
      [verifier.gammaG2, G2_BYTES],
      [verifier.deltaG2, G2_BYTES],
      [verifier.ic[0], G1_BYTES],
      [verifier.ic[1], G1_BYTES],
    ] as const) {
      lowercaseHex(point, length);
    }
    set.set(
      name,
      Object.freeze({
        file: name.replace(/\.key$/u, ".zopro"),
        size: zopro.size,
        sha256: zopro.sha256,
        keySha256: verifier.provingKeySha256,
        url: zopro.url,
      }),
    );
  }
  if (issue === undefined) throw new ClientError("CLIENT_UNEXPECTED");
  return issue(set);
}

/** The lowercase hex SHA-256 of the JSON rows `[name, keySha256, zoproSha256, zoproSize]`, by name. */
function cacheKey(keys: ReadonlyMap<string, ProvingKeySetKey>): string {
  const rows = [...keys.keys()].sort(byteOrder).map((name) => {
    const key = keys.get(name);
    if (key === undefined) throw refused("malformed");
    return [name, key.keySha256, key.sha256, key.size];
  });
  return bytesToHex(sha256(utf8ToBytes(JSON.stringify(rows))));
}

/**
 * One `keys[]` entry of a `/proving-keys` answer, its downloads with the
 * metadata the prover supplied. `decode` and `fail` raise the caller's error.
 */
export function decodeCatalogKey(
  raw: unknown,
  decoder: WireDecoder,
  fail: () => Error,
): CatalogKey {
  const entry = decoder.record(raw, "$.keys[]");
  return Object.freeze({
    name: decoder.string(entry["name"], "$.keys[].name"),
    artifacts: Object.freeze(
      decoder
        .list(entry["artifacts"], "$.keys[].artifacts")
        .map((artifact) => decodeArtifact(artifact, decoder, fail)),
    ),
  });
}

function decodeArtifact(raw: unknown, decoder: WireDecoder, fail: () => Error): Artifact {
  const value = decoder.record(raw, "$.keys[].artifacts[]");
  const format = value["format"];
  const size = value["size"];
  if (format !== "gnark" && format !== "zopro") throw fail();
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) throw fail();
  return Object.freeze({
    format,
    sha256: decoder.string(value["sha256"], "$.keys[].artifacts[].sha256"),
    size,
    url: decoder.string(value["url"], "$.keys[].artifacts[].url"),
  });
}

const RUNTIME_FIELDS = ["abi", "programId", "verifyingKeys"] as const;
const VERIFYING_KEY_FIELDS = [
  "provingKeySha256",
  "alphaG1",
  "betaG2",
  "gammaG2",
  "deltaG2",
  "ic",
] as const;

/** The `runtime` block, every field present and none unknown, as Rust `deny_unknown_fields`. */
function runtimeBlock(raw: unknown): Runtime {
  const value = decode.exactRecord(raw, "runtime", RUNTIME_FIELDS);
  const verifyingKeys = new Map<string, VerifyingKey>();
  for (const [name, entry] of Object.entries(decode.record(value["verifyingKeys"], "keys"))) {
    verifyingKeys.set(name, verifyingKey(entry));
  }
  return Object.freeze({
    abi: decode.string(value["abi"], "abi"),
    programId: decode.string(value["programId"], "programId"),
    verifyingKeys,
  });
}

function verifyingKey(raw: unknown): VerifyingKey {
  const value = decode.exactRecord(raw, "runtime", VERIFYING_KEY_FIELDS);
  const ic = decode.list(value["ic"], "ic");
  if (ic.length !== 2) throw refused("malformed");
  return Object.freeze({
    provingKeySha256: decode.string(value["provingKeySha256"], "provingKeySha256"),
    alphaG1: decode.string(value["alphaG1"], "alphaG1"),
    betaG2: decode.string(value["betaG2"], "betaG2"),
    gammaG2: decode.string(value["gammaG2"], "gammaG2"),
    deltaG2: decode.string(value["deltaG2"], "deltaG2"),
    ic: Object.freeze([decode.string(ic[0], "ic"), decode.string(ic[1], "ic")] as const),
  });
}

function only<T>(items: readonly T[]): T {
  const [item] = items;
  if (item === undefined || items.length !== 1) throw refused("malformed");
  return item;
}

/** A download the prover fetches and checks against `sha256` and `size`. */
function checkDownload(artifact: Artifact): void {
  lowercaseHex(artifact.sha256, SHA256_BYTES);
  let url: URL;
  try {
    url = new URL(artifact.url);
  } catch {
    throw refused("malformed");
  }
  const transport =
    url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHost(url.hostname));
  if (
    artifact.size < 1 ||
    artifact.size > MAX_DOWNLOAD_SIZE ||
    !transport ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    url.href.endsWith("#")
  ) {
    throw refused("malformed");
  }
}

/** Exactly `bytes` bytes of lowercase hex. */
function lowercaseHex(value: string, bytes: number): void {
  if (!isLowercaseHex(value, bytes)) throw refused("malformed");
}
