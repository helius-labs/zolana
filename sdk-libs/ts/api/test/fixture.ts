import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const FIXTURES = new URL("../../fixtures/", import.meta.url);
const FIXTURE_PATH = "api/transport-v1.json";
const FIXTURE_SCHEMA = "zolana-ts-fixtures-v1";

export type TransportCaseName =
  | "encrypted-utxos"
  | "shielded-transactions"
  | "merkle-proofs"
  | "non-inclusion-proofs"
  | "nullifier-queue-default"
  | "nullifier-queue-explicit";

export type JsonValue =
  boolean | number | string | null | readonly JsonValue[] | Readonly<{ [key: string]: JsonValue }>;

export interface SemanticRequest {
  readonly body: Readonly<{ [key: string]: JsonValue }>;
  readonly contentType: string;
  readonly method: string;
  readonly path: string;
  readonly query: string;
}

export interface TransportSuccess {
  readonly case: TransportCaseName;
  readonly request: SemanticRequest;
  readonly response: Readonly<{ [key: string]: JsonValue }>;
}

interface RustError {
  readonly body?: string;
  readonly code?: number;
  readonly field?: string;
  readonly kind: string;
  readonly message?: string;
  readonly method?: string;
  readonly status?: number;
}

interface ErrorExchange {
  readonly error: RustError;
  readonly request: SemanticRequest;
}

export interface TransportFixture {
  readonly expected: {
    readonly errors: {
      readonly http: ErrorExchange;
      readonly invalidOptionalLimit: RustError;
      readonly invalidRequiredLimit: RustError;
      readonly jsonRpc: ErrorExchange;
      readonly missingResult: ErrorExchange;
    };
    readonly successes: readonly TransportSuccess[];
  };
  readonly inputs: {
    readonly cursor: string;
    readonly explicitStartSeq: string;
    readonly leaf: string;
    readonly optionalLimit: string;
    readonly queueExplicitLimit: string;
    readonly queueLimit: string;
    readonly tag: string;
    readonly treeAccount: string;
  };
}

interface Manifest {
  readonly files: readonly Readonly<{ path: string; sha256: string }>[];
  readonly frozenCommit: string;
  readonly schema: string;
  readonly version: string;
}

function object(value: unknown, name: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Readonly<Record<string, unknown>>;
}

function string(value: unknown, name: string): string {
  if (typeof value !== "string") throw new Error(`${name} must be a string`);
  return value;
}

function integer(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${name} must be an integer`);
  }
  return value;
}

function array(value: unknown, name: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  return value;
}

function jsonValue(value: unknown, name: string): JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => jsonValue(entry, name));
  const record = object(value, name);
  return Object.fromEntries(
    Object.entries(record).map(([key, entry]) => [key, jsonValue(entry, `${name}.${key}`)]),
  );
}

function semanticRequest(value: unknown, name: string): SemanticRequest {
  const record = object(value, name);
  return {
    body: object(jsonValue(record["body"], `${name}.body`), `${name}.body`) as Readonly<{
      [key: string]: JsonValue;
    }>,
    contentType: string(record["contentType"], `${name}.contentType`),
    method: string(record["method"], `${name}.method`),
    path: string(record["path"], `${name}.path`),
    query: string(record["query"], `${name}.query`),
  };
}

function rustError(value: unknown, name: string): RustError {
  const record = object(value, name);
  return {
    ...(record["body"] === undefined ? {} : { body: string(record["body"], `${name}.body`) }),
    ...(record["code"] === undefined ? {} : { code: integer(record["code"], `${name}.code`) }),
    ...(record["field"] === undefined ? {} : { field: string(record["field"], `${name}.field`) }),
    kind: string(record["kind"], `${name}.kind`),
    ...(record["message"] === undefined
      ? {}
      : { message: string(record["message"], `${name}.message`) }),
    ...(record["method"] === undefined
      ? {}
      : { method: string(record["method"], `${name}.method`) }),
    ...(record["status"] === undefined
      ? {}
      : { status: integer(record["status"], `${name}.status`) }),
  };
}

function errorExchange(value: unknown, name: string): ErrorExchange {
  const record = object(value, name);
  return {
    error: rustError(record["error"], `${name}.error`),
    request: semanticRequest(record["request"], `${name}.request`),
  };
}

function caseName(value: unknown): TransportCaseName {
  const name = string(value, "fixture success case");
  if (
    name !== "encrypted-utxos" &&
    name !== "shielded-transactions" &&
    name !== "merkle-proofs" &&
    name !== "non-inclusion-proofs" &&
    name !== "nullifier-queue-default" &&
    name !== "nullifier-queue-explicit"
  ) {
    throw new Error(`unknown fixture success case: ${name}`);
  }
  return name;
}

function transportFixture(value: unknown, frozenCommit: string): TransportFixture {
  const fixture = object(value, "fixture");
  if (
    fixture["schema"] !== FIXTURE_SCHEMA ||
    fixture["version"] !== "1" ||
    fixture["id"] !== "fx-p00-api-transport-v1"
  ) {
    throw new Error("transport fixture provenance is invalid");
  }
  if (fixture["sourceRevision"] !== frozenCommit) {
    throw new Error("transport fixture source revision does not match the manifest");
  }
  const inputs = object(fixture["inputs"], "fixture.inputs");
  const expected = object(fixture["expected"], "fixture.expected");
  const errors = object(expected["errors"], "fixture.expected.errors");
  const successes = array(expected["successes"], "fixture.expected.successes").map(
    (value, index): TransportSuccess => {
      const position = String(index);
      const success = object(value, `fixture.expected.successes[${position}]`);
      return {
        case: caseName(success["case"]),
        request: semanticRequest(
          success["request"],
          `fixture.expected.successes[${position}].request`,
        ),
        response: object(
          jsonValue(success["response"], `fixture.expected.successes[${position}].response`),
          `fixture.expected.successes[${position}].response`,
        ) as Readonly<{ [key: string]: JsonValue }>,
      };
    },
  );
  if (successes.length !== 6 || new Set(successes.map((success) => success.case)).size !== 6) {
    throw new Error("transport fixture success cases are incomplete");
  }
  return {
    expected: {
      errors: {
        http: errorExchange(errors["http"], "fixture.expected.errors.http"),
        invalidOptionalLimit: rustError(
          errors["invalidOptionalLimit"],
          "fixture.expected.errors.invalidOptionalLimit",
        ),
        invalidRequiredLimit: rustError(
          errors["invalidRequiredLimit"],
          "fixture.expected.errors.invalidRequiredLimit",
        ),
        jsonRpc: errorExchange(errors["jsonRpc"], "fixture.expected.errors.jsonRpc"),
        missingResult: errorExchange(
          errors["missingResult"],
          "fixture.expected.errors.missingResult",
        ),
      },
      successes,
    },
    inputs: {
      cursor: string(inputs["cursor"], "fixture.inputs.cursor"),
      explicitStartSeq: string(inputs["explicitStartSeq"], "fixture.inputs.explicitStartSeq"),
      leaf: string(inputs["leaf"], "fixture.inputs.leaf"),
      optionalLimit: string(inputs["optionalLimit"], "fixture.inputs.optionalLimit"),
      queueExplicitLimit: string(inputs["queueExplicitLimit"], "fixture.inputs.queueExplicitLimit"),
      queueLimit: string(inputs["queueLimit"], "fixture.inputs.queueLimit"),
      tag: string(inputs["tag"], "fixture.inputs.tag"),
      treeAccount: string(inputs["treeAccount"], "fixture.inputs.treeAccount"),
    },
  };
}

function manifest(value: unknown): Manifest {
  const record = object(value, "fixture manifest");
  if (record["schema"] !== FIXTURE_SCHEMA || record["version"] !== "1") {
    throw new Error("fixture manifest provenance is invalid");
  }
  const frozenCommit = string(record["frozenCommit"], "fixture manifest frozenCommit");
  if (!/^[\da-f]{40}$/u.test(frozenCommit)) {
    throw new Error("fixture manifest frozenCommit is invalid");
  }
  return {
    files: array(record["files"], "fixture manifest files").map((value, index) => {
      const position = String(index);
      const entry = object(value, `fixture manifest files[${position}]`);
      const path = string(entry["path"], `fixture manifest files[${position}].path`);
      const sha256 = string(entry["sha256"], `fixture manifest files[${position}].sha256`);
      if (!/^[\da-f]{64}$/u.test(sha256)) {
        throw new Error(`fixture manifest hash is invalid: ${path}`);
      }
      return { path, sha256 };
    }),
    frozenCommit,
    schema: FIXTURE_SCHEMA,
    version: "1",
  };
}

function readText(url: URL): string {
  return readFileSync(url, "utf8");
}

export function loadTransportFixture(): TransportFixture {
  const parsedManifest = manifest(
    JSON.parse(readText(new URL("manifest.json", FIXTURES))) as unknown,
  );
  const entry = parsedManifest.files.find((candidate) => candidate.path === FIXTURE_PATH);
  if (entry === undefined) throw new Error("transport fixture is missing from the manifest");
  const text = readText(new URL(FIXTURE_PATH, FIXTURES));
  const digest = createHash("sha256").update(text).digest("hex");
  if (digest !== entry.sha256)
    throw new Error("transport fixture hash does not match the manifest");
  return transportFixture(JSON.parse(text) as unknown, parsedManifest.frozenCommit);
}
