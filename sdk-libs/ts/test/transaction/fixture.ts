import { readFileSync } from "node:fs";

import { sha256 } from "@noble/hashes/sha2.js";

const FIXTURES = new URL("../../fixtures/", import.meta.url);
const readTextFile: (path: URL, encoding: "utf8") => string = readFileSync;

interface Manifest {
  readonly files: readonly Readonly<{ path: string; sha256: string }>[];
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseManifest(value: unknown): Manifest {
  if (typeof value !== "object" || value === null || !("files" in value)) {
    throw new Error("fixture manifest is invalid");
  }
  const files = value.files;
  if (!Array.isArray(files)) throw new Error("fixture manifest files are invalid");
  return {
    files: files.map((value: unknown) => {
      const entry =
        typeof value === "object" && value !== null
          ? (value as Readonly<Record<string, unknown>>)
          : undefined;
      if (
        entry === undefined ||
        !("path" in entry) ||
        typeof entry.path !== "string" ||
        !("sha256" in entry) ||
        typeof entry.sha256 !== "string"
      ) {
        throw new Error("fixture manifest entry is invalid");
      }
      return { path: entry.path, sha256: entry.sha256 };
    }),
  };
}

const manifest = parseManifest(
  JSON.parse(readTextFile(new URL("manifest.json", FIXTURES), "utf8")) as unknown,
);

export function readFixture<T>(path: string, parse: (value: unknown) => T): T {
  const entry = manifest.files.find((candidate) => candidate.path === path);
  if (!entry) throw new Error(`fixture ${path} is not in the manifest`);
  const text = readTextFile(new URL(path, FIXTURES), "utf8");
  const digest = hex(sha256(new TextEncoder().encode(text)));
  if (digest !== entry.sha256) throw new Error(`fixture ${path} failed manifest verification`);
  return parse(JSON.parse(text) as unknown);
}

export function fixtureObject(value: unknown, name = "fixture"): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Readonly<Record<string, unknown>>;
}

export function fixtureString(value: Readonly<Record<string, unknown>>, key: string): string {
  const field = value[key];
  if (typeof field !== "string") throw new Error(`fixture ${key} must be a string`);
  return field;
}

export function fixtureArray(
  value: Readonly<Record<string, unknown>>,
  key: string,
): readonly unknown[] {
  const field = value[key];
  if (!Array.isArray(field)) throw new Error(`fixture ${key} must be an array`);
  return field;
}

export function hexBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[\da-f]*$/iu.test(value)) {
    throw new Error("fixture contains invalid hex");
  }
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}
