/// <reference types="node" />

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { TestKitError } from "../error.js";
import { FIXTURES_ROOT } from "../paths.js";

interface FixtureManifest {
  readonly frozenCommit: string;
  readonly files: readonly Readonly<{ path: string; sha256: string }>[];
}

function fixturePath(name: string): string {
  const normalized = name.endsWith(".json") ? name : `${name}.json`;
  if (
    normalized.startsWith("/") ||
    normalized.includes("\\") ||
    normalized.split("/").includes("..")
  ) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "invalidName" },
    });
  }
  return normalized;
}

async function manifest(): Promise<FixtureManifest> {
  try {
    return JSON.parse(
      await readFile(path.join(FIXTURES_ROOT, "manifest.json"), "utf8"),
    ) as FixtureManifest;
  } catch (cause) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "manifest" },
      cause: safeCause(cause),
    });
  }
}

export async function fixtureBytes(name: string): Promise<Uint8Array> {
  const relativePath = fixturePath(name);
  const entry = (await manifest()).files.find((candidate) => candidate.path === relativePath);
  if (entry === undefined) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "unlisted", path: relativePath },
    });
  }

  let bytes: Uint8Array;
  try {
    bytes = await readFile(path.join(FIXTURES_ROOT, relativePath));
  } catch (cause) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "read", path: relativePath },
      cause: safeCause(cause),
    });
  }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== entry.sha256) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "hash", path: relativePath, expected: entry.sha256, actual },
    });
  }
  return new Uint8Array(bytes);
}

export async function fixtureJson<T>(name: string): Promise<T> {
  try {
    return JSON.parse(new TextDecoder().decode(await fixtureBytes(name))) as T;
  } catch (cause) {
    if (cause instanceof TestKitError) throw cause;
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "json" },
      cause: safeCause(cause),
    });
  }
}

function safeCause(cause: unknown): unknown {
  if (cause instanceof Error) return Object.freeze({ name: cause.name });
  return undefined;
}
