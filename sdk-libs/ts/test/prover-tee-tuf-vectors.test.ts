import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, test } from "vitest";

import vector from "../../../test-vectors/tee_tuf_repository.json" with { type: "json" };
import { tufTeePolicy } from "../src/client/prover/tee/tuf-node.js";

type Case = keyof typeof vector.repositories;
const directories = new Set<string>();

afterEach(async () => {
  await Promise.all(
    Array.from(directories, (directory) => rm(directory, { recursive: true, force: true })),
  );
  directories.clear();
});

async function repository(initial: Case) {
  const cacheDirectory = await mkdtemp(join(tmpdir(), "zolana-tuf-vectors-"));
  directories.add(cacheDirectory);
  let current = initial;
  const fetch: typeof globalThis.fetch = async (input) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    const files: Readonly<Record<string, string>> = vector.repositories[current];
    const body = files[url.pathname.slice(1)];
    return body === undefined
      ? new Response(null, { status: 404 })
      : new Response(body, { headers: { "content-type": "application/json" } });
  };
  return {
    select: (next: Case) => {
      current = next;
    },
    source: () =>
      tufTeePolicy({
        network: vector.network,
        rootJson: vector.bootstrap_root,
        metadataUrl: "https://policy.test/metadata/",
        targetsUrl: "https://policy.test/targets/",
        cacheDirectory,
        fetch,
      }),
  };
}

test.each(["v1", "v2", "rotated", "fractional"] as const)(
  "accepts shared Rust/Node signed repository %s",
  async (name) => {
    const repo = await repository(name);
    const policy = await repo.source().resolve();
    expect(policy.revision).toBe(name === "v2" || name === "rotated" ? 2 : 1);
    expect(policy.deployments).toHaveLength(3);
    if (name === "fractional") expect(policy.expiresAt).toBe(vector.fractional_valid_until);
  },
);

test.each([
  "bad_signature",
  "hash_mismatch",
  "weak_hash",
  "expired",
  "rotation_old_only",
  "rotation_new_only",
] as const)("rejects shared Rust/Node signed repository %s", async (name) => {
  const repo = await repository(name);
  await expect(repo.source().resolve()).rejects.toMatchObject({
    code: "CLIENT_PROVER_TEE_ATTESTATION",
  });
});

test("shared vectors preserve policy revision floors across new client instances", async () => {
  const repo = await repository("v2");
  await repo.source().resolve();
  repo.select("rollback");
  await expect(repo.source().resolve()).rejects.toMatchObject({
    code: "CLIENT_PROVER_TEE_ATTESTATION",
  });
  repo.select("v1");
  await expect(repo.source().resolve()).rejects.toMatchObject({
    code: "CLIENT_PROVER_TEE_ATTESTATION",
  });
});

test("shared vectors reject changed bytes under an accepted policy revision", async () => {
  const repo = await repository("v1");
  await repo.source().resolve();
  repo.select("substitution");
  await expect(repo.source().resolve()).rejects.toMatchObject({
    code: "CLIENT_PROVER_TEE_ATTESTATION",
  });
});
