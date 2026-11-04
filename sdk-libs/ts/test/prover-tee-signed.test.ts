import { readFileSync } from "node:fs";

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProverClient } from "../src/client/prover/client.js";
import {
  NETWORKS,
  SignedTeePolicy,
  verifySignedTeePolicy,
  type TeeNetwork,
} from "../src/client/prover/tee/signed.js";
import { wireDecoder } from "../src/interface/decode.js";

const json = (path: string): unknown =>
  JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const testdata = (file: string): Record<string, unknown> =>
  decode.record(json(`../../../prover/tee/testdata/${file}`), file);

const vectors = testdata("signed_policy.json");
const vectorSigners = {
  network: decode.string(vectors["network"], "network"),
  keys: decode.list(vectors["public_keys"], "keys").map((key) => decode.string(key, "key")),
  threshold: Number(vectors["threshold"]),
};

describe("signed policy vectors", () => {
  it("use the clock skew the SDK allows", () => {
    expect(vectors["max_clock_skew_secs"]).toBe(86_400);
  });

  it.each(decode.list(vectors["cases"], "cases").map((item) => decode.record(item, "case")))(
    "$name",
    (vector) => {
      const verify = () =>
        verifySignedTeePolicy(vector["file"], vectorSigners, Number(vectors["now"]));
      if (vector["error"] === undefined) {
        const verified = verify();
        expect(verified.version).toBe(vector["version"]);
        expect(verified.expiresAt).toBe(vector["expires_at"]);
      } else {
        expect(verify).toThrow(
          expect.objectContaining({ details: { check: `policy_${String(vector["error"])}` } }),
        );
      }
    },
  );
});

/** `payload` signed under `domain` with the test keys of `seeds`. */
function part(domain: string, payload: Uint8Array, seeds: readonly number[]) {
  const message = concatBytes(utf8ToBytes(domain), payload);
  return {
    payload: bytesToHex(payload),
    signatures: seeds.map((seed) => {
      const key = new Uint8Array(32).fill(seed);
      return {
        public_key: bytesToHex(ed25519.getPublicKey(key)),
        signature: bytesToHex(ed25519.sign(message, key)),
      };
    }),
  };
}

/**
 * The Nitro fixture's policy as `version`, released by the test keys of `seeds`
 * until `expiresAt` and kept fresh by the key of seed 5, which the release names,
 * from `issuedAt` to `freshUntil`.
 */
function file(
  version: number,
  seeds: readonly number[],
  expiresAt = capturedAt + 3600,
  { issuedAt = capturedAt - 60, freshUntil = capturedAt + 3600 } = {},
): unknown {
  const release = utf8ToBytes(
    JSON.stringify({
      network: "fixture",
      version,
      expires_at: expiresAt,
      freshness: { public_keys: [publicKey(5)], threshold: 1, max_lifetime_secs: 3 * 86_400 },
      policy: { ...policy, max_age_secs: 300 },
    }),
  );
  const freshness = utf8ToBytes(
    JSON.stringify({
      network: "fixture",
      release_version: version,
      release_sha256: bytesToHex(sha256(release)),
      issued_at: issuedAt,
      expires_at: freshUntil,
    }),
  );
  return {
    release: part("zolana/prover-tee/v2/release", release, seeds),
    freshness: part("zolana/prover-tee/v2/freshness", freshness, [5]),
  };
}

const live = testdata("nitro_live_attestation.json");
const policy = decode.record(testdata("nitro_live_policy.json")["deployment"], "deployment");
const capturedAt = Number(decode.integer(live["captured_at"], "captured_at"));
const publicKey = (seed: number) => bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(seed)));
const publicKeys = [1, 2, 3].map(publicKey);
const signers = { publicKeys, threshold: 2 };

describe("the networks the SDK pins", () => {
  it("match the Rust client's signers.json", () => {
    const networks = decode.record(json("../../client/src/prover/tee/signers.json"), "signers");
    expect(NETWORKS).toEqual(
      Object.fromEntries(
        Object.entries(networks).map(([network, entry]) => {
          const pinned = decode.record(entry, network);
          return [
            network,
            {
              url: pinned["url"],
              publicKeys: pinned["public_keys"],
              threshold: pinned["threshold"],
            },
          ];
        }),
      ),
    );
    expect(() => SignedTeePolicy.forNetwork("mainnet")).not.toThrow();
    expect(() => SignedTeePolicy.forNetwork("devnet")).not.toThrow();
  });

  it("refuses a network it does not pin", () => {
    expect(() => SignedTeePolicy.forNetwork("nowhere" as TeeNetwork)).toThrow(
      expect.objectContaining({ details: { field: "tee.network" } }),
    );
  });
});

describe("a prover client under a signed policy", () => {
  afterEach(() => vi.restoreAllMocks());

  /**
   * Serves `files` in turn at /policy.json and records every path asked for.
   * The clock moves to `answeredAt` when the attestation is asked.
   */
  function client(
    files: (() => Response | Promise<Response>)[],
    answeredAt?: number,
    answers: (() => Response)[] = [],
  ) {
    vi.restoreAllMocks();
    const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
    const fill = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((bytes) => {
      if (!(bytes instanceof Uint8Array) || bytes.length !== nonce.length) return fill(bytes);
      bytes.set(nonce);
      return bytes;
    });
    const now = vi.spyOn(Date, "now").mockReturnValue(capturedAt * 1000);
    const paths: string[] = [];
    const fetch: typeof globalThis.fetch = (input) => {
      const path = new URL(String(input)).pathname;
      paths.push(path);
      if (path === "/policy.json")
        return Promise.resolve(files.shift()?.() ?? new Response(null, { status: 404 }));
      if (path === "/attestation") {
        if (answeredAt !== undefined) now.mockReturnValue(answeredAt * 1000);
        return Promise.resolve(Response.json(live["attestation"]));
      }
      return Promise.resolve(
        answers.shift()?.() ?? Response.json({ code: "done" }, { status: 418 }),
      );
    };
    const tee = new SignedTeePolicy({
      url: "https://policy.invalid/policy.json",
      network: "fixture",
      ...signers,
    });
    const prover = new ProverClient({ url: "https://prover.invalid", tee, fetch });
    const health = () =>
      expect(prover.health()).rejects.toMatchObject({ details: { status: 418 } });
    return { paths, now, health, prover };
  }

  const served =
    (value: unknown, status = 200) =>
    () =>
      Response.json(value, { status });

  it("downloads the policy once, then attests and sends encrypted", async () => {
    const { paths, health } = client([served(file(2, [1, 2]))]);
    await health();
    await health();
    expect(paths).toEqual(["/policy.json", "/attestation", "/health", "/health"]);
  });

  it("sends nothing without a quorum of pinned signers", async () => {
    for (const seeds of [[1], [1, 4], [1, 1]]) {
      const { paths, prover } = client([served(file(2, seeds)), served(file(2, seeds))]);
      for (const call of [() => prover.health(), () => prover.attest()]) {
        await expect(call()).rejects.toMatchObject({
          code: "CLIENT_PROVER_TEE_ATTESTATION",
          details: { check: "policy_signature" },
        });
      }
      expect(paths).toEqual(["/policy.json", "/policy.json"]);
    }
  });

  it("re-reads the policy whenever it attests again, keeping it through a refused download", async () => {
    const { paths, now, health } = client([
      served(file(2, [1, 2])),
      served(file(3, [2, 3])),
      served({}, 503),
      served(file(2, [1, 2])),
    ]);
    await health();
    for (let step = 1; step <= 3; step++) {
      now.mockReturnValue((capturedAt + 301 * step) * 1000);
      await health();
    }
    expect(paths).toEqual([
      "/policy.json",
      "/attestation",
      "/health",
      "/policy.json",
      "/attestation",
      "/health",
      "/policy.json",
      "/attestation",
      "/health",
      "/policy.json",
      "/attestation",
      "/health",
    ]);
  });

  it("reads the policy again when the prover lost the key, before attesting again", async () => {
    const lost = served({ code: "tee_decryption_failed" }, 400);
    const { paths, health } = client(
      [served(file(2, [1, 2])), served(file(3, [2, 3]))],
      undefined,
      [lost],
    );
    await health();
    expect(paths).toEqual([
      "/policy.json",
      "/attestation",
      "/health",
      "/policy.json",
      "/attestation",
      "/health",
    ]);
  });

  it("never uses a policy past its expiry", async () => {
    const { paths, now, health, prover } = client([served(file(2, [1, 2], capturedAt + 60))]);
    await health();
    now.mockReturnValue((capturedAt + 60) * 1000);
    await expect(prover.health()).rejects.toMatchObject({
      details: { check: "policy_unavailable" },
    });
    expect(paths).toEqual(["/policy.json", "/attestation", "/health", "/policy.json"]);
  });

  it("keeps a release in force past its old freshness once the freshness is renewed", async () => {
    const { paths, now, health } = client([
      served(file(2, [1, 2], undefined, { freshUntil: capturedAt + 400 })),
      served(file(2, [1, 3], undefined, { issuedAt: capturedAt + 300 })),
      served(file(2, [1, 2], undefined, { freshUntil: capturedAt + 400 })),
    ]);
    await health();
    now.mockReturnValue((capturedAt + 301) * 1000);
    await health();
    now.mockReturnValue((capturedAt + 602) * 1000);
    await health();
    expect(paths).toEqual([
      "/policy.json",
      "/attestation",
      "/health",
      "/policy.json",
      "/attestation",
      "/health",
      "/policy.json",
      "/attestation",
      "/health",
    ]);
  });

  it("refuses an older freshness of the same release, keeping the newer expiry", async () => {
    const tee = new SignedTeePolicy({
      url: "https://policy.invalid/policy.json",
      network: "fixture",
      ...signers,
    });
    const now = vi.spyOn(Date, "now").mockReturnValue(capturedAt * 1000);
    const files: unknown[] = [
      file(2, [1, 2], undefined, { issuedAt: capturedAt }),
      file(2, [1, 2], undefined, { issuedAt: capturedAt - 60, freshUntil: capturedAt + 100 }),
    ];
    const fetch: typeof globalThis.fetch = () =>
      Promise.resolve(
        files.length > 0 ? Response.json(files.shift()) : new Response(null, { status: 404 }),
      );
    const newer = await tee.current(fetch);
    tee.invalidate();
    await expect(tee.current(fetch)).resolves.toBe(newer);
    now.mockReturnValue((capturedAt + 200) * 1000);
    await expect(tee.current(fetch)).resolves.toBe(newer);
    expect(files).toEqual([]);
  });

  it("gives up on a download that ignores its deadline and downloads again", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const { paths, prover, health } = client([
        () => new Promise<Response>(() => undefined),
        served(file(2, [1, 2])),
      ]);
      const stalled = prover.health().catch((caught: unknown) => caught);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(await stalled).toBeInstanceOf(Error);
      await health();
      expect(paths).toEqual(["/policy.json", "/policy.json", "/attestation", "/health"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("sends nothing when its policy expires while it attests", async () => {
    const { paths, prover } = client([served(file(2, [1, 2], capturedAt + 60))], capturedAt + 60);
    await expect(prover.health()).rejects.toMatchObject({
      details: { check: "policy_unavailable" },
    });
    expect(paths).toEqual(["/policy.json", "/attestation", "/policy.json"]);
  });

  it.each([
    ["url", { url: "http://policy.example/p.json" }],
    ["publicKeys", { publicKeys: [publicKeys[0]!, publicKeys[0]!], threshold: 1 }],
    ["publicKeys", { publicKeys: ["02" + "00".repeat(31)], threshold: 1 }],
    ["threshold", { threshold: 4 }],
    ["threshold", { threshold: 0 }],
    ["network", { network: "" }],
  ])("refuses a configuration with a bad %s", (field, change) => {
    expect(
      () =>
        new SignedTeePolicy({
          url: "https://policy.example/p.json",
          network: "fixture",
          ...signers,
          ...change,
        }),
    ).toThrow(expect.objectContaining({ details: { field: `tee.${field}` } }));
  });
});
