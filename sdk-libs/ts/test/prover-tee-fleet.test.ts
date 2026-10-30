import { readFileSync } from "node:fs";

import { hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import vector from "../../../test-vectors/tee_fleet_policy.json" with { type: "json" };
import { ProverClient } from "../src/client/prover/client.js";
import {
  checkedProverTeePolicy,
  teeFleetPolicyFromJson,
  verifyFleetAttestation,
} from "../src/client/prover/tee/fleet.js";
import { TeeSession } from "../src/client/prover/tee/session.js";
import { wireDecoder } from "../src/interface/decode.js";
import { expectedProvingKey } from "../src/interface/proving-keys.js";

const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const invalidConfig = expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" });
const attestationFailure = expect.objectContaining({ code: "CLIENT_PROVER_TEE_ATTESTATION" });

function fixture(name: string) {
  const json: unknown = JSON.parse(
    readFileSync(new URL(`../../../prover/tee/testdata/${name}`, import.meta.url), "utf8"),
  );
  const record = decode.record(json, "fixture");
  return {
    attestation: decode.record(record["attestation"], "attestation"),
    nonce: hexToBytes(decode.string(record["nonce"], "nonce")),
    at: Number(decode.integer(record["captured_at"], "captured_at")),
  };
}

function rawPolicy(): Record<string, unknown> {
  return decode.record(structuredClone(vector.policy), "policy");
}

function rawEntries(file: Record<string, unknown>): Record<string, unknown>[] {
  return decode
    .list(file["deployments"], "deployments")
    .map((entry) => decode.record(entry, "entry"));
}

function firstFixture() {
  const first = vector.cases[0];
  if (first === undefined) throw new Error("empty fleet fixture");
  return fixture(first.fixture);
}

afterEach(() => vi.restoreAllMocks());

describe("explicit TEE fleet policy", () => {
  it.each(vector.cases)(
    "verifies the complete $deployment_id entry",
    ({ fixture: name, deployment_id }) => {
      const fleet = teeFleetPolicyFromJson(vector.policy, "fixture");
      const answer = fixture(name);
      const result = verifyFleetAttestation(answer.attestation, fleet, answer.nonce, answer.at);
      const entry = fleet.deployments.find((deployment) => deployment.id === deployment_id);
      expect(entry).toBeDefined();
      expect(result.policy).toBe(entry?.policy);
      expect(result.prover.hpkePublicKey).toEqual(
        hexToBytes(decode.string(answer.attestation["hpke_public_key"], "key")),
      );
    },
  );

  it("requires the intended network and a supported bounded schema", () => {
    expect(() => teeFleetPolicyFromJson(vector.policy, "mainnet")).toThrow(invalidConfig);
    const sparse: unknown[] = [];
    sparse.length = 1;
    for (const [field, value] of [
      ["schema_version", 2],
      ["network", "Fixture"],
      ["revision", 0],
      ["revision", Number.MAX_SAFE_INTEGER + 1],
      ["expires_at", -1],
      ["expires_at", Number.MAX_SAFE_INTEGER + 1],
      ["deployments", []],
      ["deployments", sparse],
      ["deployments", Array.from({ length: 33 }, () => vector.policy.deployments[0])],
      ["unexpected", true],
    ] as const) {
      expect(() => teeFleetPolicyFromJson({ ...vector.policy, [field]: value }, "fixture")).toThrow(
        invalidConfig,
      );
    }
  });

  it("rejects ambiguous, unpinned, and malformed entries", () => {
    const edits: readonly ((entries: Record<string, unknown>[]) => void)[] = [
      (entries) => {
        const [a, b] = entries;
        if (a === undefined || b === undefined) throw new Error("missing entries");
        b["id"] = a["id"];
      },
      (entries) => {
        const [a, b] = entries;
        if (a === undefined || b === undefined) throw new Error("missing entries");
        b["policy"] = a["policy"];
      },
      (entries) => {
        const [a] = entries;
        if (a === undefined) throw new Error("missing entry");
        delete decode.record(a["policy"], "policy")["hpke_public_key"];
      },
      (entries) => {
        const [a] = entries;
        if (a === undefined) throw new Error("missing entry");
        a["unexpected"] = true;
      },
      (entries) => {
        const [a] = entries;
        if (a === undefined) throw new Error("missing entry");
        decode.record(a["policy"], "policy")["unexpected"] = true;
      },
      (entries) => {
        const [a] = entries;
        if (a === undefined) throw new Error("missing entry");
        a["policy"] = { deployment: a["policy"] };
      },
      (entries) => {
        const [a] = entries;
        if (a === undefined) throw new Error("missing entry");
        const policy = decode.record(a["policy"], "policy");
        policy["hpke_public_key"] = decode.string(policy["hpke_public_key"], "key").toUpperCase();
      },
    ];
    for (const edit of edits) {
      const file = rawPolicy();
      const entries = rawEntries(file);
      edit(entries);
      file["deployments"] = entries;
      expect(() => teeFleetPolicyFromJson(file, "fixture")).toThrow(invalidConfig);
    }
  });

  it("never combines a permitted key with another entry's measurements", () => {
    const file = rawPolicy();
    const entries = rawEntries(file);
    const [first, second] = entries;
    if (first === undefined || second === undefined) throw new Error("missing entries");
    const a = decode.record(first["policy"], "policy");
    const b = decode.record(second["policy"], "policy");
    [a["measurements"], b["measurements"]] = [b["measurements"], a["measurements"]];
    file["deployments"] = entries;
    const fleet = teeFleetPolicyFromJson(file, "fixture");
    const answer = firstFixture();
    expect(() =>
      verifyFleetAttestation(answer.attestation, fleet, answer.nonce, answer.at),
    ).toThrow(attestationFailure);
  });

  it("treats the offered key as an untrusted selection hint and still verifies nonce and binding", () => {
    const fleet = teeFleetPolicyFromJson(vector.policy, "fixture");
    const answer = firstFixture();
    expect(() =>
      verifyFleetAttestation(answer.attestation, fleet, new Uint8Array(32), answer.at),
    ).toThrow(attestationFailure);
    for (const key of [fleet.deployments[1]?.policy.hpkePublicKey, "00".repeat(32)]) {
      expect(() =>
        verifyFleetAttestation(
          { ...answer.attestation, hpke_public_key: key },
          fleet,
          answer.nonce,
          answer.at,
        ),
      ).toThrow(attestationFailure);
    }
  });

  it("revalidates caller-built fleets and isolates sessions from later mutations", () => {
    const fleet = teeFleetPolicyFromJson(vector.policy, "fixture");
    expect(() => new TeeSession({ ...fleet, revision: 0 })).toThrow(invalidConfig);
    const mutable = { ...fleet, deployments: [...fleet.deployments] };
    const checked = checkedProverTeePolicy(mutable);
    mutable.deployments.splice(0);
    expect("kind" in checked && checked.deployments).toHaveLength(3);
    expect(Object.isFrozen(checked)).toBe(true);
    for (const invalid of [
      { ...fleet, deployments: null },
      { ...fleet, deployments: [null] },
      { ...fleet, deployments: [{ id: "eu-1", region: "eu-north-1", policy: null }] },
    ]) {
      expect(() =>
        Reflect.construct(ProverClient, [{ url: "https://api.example", tee: invalid }]),
      ).toThrow(invalidConfig);
    }
  });

  it("accepts the public client fleet input and encrypts a synthetic witness", async () => {
    const answer = firstFixture();
    vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((bytes) => {
      if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce");
      bytes.set(answer.nonce);
      return bytes;
    });
    const requests: string[] = [];
    const client = new ProverClient({
      url: "https://api.example/v1/zolana?api-key=test",
      tee: teeFleetPolicyFromJson(vector.policy, "fixture"),
      fetch: async (input, init) => {
        const url = new URL(String(input));
        requests.push(url.pathname);
        if (url.pathname.endsWith("/attestation")) return Response.json(answer.attestation);
        expect(new Headers(init?.headers).get("Zolana-Tee")).toBe("v1");
        expect(init?.body).toBeInstanceOf(Uint8Array);
        expect(init?.body).not.toEqual(new TextEncoder().encode("synthetic-witness"));
        return new Response(null, { status: 400 });
      },
    });
    await expect(
      client.send(
        "synthetic-witness",
        "sync",
        expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 }),
      ),
    ).rejects.toThrow();
    expect(requests).toHaveLength(2);
  });

  it("sends no HTTP for an expired fleet, even when an attested key is cached", async () => {
    const answer = firstFixture();
    const now = vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((bytes) => {
      if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce");
      bytes.set(answer.nonce);
      return bytes;
    });
    const fetch = vi.fn(async () => Response.json(answer.attestation));
    const client = new ProverClient({
      url: "https://api.example/v1/zolana",
      tee: teeFleetPolicyFromJson({ ...vector.policy, expires_at: answer.at + 1 }, "fixture"),
      fetch,
    });
    await client.attest();
    expect(fetch).toHaveBeenCalledTimes(1);
    now.mockReturnValue((answer.at + 1) * 1000);
    await expect(client.checkProvingKeys()).rejects.toThrow(attestationFailure);
    await expect(client.attest()).rejects.toThrow(attestationFailure);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("refreshes the selected generation's quote at its own lifetime, not another entry's", async () => {
    const answer = firstFixture();
    const now = vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    const random = vi.spyOn(globalThis.crypto, "getRandomValues");
    for (let quote = 0; quote < 2; quote++) {
      random.mockImplementationOnce((bytes) => {
        if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce");
        bytes.set(answer.nonce);
        return bytes;
      });
    }
    let quotes = 0;
    const client = new ProverClient({
      url: "https://api.example/v1/zolana",
      tee: teeFleetPolicyFromJson(vector.policy, "fixture"),
      fetch: async (input) => {
        if (new URL(String(input)).pathname.endsWith("/attestation")) {
          quotes++;
          return Response.json(answer.attestation);
        }
        return new Response(null, { status: 400 });
      },
    });
    await client.attest();
    now.mockReturnValue((answer.at + 61) * 1000);
    await expect(client.checkProvingKeys()).rejects.toThrow();
    expect(quotes).toBe(2);
  });

  it("does not send a witness to a key whose evidence fails its paired measurements", async () => {
    const answer = firstFixture();
    vi.spyOn(Date, "now").mockReturnValue(answer.at * 1000);
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementationOnce((bytes) => {
      if (!(bytes instanceof Uint8Array)) throw new Error("unexpected nonce");
      bytes.set(answer.nonce);
      return bytes;
    });
    const file = rawPolicy();
    const entries = rawEntries(file);
    const first = entries[0];
    if (first === undefined) throw new Error("missing entry");
    const second = entries[1];
    if (second === undefined) throw new Error("missing entry");
    decode.record(first["policy"], "policy")["measurements"] = decode.record(
      second["policy"],
      "policy",
    )["measurements"];
    file["deployments"] = entries;
    const fetch = vi.fn(async () => Response.json(answer.attestation));
    const client = new ProverClient({
      url: "https://api.example/v1/zolana",
      tee: teeFleetPolicyFromJson(file, "fixture"),
      fetch,
    });
    await expect(
      client.send(
        "synthetic-witness",
        "sync",
        expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 }),
      ),
    ).rejects.toThrow(attestationFailure);
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
