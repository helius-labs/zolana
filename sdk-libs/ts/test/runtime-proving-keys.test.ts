import vector from "../../../test-vectors/runtime_proving_keys.json" with { type: "json" };
import { readFileSync } from "node:fs";

import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { gcm } from "@noble/ciphers/aes.js";
import { concatBytes, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { SprClient } from "../src/client/client.js";
import { asField, createDummyTransferInput, createOutput } from "../src/client/prover/assembly.js";
import { ProverClient } from "../src/client/prover/client.js";
import { provingKeySetFromCatalog, type ProvingKeySet } from "../src/client/prover/key-set.js";
import { teePolicyFromJson } from "../src/client/prover/tee/policy.js";
import type { MergeInputs } from "../src/client/prover/types.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import { MERGE_INPUT_COUNT } from "../src/interface/constants.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { PROVING_KEY_SHA256S, expectedProvingKey } from "../src/interface/proving-keys.js";
import { INPUT_TREES, ZERO_TREE_SLOT } from "../src/interface/tree-slot.js";
import { treeSlotFields } from "../src/client/prover/assembly.js";
import type { Bytes32 } from "../src/interface/index.js";
import { ProofInputUtxo, createProofOutput } from "../src/transaction/index.js";

// The attested key is one this file holds, so it can answer encrypted calls.
const enclave = vi.hoisted(() => ({ publicKey: new Uint8Array(32) }));
vi.mock("../src/client/prover/tee/verify.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/client/prover/tee/verify.js")>();
  return {
    ...actual,
    verifyAttestation: () =>
      Object.freeze({
        platform: "dstack-tdx",
        hpkePublicKey: enclave.publicKey.slice(),
        imageId: new Uint8Array(32),
        gpuVerified: false,
      }),
  };
});

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});
let enclaveKey: CryptoKeyPair;

beforeAll(async () => {
  enclaveKey = await suite.kem.generateKeyPair();
  enclave.publicKey = new Uint8Array(await suite.kem.serializePublicKey(enclaveKey.publicKey));
});

const policy = teePolicyFromJson(
  JSON.parse(
    readFileSync(
      new URL("../../../prover/tee/testdata/probe_policy.json", import.meta.url),
      "utf8",
    ),
  ),
);

type Catalog = {
  keys: { name: string; artifacts: Record<string, unknown>[] }[];
  runtime?: Record<string, unknown> | null;
  [field: string]: unknown;
};

/** A fresh copy of the shared vector, as the prover serves it. */
function catalog(): Catalog {
  return structuredClone(vector) as Catalog;
}

function verifier(value: Catalog, name: string): Record<string, unknown> {
  const runtime = value.runtime;
  if (runtime === undefined || runtime === null) throw new Error("no runtime");
  return (runtime["verifyingKeys"] as Record<string, Record<string, unknown>>)[name] ?? {};
}

function entry(value: Catalog, name: string): Catalog["keys"][number] {
  const found = value.keys.find((key) => key.name === name);
  if (found === undefined) throw new Error(`${name} is not listed`);
  return found;
}

function artifact(value: Catalog, name: string, format: string): Record<string, unknown> {
  const found = entry(value, name).artifacts.find((item) => item["format"] === format);
  if (found === undefined) throw new Error(`${name} has no ${format}`);
  return found;
}

function check(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("accepted");
}

const refusedWith = (check: string) => ({
  code: "CLIENT_PROVING_KEY_SET",
  details: { check },
});

/** `merge_24_1.key` moved to a new proving key. */
function rotated(): Catalog {
  const value = catalog();
  const sha = "ab".repeat(32);
  verifier(value, "merge_24_1.key")["provingKeySha256"] = sha;
  artifact(value, "merge_24_1.key", "gnark")["sha256"] = sha;
  return value;
}

describe("a runtime proving key set", () => {
  it("parses the shared vector and reproduces its cache key", () => {
    const set = provingKeySetFromCatalog(catalog());
    expect(set.cacheKey).toBe(vector.expectedCacheKey);
    expect(Object.isFrozen(set)).toBe(true);
    // The web prover's `ProvingKeySource` takes a set as it is.
    const source: {
      readonly cacheKey: string;
      key(name: string): Readonly<{
        file: string;
        size: number;
        sha256: string;
        keySha256: string;
        url: string;
      }>;
    } = set;
    expect(source.cacheKey).toMatch(/^[0-9a-f]{64}$/u);
    const names = Object.keys(PROVING_KEY_SHA256S).filter(
      (name) =>
        /^transfer_confidential_\d+_\d+\.key$/u.test(name) || /^merge_\d+_1\.key$/u.test(name),
    );
    expect(names).toHaveLength(41);
    for (const name of names) {
      const zopro = artifact(catalog(), name, "zopro");
      const key = set.key(name);
      expect(key).toEqual({
        file: name.replace(/\.key$/u, ".zopro"),
        size: zopro["size"],
        sha256: zopro["sha256"],
        keySha256: PROVING_KEY_SHA256S[name],
        url: zopro["url"],
      });
      expect(Object.isFrozen(key)).toBe(true);
    }
  });

  it("keys the cache by content, not by the catalog's order", () => {
    const value = catalog();
    value.keys.reverse();
    expect(provingKeySetFromCatalog(value).cacheKey).toBe(vector.expectedCacheKey);
    expect(provingKeySetFromCatalog(rotated()).cacheKey).not.toBe(vector.expectedCacheKey);
  });

  it("refuses a key outside the set", () => {
    const set = provingKeySetFromCatalog(catalog());
    for (const name of [
      "merge_ring_8_1.key",
      "transfer_confidential_eddsa_2_8.key",
      "transfer_ring_2_2.key",
      "batch_address-append_40_10.key",
    ]) {
      expect(check(() => set.key(name))).toMatchObject(refusedWith("unsupported_circuit"));
    }
  });

  it("accepts a loopback download and verifying keys of other circuits", () => {
    const value = catalog();
    artifact(value, "merge_8_1.key", "zopro")["url"] = "http://127.0.0.1:8080/merge_8_1.zopro";
    artifact(value, "merge_24_1.key", "zopro")["url"] = "http://keys.localhost/merge_24_1.zopro";
    const runtime = value.runtime as Record<string, Record<string, unknown>>;
    runtime["verifyingKeys"] = {
      ...runtime["verifyingKeys"],
      "merge_99_1.key": verifier(value, "merge_8_1.key"),
    };
    expect(provingKeySetFromCatalog(value).key("merge_8_1.key").url).toBe(
      "http://127.0.0.1:8080/merge_8_1.zopro",
    );
  });

  const zopro = (value: Catalog) => artifact(value, "merge_8_1.key", "zopro");
  const cases: readonly (readonly [string, string, (value: Catalog) => void])[] = [
    [
      "a missing runtime",
      "runtime_missing",
      (value) => {
        delete value.runtime;
      },
    ],
    [
      "a null runtime",
      "runtime_missing",
      (value) => {
        value.runtime = null;
      },
    ],
    [
      "another abi",
      "incompatible",
      (value) => {
        (value.runtime as Record<string, unknown>)["abi"] = "spr-confidential-v2";
      },
    ],
    [
      "another program",
      "incompatible",
      (value) => {
        (value.runtime as Record<string, unknown>)["programId"] =
          "11111111111111111111111111111111";
      },
    ],
    [
      "a missing verifying key",
      "incompatible",
      (value) => {
        const runtime = value.runtime as Record<string, Record<string, unknown>>;
        delete runtime["verifyingKeys"]?.["merge_8_1.key"];
      },
    ],
    [
      "an unknown runtime field",
      "malformed",
      (value) => {
        (value.runtime as Record<string, unknown>)["extra"] = 1;
      },
    ],
    [
      "an unknown verifying key field",
      "malformed",
      (value) => {
        verifier(value, "merge_8_1.key")["extra"] = "00";
      },
    ],
    [
      "a short point",
      "malformed",
      (value) => {
        verifier(value, "merge_8_1.key")["alphaG1"] = "00";
      },
    ],
    [
      "a long G2 point",
      "malformed",
      (value) => {
        verifier(value, "merge_8_1.key")["betaG2"] += "00";
      },
    ],
    [
      "an uppercase point",
      "malformed",
      (value) => {
        const key = verifier(value, "merge_8_1.key");
        key["deltaG2"] = String(key["deltaG2"]).toUpperCase();
      },
    ],
    [
      "no ic",
      "malformed",
      (value) => {
        verifier(value, "merge_8_1.key")["ic"] = [];
      },
    ],
    [
      "one ic",
      "malformed",
      (value) => {
        const key = verifier(value, "merge_8_1.key");
        key["ic"] = (key["ic"] as string[]).slice(0, 1);
      },
    ],
    [
      "three ic",
      "malformed",
      (value) => {
        const key = verifier(value, "merge_8_1.key");
        const ic = key["ic"] as string[];
        key["ic"] = [...ic, ic[0]];
      },
    ],
    [
      "a gnark key of another verifying key",
      "source_mismatch",
      (value) => {
        verifier(value, "merge_8_1.key")["provingKeySha256"] = "cd".repeat(32);
      },
    ],
    [
      "an uppercase zopro sha",
      "malformed",
      (value) => {
        zopro(value)["sha256"] = "AB".repeat(32);
      },
    ],
    [
      "a short zopro sha",
      "malformed",
      (value) => {
        zopro(value)["sha256"] = "ab";
      },
    ],
    [
      "size 0",
      "malformed",
      (value) => {
        zopro(value)["size"] = 0;
      },
    ],
    [
      "size 2^32",
      "malformed",
      (value) => {
        zopro(value)["size"] = 2 ** 32;
      },
    ],
    [
      "a fractional size",
      "malformed",
      (value) => {
        zopro(value)["size"] = 1.5;
      },
    ],
    [
      "plain http to a remote host",
      "malformed",
      (value) => {
        zopro(value)["url"] = "http://keys.example/merge_8_1.zopro";
      },
    ],
    [
      "another scheme",
      "malformed",
      (value) => {
        zopro(value)["url"] = "ftp://keys.example/merge_8_1.zopro";
      },
    ],
    [
      "a user and password",
      "malformed",
      (value) => {
        zopro(value)["url"] = "https://user:pw@keys.example/k";
      },
    ],
    [
      "a user",
      "malformed",
      (value) => {
        zopro(value)["url"] = "https://user@keys.example/k";
      },
    ],
    [
      "a fragment",
      "malformed",
      (value) => {
        zopro(value)["url"] = "https://keys.example/k#frag";
      },
    ],
    [
      "an empty fragment",
      "malformed",
      (value) => {
        zopro(value)["url"] = "https://keys.example/k#";
      },
    ],
    [
      "no URL",
      "malformed",
      (value) => {
        zopro(value)["url"] = "merge_8_1.zopro";
      },
    ],
    [
      "a duplicate key entry",
      "malformed",
      (value) => {
        value.keys.push(structuredClone(entry(value, "merge_8_1.key")));
      },
    ],
    [
      "a duplicate zopro artifact",
      "malformed",
      (value) => {
        entry(value, "merge_8_1.key").artifacts.push({ ...zopro(value) });
      },
    ],
    [
      "a duplicate gnark artifact",
      "malformed",
      (value) => {
        const key = entry(value, "merge_8_1.key");
        key.artifacts.push({ ...artifact(value, "merge_8_1.key", "gnark") });
      },
    ],
    [
      "no zopro artifact",
      "malformed",
      (value) => {
        const key = entry(value, "merge_8_1.key");
        key.artifacts = key.artifacts.filter((item) => item["format"] !== "zopro");
      },
    ],
    [
      "an unknown artifact format",
      "malformed",
      (value) => {
        zopro(value)["format"] = "arkworks";
      },
    ],
    [
      "empty keys",
      "malformed",
      (value) => {
        value.keys = [];
      },
    ],
    [
      "no keys",
      "malformed",
      (value) => {
        Reflect.deleteProperty(value, "keys");
      },
    ],
  ];

  it.each(cases)("refuses %s as %s", (_name, reason, change) => {
    const value = catalog();
    change(value);
    expect(check(() => provingKeySetFromCatalog(value))).toMatchObject(refusedWith(reason));
  });

  it("refuses a value that is not a catalog", () => {
    for (const value of [null, [], "catalog", 1]) {
      expect(check(() => provingKeySetFromCatalog(value))).toMatchObject(refusedWith("malformed"));
    }
  });
});

/** Answers each `/proving-keys` call as an attested enclave would. */
async function sealedAnswer(
  init: RequestInit | undefined,
  status: number,
  body: string,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  const recipient = await suite.createRecipientContext({
    recipientKey: enclaveKey,
    enc: hexToBytes(headers.get("Spr-Tee-Enc") ?? ""),
    info: utf8ToBytes("zolana/prover-tee/v1"),
  });
  await recipient.open(
    hexToBytes(headers.get("Spr-Tee-Ciphertext") ?? ""),
    utf8ToBytes("GET /proving-keys"),
  );
  const key = new Uint8Array(
    await recipient.export(utf8ToBytes("zolana/prover-tee/v1/response"), 32),
  );
  const nonce = randomBytes(12);
  const plaintext = concatBytes(Uint8Array.of(status >> 8, status & 0xff), utf8ToBytes(body));
  return new Response(concatBytes(nonce, gcm(key, nonce).encrypt(plaintext)), {
    headers: { "Spr-Tee": "v1" },
  });
}

function prover(
  answer: (init: RequestInit | undefined) => Promise<Response>,
  sent: string[] = [],
): typeof globalThis.fetch {
  return async (input, init) => {
    const path = new URL(String(input)).pathname;
    sent.push(path);
    if (path === "/attestation") return Response.json({});
    return answer(init);
  };
}

describe("fetching a runtime proving key set", () => {
  it("requires an attested prover before any HTTP, loopback included", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    for (const url of ["http://127.0.0.1:3001", "https://prover.example"]) {
      await expect(new ProverClient({ url, fetch }).fetchProvingKeySet()).rejects.toMatchObject(
        refusedWith("attestation_required"),
      );
      await expect(
        new SprClient({ proverUrl: url, fetch }).fetchProvingKeySet(),
      ).rejects.toMatchObject(refusedWith("attestation_required"));
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it("reads the set over the encrypted channel of a client with only a prover", async () => {
    const sent: string[] = [];
    const fetch = prover((init) => sealedAnswer(init, 200, JSON.stringify(vector)), sent);
    const client = new SprClient({
      proverUrl: "https://prover.example",
      proverTee: policy,
      fetch,
    });
    const set = await client.fetchProvingKeySet();
    expect(set.cacheKey).toBe(vector.expectedCacheKey);
    expect(sent).toEqual(["/attestation", "/proving-keys"]);
    const local = new ProverClient({ url: "http://127.0.0.1:3001", tee: policy, fetch });
    expect((await local.fetchProvingKeySet()).cacheKey).toBe(vector.expectedCacheKey);
  });

  it("refuses a plaintext answer to an attested request", async () => {
    const fetch = prover(async () => Response.json(vector));
    await expect(
      new ProverClient({ url: "https://prover.example", tee: policy, fetch }).fetchProvingKeySet(),
    ).rejects.toMatchObject({
      code: "CLIENT_PROVER_TEE_ENCRYPTION",
      details: { check: "unencrypted" },
    });
  });

  it.each([
    ["a plaintext refusal", async () => new Response("404 page not found", { status: 404 })],
    ["an encrypted 503", (init: RequestInit | undefined) => sealedAnswer(init, 503, "{}")],
    [
      "an encrypted 201",
      (init: RequestInit | undefined) => sealedAnswer(init, 201, JSON.stringify(vector)),
    ],
  ])("reads %s as unavailable", async (_name, answer) => {
    await expect(
      new ProverClient({
        url: "https://prover.example",
        tee: policy,
        fetch: prover(answer),
      }).fetchProvingKeySet(),
    ).rejects.toMatchObject(refusedWith("unavailable"));
  });

  it.each([
    ["not JSON", "keys", "malformed"],
    [
      "a catalog without runtime metadata",
      JSON.stringify({ keys: vector.keys }),
      "runtime_missing",
    ],
  ])("refuses an encrypted answer of %s", async (_name, body, reason) => {
    await expect(
      new ProverClient({
        url: "https://prover.example",
        tee: policy,
        fetch: prover((init) => sealedAnswer(init, 200, body)),
      }).fetchProvingKeySet(),
    ).rejects.toMatchObject(refusedWith(reason));
  });
});

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function dummyInput() {
  const utxo = ProofInputUtxo.dummy(bytes(7));
  const proof: NonInclusionProof = {
    leaf: utxo.nullifier(),
    merkleContext: { treeType: 0, tree: treeAddress(0) },
    lowElement: bytes(1),
    highElement: bytes(2),
    highElementIndex: 1n,
    path: [],
    lowElementIndex: 0n,
    root: bytes(3),
    rootSeq: 0n,
    rootIndex: 0,
  };
  return createDummyTransferInput(utxo, proof);
}

function mergeInputs(): MergeInputs {
  return {
    inputs: Array.from({ length: MERGE_INPUT_COUNT }, () => dummyInput()),
    output: createOutput(
      createProofOutput({
        asset: address("11111111111111111111111111111111"),
        amount: 0n,
        blinding: bytes(0),
      }),
      0,
    ),
    treeSlots: Array.from({ length: INPUT_TREES }, () => treeSlotFields(ZERO_TREE_SLOT)),
    outputTreeId: asField(0n),
    mintChunks: [asField(0n), asField(0n)],
    outputCiphertextSalt: asField(0n),
    ownerPublicKeyHash: asField(0n),
    userNullifierPublicKey: asField(0n),
    userNullifierSecret: asField(0n),
    externalDataHash: asField(0n),
    privateTxHash: asField(0n),
    allowDummyInputs: asField(1n),
    publicInputHash: asField(0n),
    outputRingDataHash: asField(0n),
    ringProgramId: asField(0n),
  };
}

const proofReporting = (provingKeySha256: string) => ({
  ar: ["0x0", "0x0"],
  bs: [
    ["0x0", "0x0"],
    ["0x0", "0x0"],
  ],
  krs: ["0x0", "0x0"],
  provingKeySha256,
});

describe("proving with a runtime proving key set", () => {
  const mergeKey = `merge_${String(MERGE_INPUT_COUNT)}_1.key`;
  const rotatedSha = "ab".repeat(32);
  let set: ProvingKeySet;
  beforeAll(() => {
    const value = rotated();
    if (mergeKey !== "merge_24_1.key") throw new Error("rotated() moves merge_24_1.key");
    set = provingKeySetFromCatalog(value);
  });

  it("expects the set's key in every proof", async () => {
    const answer = (sha: string) =>
      vi.fn<typeof globalThis.fetch>(async () => Response.json(proofReporting(sha)));
    const url = "http://127.0.0.1:3001";
    await expect(
      new ProverClient({ url, fetch: answer(rotatedSha), provingKeys: set }).proveMerge(
        mergeInputs(),
      ),
    ).resolves.toBeDefined();
    await expect(
      new ProverClient({
        url,
        fetch: answer(PROVING_KEY_SHA256S[mergeKey] ?? ""),
        provingKeys: set,
      }).proveMerge(mergeInputs()),
    ).rejects.toMatchObject({
      code: "CLIENT_PROVING_KEY_MISMATCH",
      details: { keyName: mergeKey, expectedSha256: rotatedSha },
    });
    // Without the set the compiled pin still holds.
    await expect(
      new ProverClient({ url, fetch: answer(rotatedSha) }).proveMerge(mergeInputs()),
    ).rejects.toMatchObject({ code: "CLIENT_PROVING_KEY_MISMATCH" });
  });

  it("refuses a circuit outside the set and the indexed route before any HTTP", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const client = new ProverClient({ url: "http://127.0.0.1:3001", fetch, provingKeys: set });
    const ring = expectedProvingKey({ circuit: "transfer-ring", nInputs: 2, nOutputs: 2 });
    await expect(client.send("{}", "sync", ring)).rejects.toMatchObject(
      refusedWith("unsupported_circuit"),
    );
    await expect(
      client.proveMerge({ ...mergeInputs(), ringProgramId: asField(7n) }),
    ).rejects.toMatchObject(refusedWith("unsupported_circuit"));
    const merge = expectedProvingKey({ circuit: "merge", nInputs: 8 });
    await expect(client.send("{}", "indexed", merge)).rejects.toMatchObject(
      refusedWith("indexed_proving_unsupported"),
    );
    await expect(Reflect.apply(client.proveIndexed, client, [{}])).rejects.toMatchObject(
      refusedWith("indexed_proving_unsupported"),
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("checks the prover's catalog against the set's digests only", async () => {
    // A rotation also changes keys outside the set, which the set refuses anyway.
    const outside = "merge_ring_8_1.key";
    const report = (sha: string) => ({
      keys: Object.entries(PROVING_KEY_SHA256S).map(([name, pin]) => ({
        name,
        artifacts: [
          {
            format: "gnark",
            sha256: name === mergeKey ? sha : name === outside ? "cd".repeat(32) : pin,
            size: 1,
            url: "https://keys.example/key",
          },
        ],
      })),
    });
    const client = (sha: string) =>
      new ProverClient({
        url: "http://127.0.0.1:3001",
        fetch: async () => Response.json(report(sha)),
        provingKeys: set,
      });
    await expect(client(rotatedSha).checkProvingKeys()).resolves.toEqual(report(rotatedSha));
    await expect(
      client(PROVING_KEY_SHA256S[mergeKey] ?? "").checkProvingKeys(),
    ).rejects.toMatchObject({
      code: "CLIENT_PROVER_PROVING_KEYS_MISMATCH",
      details: { keyNames: mergeKey },
    });
  });

  it("requires the client proof data source", () => {
    const base = { proverUrl: "http://127.0.0.1:3001", provingKeys: set };
    expect(() => new SprClient({ ...base, proofDataSource: "client" })).not.toThrow();
    for (const config of [base, { ...base, proofDataSource: "prover" as const }]) {
      expect(() => new SprClient(config)).toThrow(
        expect.objectContaining({
          code: "CLIENT_INVALID_CONFIG",
          details: { field: "proofDataSource" },
        }),
      );
    }
  });

  it("refuses a set the SDK did not parse", () => {
    const handMade = [
      { cacheKey: set.cacheKey, key: (name: string) => set.key(name) },
      Object.create(Object.getPrototypeOf(set) as object) as object,
      { ...set },
    ];
    for (const provingKeys of handMade) {
      expect(() =>
        Reflect.construct(SprClient, [{ proofDataSource: "client", provingKeys }]),
      ).toThrow(
        expect.objectContaining({
          code: "CLIENT_INVALID_CONFIG",
          details: { field: "provingKeys" },
        }),
      );
      expect(() =>
        Reflect.construct(ProverClient, [{ url: "http://127.0.0.1:3001", provingKeys }]),
      ).toThrow(
        expect.objectContaining({
          code: "CLIENT_INVALID_CONFIG",
          details: { field: "provingKeys" },
        }),
      );
    }
    expect(() => Reflect.construct(set.constructor, [Symbol("ProvingKeySet"), new Map()])).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" }),
    );
  });
});
