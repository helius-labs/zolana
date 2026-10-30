import { createHash as nodeHash, generateKeyPairSync, sign } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { expect, it } from "vitest";
import vector from "../../../test-vectors/tee_tuf_repository.json" with { type: "json" };
import { createHash, createPublicKey, verify } from "../src/client/prover/tee/browser/crypto.js";
import { isDeepStrictEqual } from "../src/client/prover/tee/browser/equality.js";
import { uniqueJson } from "../src/client/prover/tee/browser/json.js";
import { tufTeePolicy } from "../src/client/prover/tee/tuf-browser.js";

it("verifies native Ed25519 signatures through the browser crypto port", () => {
  const pair = generateKeyPairSync("ed25519");
  const der = pair.publicKey.export({ type: "spki", format: "der" });
  const key = createPublicKey({ key: der, type: "spki", format: "der" });
  const bytes = new TextEncoder().encode("signed TUF metadata");
  const signature = sign(null, bytes, pair.privateKey);
  expect(verify(undefined, bytes, { key }, signature)).toBe(true);
  expect(verify(undefined, bytes.slice(1), { key }, signature)).toBe(false);
  signature[0] = signature[0]! ^ 1;
  expect(verify(undefined, bytes, { key }, signature)).toBe(false);
  expect(() => verify("sha256", bytes, { key }, signature)).toThrow();
  expect(() => verify(undefined, bytes, { key: {} }, signature)).toThrow();
});

it("rejects malformed, PEM and non-Ed25519 public keys instead of emulating unsupported crypto", () => {
  for (const input of [
    null,
    {},
    "-----BEGIN PUBLIC KEY-----",
    { key: new Uint8Array(44), format: "der", type: "spki" },
  ]) {
    expect(() => createPublicKey(input)).toThrow();
  }
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  expect(() =>
    createPublicKey({
      key: rsa.publicKey.export({ format: "der", type: "spki" }),
      format: "der",
      type: "spki",
    }),
  ).toThrow();
});

it("uses strict Ed25519 verification and rejects low-order forged signatures", () => {
  const der = new Uint8Array(44);
  der.set([0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3, 0x21, 0]);
  der[12] = 1; // Encoded identity point, with a trivial signature.
  const signature = new Uint8Array(64);
  signature[0] = 1;
  expect(ed25519.verify(signature, new Uint8Array(), der.subarray(12), { zip215: false })).toBe(
    false,
  );
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  expect(verify(undefined, new Uint8Array(), { key }, signature)).toBe(false);
});

it("matches native incremental SHA-256 and refuses unsupported algorithms and encodings", () => {
  const suffix = Uint8Array.of(0, 1, 2, 255);
  expect(createHash("sha256").update("prefix").update(suffix).digest("hex")).toBe(
    nodeHash("sha256").update("prefix").update(suffix).digest("hex"),
  );
  expect(createHash("sha256").update(suffix).digest()).toEqual(
    new Uint8Array(nodeHash("sha256").update(suffix).digest()),
  );
  expect(() => createHash("md5")).toThrow();
  expect(() => createHash("sha256").digest("base64")).toThrow();
});

it.each([
  '{"a":1,"a":2}',
  '{"a":1,"\\u0061":2}',
  '{"nested":{"x":1,"x":2}}',
  '{"a":01}',
  '{"a":truex}',
  '{"a":1,}',
  "[1,]",
  "{} null",
  '"bad\\x20"',
  `${"[".repeat(34)}0${"]".repeat(34)}`,
])("rejects ambiguous or malformed policy JSON %s", (json) => {
  expect(() => uniqueJson(json)).toThrow();
});

it("accepts JSON escapes, repeated names in separate objects and nested arrays", () => {
  const json = '{"a":[{"x":"\\\""},{"x":-1.25e2}],"b":true,"c":null}';
  expect(uniqueJson(json)).toEqual(JSON.parse(json));
});

it("compares the JSON model values without broad object coercion", () => {
  expect(isDeepStrictEqual({ a: [1, null], b: false }, { b: false, a: [1, null] })).toBe(true);
  expect(isDeepStrictEqual({ a: undefined }, {})).toBe(false);
  expect(isDeepStrictEqual([1], ["1"])).toBe(false);
  expect(() => isDeepStrictEqual(new Date(0), new Date(0))).toThrow();
});

const options = {
  network: vector.network,
  rootJson: vector.bootstrap_root,
  metadataUrl: "https://policy.test/metadata/",
  targetsUrl: "https://policy.test/targets/",
};

it("fails closed outside a browser with durable storage and Web Locks", async () => {
  await expect(tufTeePolicy(options).resolve()).rejects.toMatchObject({
    code: "CLIENT_PROVER_TEE_ATTESTATION",
    details: { check: "policy_storage" },
  });
});

it("rejects invalid roots, origins and database names before I/O", () => {
  for (const patch of [
    { rootJson: "{}" },
    { metadataUrl: "http://policy.test/" },
    { targetsUrl: "https://policy.test/?api-key=secret" },
    { databaseName: "" },
  ]) {
    expect(() => tufTeePolicy({ ...options, ...patch })).toThrow();
  }
});
