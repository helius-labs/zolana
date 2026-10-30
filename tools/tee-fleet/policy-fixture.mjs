// Ephemeral test-only publisher. Real ceremonies and production keys live in infra.
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { canonicalize } from "@tufjs/canonical-json";

export function policyFixture(policy) {
  const keys = generateKeyPairSync("ed25519");
  const der = keys.publicKey.export({ type: "spki", format: "der" });
  const key = {
    keytype: "ed25519",
    scheme: "ed25519",
    keyval: { public: der.subarray(-32).toString("hex") },
  };
  const digest = (data) => createHash("sha256").update(data).digest("hex");
  const id = digest(canonicalize(key));
  const expires = new Date(Date.now() + 3_600_000).toISOString();
  const metadata = (type, fields) => {
    const signed = { _type: type, version: 1, spec_version: "1.0.31", expires, ...fields };
    return JSON.stringify({
      signed,
      signatures: [
        {
          keyid: id,
          sig: sign(null, Buffer.from(canonicalize(signed)), keys.privateKey).toString("hex"),
        },
      ],
    });
  };
  const root = metadata("root", {
    consistent_snapshot: true,
    keys: { [id]: key },
    roles: Object.fromEntries(
      ["root", "targets", "snapshot", "timestamp"].map((role) => [
        role,
        { keyids: [id], threshold: 1 },
      ]),
    ),
  });
  const bytes = JSON.stringify(policy);
  const target = { length: Buffer.byteLength(bytes), hashes: { sha256: digest(bytes) } };
  const targets = metadata("targets", { targets: { [`${policy.network}/fleet.json`]: target } });
  const ref = (data) => ({
    version: 1,
    length: Buffer.byteLength(data),
    hashes: { sha256: digest(data) },
  });
  const snapshot = metadata("snapshot", { meta: { "targets.json": ref(targets) } });
  const timestamp = metadata("timestamp", { meta: { "snapshot.json": ref(snapshot) } });
  return {
    root,
    files: {
      "metadata/1.root.json": root,
      "metadata/timestamp.json": timestamp,
      "metadata/1.snapshot.json": snapshot,
      "metadata/1.targets.json": targets,
      [`targets/${policy.network}/${target.hashes.sha256}.fleet.json`]: bytes,
    },
  };
}
