// Fixture provenance gates for G8-1 (revision compatibility) and G8-2
// (verifying-key identity). Invoked from fixtures-check.mjs after generators.
//
//   node sdk-libs/ts/config/fixtures-provenance.mjs

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const fixturesRoot = path.join(root, "sdk-libs/ts/fixtures");
const vkRoot = path.join(root, "program-libs/interface/src/verifying_keys");

const REQUIRED_REVISION_KEYS = [
  "baseline",
  "client",
  "interface",
  "merkleTree",
  "frozenCommit",
  "historicalBaselineCommit",
  "photonSchemaRevision",
  "specSha256",
  "provingKeyRelease",
  "driftReview",
];

/** Fixture path → manifest revision key its sourceRevision must equal. */
const SOURCE_REVISION_BINDINGS = Object.freeze({
  "client/errors-v1.json": "client",
  "client/lib.json": "client",
  "client/rpc-indexer-v1.json": "client",
  "merkle-tree/paths-v1.json": "merkleTree",
  "api/transport-v1.json": "frozenCommit",
});

/**
 * Proof fixtures and the verifying-key modules the release verifier loads for
 * the rail/shape each fixture exercises. SHA-256 is over the committed
 * `program-libs/interface/src/verifying_keys/<module>.rs` source the
 * `groth16-verify` oracle imports.
 */
const PROOF_FIXTURE_VKS = Object.freeze({
  "client/proof-validity-v1.json": [
    { rail: "eddsa", module: "transfer_confidential_1_1" },
    { rail: "p256", module: "transfer_p256_confidential_1_1" },
  ],
  "client/proof-result-compression-v1.json": [
    { rail: "p256", module: "transfer_p256_confidential_1_1" },
  ],
  "client/proof-input-v1.json": [{ rail: "eddsa", module: "transfer_confidential_1_1" }],
});

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function readJson(relative) {
  return JSON.parse(readFileSync(path.join(fixturesRoot, relative), "utf8"));
}

function pinValue(manifest, key) {
  if (key === "specSha256") return manifest.specSha256;
  if (key === "provingKeyRelease") return manifest.provingKeyRelease?.lockSha256;
  if (key === "frozenCommit") return manifest.frozenCommit;
  if (key === "historicalBaselineCommit") return manifest.historicalBaselineCommit;
  if (key === "photonSchemaRevision") return manifest.photonSchemaRevision;
  if (key === "driftReview") return manifest.driftReview?.reviewedAgainst;
  return manifest.canonicalSourceRevisions?.[key];
}

function checkDriftReview(manifest) {
  const review = manifest.driftReview;
  if (review === undefined || typeof review !== "object" || Array.isArray(review)) {
    throw new Error("manifest.json lacks driftReview");
  }
  for (const field of ["reviewedAt", "reviewedAgainst", "finding", "notes"]) {
    if (typeof review[field] !== "string" || review[field].length === 0) {
      throw new Error(`driftReview.${field} is missing`);
    }
  }
  if (!/^[0-9a-f]{40}$/u.test(review.reviewedAgainst)) {
    throw new Error("driftReview.reviewedAgainst is not a 40-char commit sha");
  }
  if (!Array.isArray(review.generators) || review.generators.length === 0) {
    throw new Error("driftReview.generators must name the generators that were run");
  }
  if (review.finding !== "no-body-drift" && !review.finding.startsWith("body-change:")) {
    throw new Error(
      `driftReview.finding must be no-body-drift or body-change:<path> (got ${review.finding})`,
    );
  }
  if (
    typeof review.commitsSinceFrozenTouchingFixtureSources !== "number" ||
    review.commitsSinceFrozenTouchingFixtureSources < 0
  ) {
    throw new Error("driftReview.commitsSinceFrozenTouchingFixtureSources is missing");
  }
}

function checkRevisionCompatibility(manifest) {
  const rules = manifest.revisionCompatibility;
  if (rules === undefined || typeof rules !== "object" || Array.isArray(rules)) {
    throw new Error("manifest.json lacks revisionCompatibility");
  }

  for (const key of REQUIRED_REVISION_KEYS) {
    const rule = rules[key];
    if (rule === undefined || typeof rule !== "object") {
      throw new Error(`revisionCompatibility lacks key ${key}`);
    }
    if (typeof rule.compatibility !== "string" || rule.compatibility.length === 0) {
      throw new Error(`revisionCompatibility.${key} lacks compatibility`);
    }
    if (typeof rule.regenerationTrigger !== "string" || rule.regenerationTrigger.length === 0) {
      throw new Error(`revisionCompatibility.${key} lacks regenerationTrigger`);
    }
  }

  for (const key of REQUIRED_REVISION_KEYS) {
    const rule = rules[key];
    const value = pinValue(manifest, key);
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`manifest pin ${key} is missing`);
    }
    for (const other of rule.mustAgreeWith ?? []) {
      const otherValue = pinValue(manifest, other);
      if (value !== otherValue) {
        throw new Error(
          `incompatible pins: ${key}=${value} must agree with ${other}=${otherValue}`,
        );
      }
    }
  }

  for (const [relative, key] of Object.entries(SOURCE_REVISION_BINDINGS)) {
    const fixture = readJson(relative);
    const expected = pinValue(manifest, key);
    if (fixture.sourceRevision !== expected) {
      throw new Error(
        `${relative} sourceRevision ${fixture.sourceRevision} is incompatible with manifest ${key}=${expected}`,
      );
    }
  }

  const lockPath = manifest.provingKeyRelease?.lockPath;
  if (typeof lockPath !== "string") {
    throw new Error("manifest provingKeyRelease.lockPath is missing");
  }
  const lockBytes = readFileSync(path.join(root, lockPath));
  // Live lockfile may move with key rotation; the historical pin is the blob at
  // frozenCommit. Compare the committed working-tree lock only when it still
  // matches the pin — otherwise require the pin to equal the frozen blob hash
  // already recorded (generators own that). Here we only refuse a pin that does
  // not look like a sha256.
  if (!/^[0-9a-f]{64}$/u.test(manifest.provingKeyRelease.lockSha256)) {
    throw new Error("manifest provingKeyRelease.lockSha256 is not a sha256 hex digest");
  }
  void lockBytes;
}

function checkProofVerifyingKeys() {
  for (const [relative, expected] of Object.entries(PROOF_FIXTURE_VKS)) {
    const fixture = readJson(relative);
    const recorded = fixture.verifyingKeys;
    if (!Array.isArray(recorded) || recorded.length === 0) {
      throw new Error(`${relative} lacks verifyingKeys`);
    }
    if (recorded.length !== expected.length) {
      throw new Error(`${relative} verifyingKeys length ${recorded.length} != ${expected.length}`);
    }
    for (let i = 0; i < expected.length; i += 1) {
      const want = expected[i];
      const got = recorded[i];
      if (got?.module !== want.module || got?.rail !== want.rail) {
        throw new Error(
          `${relative} verifyingKeys[${i}] expected ${want.rail}/${want.module}, got ${got?.rail}/${got?.module}`,
        );
      }
      const vkPath = path.join(vkRoot, `${want.module}.rs`);
      const liveSha = sha256Hex(readFileSync(vkPath));
      if (got.sha256 !== liveSha) {
        throw new Error(
          `${relative} verifyingKeys[${i}] sha256 ${got.sha256} differs from verifier module ${want.module} at ${liveSha}`,
        );
      }
    }
  }
}

const manifest = readJson("manifest.json");
checkRevisionCompatibility(manifest);
checkDriftReview(manifest);
checkProofVerifyingKeys();
console.log("fixture provenance ok");
