/**
 * Runs in a browser. Asserts the SDK against the same Rust vectors the Node
 * suites use, so a Node/browser byte divergence fails here rather than only
 * in a real wallet.
 *
 * Loaded by `browser-runtime-check.mjs` through an esbuild browser bundle; do
 * not import this from Node.
 */
import { initializePoseidon, poseidon } from "@zolana/hasher";
import { SigningKey, ViewingKey, sha256Be, sha256Bytes } from "@zolana/keypair";

import certification from "../vectors/key-certification-v1.json" with { type: "json" };
import keypairParity from "../vectors/keypair-parity-v1.json" with { type: "json" };
import poseidonParity from "../vectors/poseidon-parity-v1.json" with { type: "json" };

function fromHex(value) {
  return Uint8Array.from((value.match(/../gu) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function check(failures, name, actual, expected) {
  if (actual === expected) return;
  failures.push({ name, actual, expected });
}

function checkHex(failures, name, actual, expected) {
  check(failures, name, toHex(actual), expected);
}

function runPoseidon(failures) {
  for (const vector of poseidonParity.vectors) {
    checkHex(
      failures,
      `poseidon/${vector.id}`,
      poseidon(vector.inputsBytes.map(fromHex)),
      vector.expectedBytes,
    );
  }
  for (const short of poseidonParity.shortInputs) {
    checkHex(
      failures,
      `poseidon-short/${short.id}`,
      poseidon([fromHex(short.shortBytes)]),
      short.expectedBytes,
    );
  }
}

function runSha256(failures) {
  const recorded = keypairParity.hashes;
  const preimage = fromHex(recorded.preimageBytes);
  checkHex(failures, "sha256Bytes", sha256Bytes(preimage), recorded.sha256Bytes);
  checkHex(failures, "sha256Be", sha256Be(preimage), recorded.sha256BeBytes);
}

// Viewing tags expand an HKDF-SHA-256 view root; a wrong digest or info string
// moves every tag byte.
function runHkdf(failures) {
  const recorded = keypairParity.viewingKeys;
  const viewing = ViewingKey.fromBytes(fromHex(recorded.secretBytes));
  const counterparty = ViewingKey.fromBytes(fromHex(recorded.counterpartySecretBytes));
  checkHex(failures, "hkdf/ecdh", viewing.ecdh(counterparty.publicKey()), recorded.ecdhBytes);
  for (const tags of recorded.tags) {
    const counter = BigInt(tags.counter);
    checkHex(
      failures,
      `hkdf/sender/${tags.counter}`,
      viewing.senderViewTag(counter),
      tags.senderBytes,
    );
    checkHex(
      failures,
      `hkdf/merge/${tags.counter}`,
      viewing.mergeViewTag(counter),
      tags.mergeBytes,
    );
    checkHex(
      failures,
      `hkdf/sendShared/${tags.counter}`,
      viewing.sendSharedViewTag(counterparty.publicKey(), counter),
      tags.sendSharedBytes,
    );
  }
  const derived = viewing.transactionViewingKey(fromHex(recorded.firstNullifierBytes));
  checkHex(
    failures,
    "hkdf/transactionViewingKey",
    derived.secretBytes(),
    recorded.transactionSecretBytes,
  );
}

function runAesCtr(failures) {
  const recorded = keypairParity.encryption;
  const sender = ViewingKey.fromBytes(fromHex(recorded.senderSecretBytes));
  const recipient = ViewingKey.fromBytes(fromHex(recorded.recipientSecretBytes));
  const salt = fromHex("5a".repeat(16));
  for (const entry of recorded.lengths) {
    const plaintext = fromHex(entry.plaintextBytes);
    const ciphertext = sender.encryptSlot(recipient.publicKey(), plaintext, salt, 3);
    checkHex(
      failures,
      `aes-ctr/encrypt/${String(entry.length)}`,
      ciphertext,
      entry.ciphertextBytes,
    );
    checkHex(
      failures,
      `aes-ctr/decrypt/${String(entry.length)}`,
      recipient.decryptUtxo(ciphertext, sender.publicKey(), salt, 3),
      entry.recoveredBytes,
    );
  }
}

function runEd25519(failures) {
  const recorded = certification.k3Ed25519Signatures;
  const signer = SigningKey.fromEd25519Bytes(fromHex(recorded.secretBytes));
  checkHex(
    failures,
    "ed25519/publicKey",
    signer.publicKey().toBytes(),
    recorded.taggedPublicKeyBytes,
  );
  for (const entry of recorded.messages) {
    const message = fromHex(entry.messageBytes);
    const signature = signer.sign(message);
    checkHex(
      failures,
      `ed25519/sign/${entry.messageBytes.length}`,
      signature,
      entry.signatureBytes,
    );
    check(
      failures,
      `ed25519/verify/${entry.messageBytes.length}`,
      signer.verify(message, fromHex(entry.signatureBytes)),
      entry.verified,
    );
  }
}

function runP256(failures) {
  const recorded = certification.k2P256Signatures;
  const signer = SigningKey.fromBytes(fromHex(recorded.keySecretBytes));
  for (const entry of recorded.digestSweep) {
    const digest = fromHex(entry.digestBytes);
    const signature = signer.sign(digest);
    checkHex(
      failures,
      `p256/sign/${entry.digestBytes.slice(0, 8)}`,
      signature,
      entry.signatureBytes,
    );
    check(
      failures,
      `p256/verify/${entry.digestBytes.slice(0, 8)}`,
      signer.verify(digest, signature),
      entry.verified,
    );
  }
}

export async function runBrowserRuntimeChecks() {
  const failures = [];
  await initializePoseidon();
  runPoseidon(failures);
  runSha256(failures);
  runHkdf(failures);
  runAesCtr(failures);
  runEd25519(failures);
  runP256(failures);
  return {
    ok: failures.length === 0,
    failures,
    checks: {
      poseidonVectors: poseidonParity.vectors.length,
      poseidonShortInputs: poseidonParity.shortInputs.length,
      sha256: 2,
      hkdfTags: keypairParity.viewingKeys.tags.length,
      aesCtrLengths: keypairParity.encryption.lengths.length,
      ed25519Messages: certification.k3Ed25519Signatures.messages.length,
      p256Digests: certification.k2P256Signatures.digestSweep.length,
    },
  };
}

globalThis.__zolanaBrowserRuntime = { run: runBrowserRuntimeChecks };
