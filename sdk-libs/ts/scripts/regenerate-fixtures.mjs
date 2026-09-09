// Recomputes the derivation-dependent fields in fixtures/transaction/*.json
// with the current library and rewrites fixtures/manifest.json. Run after a
// build: `npm run build && node scripts/regenerate-fixtures.mjs`.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  initializePoseidon,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../dist/keypair/index.js";
import { AssetRegistry, Data, SOL_MINT } from "../dist/transaction/index.js";
import {
  EncryptedScheme,
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  decodePlaintextTransfer,
  decodeProofless,
  decodeSplitBundle,
  decryptAnonymous,
  decryptConfidential,
  decryptSplit,
  encodeAnonymousRecipient,
  encodeAnonymousSender,
  encodeConfidential,
  encodeOutputData,
  encodePlaintextTransfer,
  encodeProofless,
  encodeSplitBundle,
  encryptAnonymous,
  encryptConfidential,
  encryptSplit,
} from "../dist/transaction/serialization/index.js";

const FIXTURES = new URL("../fixtures/", import.meta.url);

function readJson(name) {
  return JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
}

function writeJson(name, value) {
  writeFileSync(new URL(name, FIXTURES), `${JSON.stringify(value, null, 2)}\n`);
}

function bytes(value) {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function keypairFromInputs(inputs) {
  const signing = SigningKey.fromP256Bytes(bytes(inputs.signingSecretBytes));
  const viewing = ViewingKey.fromBytes(bytes(inputs.viewingSecretBytes));
  return { keypair: ShieldedKeypair.withViewingKey(signing, viewing), signing };
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/**
 * A golden holds only what the library produced and could read back: a
 * family whose re-encoded plaintext differs from the encoded bytes is a codec
 * defect, not a fixture to pin.
 */
function verifiedRoundTrip(name, encoded, reencoded) {
  if (!sameBytes(encoded, reencoded)) {
    throw new Error(`fixture family ${name} does not round-trip`);
  }
  return true;
}

await initializePoseidon();

const authority = readJson("transaction/authority-v1.json");
{
  const { keypair, signing } = keypairFromInputs(authority.inputs);
  const nullifierPubkey = hex(keypair.nullifierPublicKey());
  authority.expected.authority.nullifierPubkeyBytes = nullifierPubkey;
  authority.expected.authority.shieldedAddress.nullifierPubkeyBytes = nullifierPubkey;
  const signature = signing.sign(bytes(authority.inputs.messageHashBytes));
  authority.expected.p256Signature.rBytes = hex(signature.slice(0, 32));
  authority.expected.p256Signature.sBytes = hex(signature.slice(32));
  writeJson("transaction/authority-v1.json", authority);
}

const walletState = readJson("transaction/wallet-state-v1.json");
{
  const { keypair } = keypairFromInputs(walletState.inputs);
  const nullifierKey = keypair.nullifierKey();
  for (const row of walletState.inputs.walletUtxos) {
    row.nullifierBytes = hex(
      nullifierKey.nullifier(bytes(row.hashBytes), bytes(row.utxo.blindingBytes)),
    );
  }
  writeJson("transaction/wallet-state-v1.json", walletState);
}

// The plaintext families of transaction/test/serialization.test.ts, rebuilt
// through the public encoders and ciphers from the fixture inputs. The
// scenario constants (amounts, asset ids, slot indexes, the "codec" memo)
// mirror that test; every blinding is `TXOB(firstNullifier, outputSeed, slot)`
// and the seed-disclosing plaintexts carry the DERIVED output seed.
const serialization = readJson("transaction/serialization-v1.json");
{
  const { inputs } = serialization;
  const { keypair } = keypairFromInputs(inputs);
  const recipientViewing = ViewingKey.fromBytes(bytes(inputs.recipientViewingSecretBytes));
  const recipient = ShieldedKeypair.withViewingKey(
    SigningKey.fromP256Bytes(bytes(inputs.recipientSigningSecretBytes)),
    recipientViewing,
  );
  const tx = ViewingKey.fromBytes(bytes(inputs.txViewingSecretBytes));
  const salt = bytes(inputs.saltBytes);
  const firstNullifier = bytes(inputs.firstNullifierBytes);
  const outputSeed = outputBlindingSeed(firstNullifier, bytes(inputs.blindingSeedBytes));
  const blinding = (slot) => transactOutputBlinding(firstNullifier, outputSeed, slot);
  const data = new Data([{ kind: "memo", bytes: new TextEncoder().encode("codec") }]);
  const { families } = serialization.expected;

  const confidential = { assetId: 1n, amount: 55n, blinding: blinding(1), data };
  const confidentialBytes = encodeConfidential(confidential);
  const confidentialBody = encryptConfidential(
    tx,
    recipient.viewingPublicKey(),
    confidential,
    salt,
    0,
  );
  families.confidential.wincodeBytes = hex(confidentialBytes);
  families.confidential.encryptedBodyBytes = hex(confidentialBody);
  families.confidential.envelopeBorshBytes = hex(
    encodeOutputData(EncryptedScheme.confidential, confidentialBody, "encrypted"),
  );
  families.confidential.roundTripVerified = verifiedRoundTrip(
    "confidential",
    confidentialBytes,
    encodeConfidential(
      decryptConfidential(recipientViewing, tx.publicKey(), confidentialBody, salt, 0),
    ),
  );

  const anonymousRecipient = {
    ownerPublicKey: recipient.signingPublicKey(),
    senderPublicKey: keypair.viewingPublicKey(),
    assetId: 1n,
    amount: 19n,
    blinding: blinding(2),
    data,
  };
  const recipientBytes = encodeAnonymousRecipient(anonymousRecipient);
  const recipientBody = encryptAnonymous(tx, recipient.viewingPublicKey(), recipientBytes, salt, 1);
  families.anonymousRecipient.wincodeBytes = hex(recipientBytes);
  families.anonymousRecipient.encryptedBodyBytes = hex(recipientBody);
  families.anonymousRecipient.envelopeBorshBytes = hex(
    encodeOutputData(EncryptedScheme.anonymousRecipient, recipientBody, "encrypted"),
  );
  families.anonymousRecipient.roundTripVerified = verifiedRoundTrip(
    "anonymousRecipient",
    recipientBytes,
    encodeAnonymousRecipient(
      decodeAnonymousRecipient(
        decryptAnonymous(recipientViewing, tx.publicKey(), recipientBody, salt, 1),
      ),
    ),
  );

  const anonymousSender = {
    ownerPublicKey: keypair.signingPublicKey(),
    splAssetId: 0n,
    splAmount: 0n,
    solAmount: 36n,
    blindingSeed: outputSeed,
    recipientViewingPublicKeys: [recipient.viewingPublicKey()],
    splData: new Data(),
    solData: data,
  };
  const senderBytes = encodeAnonymousSender(anonymousSender);
  const senderBody = encryptAnonymous(tx, keypair.viewingPublicKey(), senderBytes, salt, 2);
  families.anonymousSender.wincodeBytes = hex(senderBytes);
  families.anonymousSender.encryptedBodyBytes = hex(senderBody);
  families.anonymousSender.envelopeBorshBytes = hex(
    encodeOutputData(EncryptedScheme.anonymousSender, senderBody, "encrypted"),
  );
  families.anonymousSender.roundTripVerified = verifiedRoundTrip(
    "anonymousSender",
    senderBytes,
    encodeAnonymousSender(
      decodeAnonymousSender(
        decryptAnonymous(keypair.viewingKey(), tx.publicKey(), senderBody, salt, 2),
      ),
    ),
  );

  const split = {
    ownerPublicKey: keypair.signingPublicKey(),
    numOutputs: 3,
    assetId: 1n,
    assetAmount: 12n,
    blindingSeed: outputSeed,
    data,
  };
  const splitBytes = encodeSplitBundle(split);
  const splitBody = encryptSplit(tx, keypair.viewingPublicKey(), splitBytes, salt, 3);
  families.split.wincodeBytes = hex(splitBytes);
  families.split.encryptedBodyBytes = hex(splitBody);
  families.split.envelopeBorshBytes = hex(
    encodeOutputData(EncryptedScheme.split, splitBody, "encrypted"),
  );
  families.split.roundTripVerified = verifiedRoundTrip(
    "split",
    splitBytes,
    encodeSplitBundle(
      decodeSplitBundle(decryptSplit(keypair.viewingKey(), tx.publicKey(), splitBody, salt, 3)),
    ),
  );

  const plaintextTransfer = {
    typePrefix: 4,
    blindingSeed: outputSeed,
    sender: {
      ownerPublicKey: keypair.signingPublicKey(),
      spl: { amount: 7n, assetId: 1n },
      solAmount: 8n,
      splData: new Data(),
      solData: data,
    },
    recipientSlots: [
      { ownerPublicKey: recipient.signingPublicKey(), assetId: 1n, amount: 9n, data },
    ],
  };
  const plaintextBytes = encodePlaintextTransfer(plaintextTransfer);
  families.plaintextTransfer.wincodeBytes = hex(plaintextBytes);
  families.plaintextTransfer.envelopeBorshBytes = hex(
    encodeOutputData(EncryptedScheme.plaintextTransfer, plaintextBytes, "plaintext"),
  );
  families.plaintextTransfer.roundTripVerified = verifiedRoundTrip(
    "plaintextTransfer",
    plaintextBytes,
    encodePlaintextTransfer(decodePlaintextTransfer(plaintextBytes, 4)),
  );

  const proofless = {
    owner: keypair.shieldedAddress().ownerHash(),
    blinding: blinding(4),
    asset: SOL_MINT,
    amount: 33n,
  };
  const prooflessBytes = encodeProofless(proofless);
  families.proofless.borshBytes = hex(prooflessBytes);
  families.proofless.envelopeBorshBytes = hex(
    encodeOutputData(EncryptedScheme.proofless, prooflessBytes, "plaintext"),
  );
  families.proofless.roundTripVerified = verifiedRoundTrip(
    "proofless",
    prooflessBytes,
    encodeProofless(decodeProofless(prooflessBytes)),
  );

  // The registry is unused by the encoders above; it is constructed so a
  // fixture consumer resolving asset id 1 gets the same SOL mint the test does.
  if (new AssetRegistry().resolve(1n) !== SOL_MINT) {
    throw new Error("asset id 1 must resolve to the SOL mint");
  }
  writeJson("transaction/serialization-v1.json", serialization);
}

const manifest = readJson("manifest.json");
for (const entry of manifest.files) {
  const text = readFileSync(new URL(entry.path, FIXTURES), "utf8");
  entry.sha256 = createHash("sha256").update(text, "utf8").digest("hex");
}
writeJson("manifest.json", manifest);

console.log("fixtures regenerated");
