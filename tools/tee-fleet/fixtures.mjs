// Fresh synthetic Nitro PKI for transport tests. These are not AWS attestations.
import { randomBytes } from "node:crypto";
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { gcm } from "@noble/ciphers/aes.js";
import { p384 } from "@noble/curves/nist.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  AlgorithmIdentifier,
  AttributeTypeAndValue,
  AttributeValue,
  BasicConstraints,
  Certificate,
  Extension,
  Extensions,
  Name,
  RelativeDistinguishedName,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
  id_ce_basicConstraints,
} from "@peculiar/asn1-x509";
import { Tagged, encode } from "cborg";
import { reportData } from "../../sdk-libs/ts/dist/client/prover/tee/verify.js";
import { requestAad } from "../../sdk-libs/ts/dist/client/prover/tee/encryption.js";
import { KEY_ID, PREFIX, recipientId } from "./gateway.mjs";

function cert(subject, issuer, publicKey, signer, ca) {
  const name = (value) =>
    new Name([
      new RelativeDistinguishedName([
        new AttributeTypeAndValue({
          type: "2.5.4.3",
          value: new AttributeValue({ utf8String: value }),
        }),
      ]),
    ]);
  const algorithm = () => new AlgorithmIdentifier({ algorithm: "1.2.840.10045.4.3.3" });
  const tbsCertificate = new TBSCertificate({
    version: Version.v3,
    serialNumber: Uint8Array.of(1).buffer,
    signature: algorithm(),
    issuer: name(issuer),
    subject: name(subject),
    validity: new Validity({
      notBefore: new Date(Date.now() - 3_600_000),
      notAfter: new Date(Date.now() + 3_600_000),
    }),
    subjectPublicKeyInfo: new SubjectPublicKeyInfo({
      algorithm: new AlgorithmIdentifier({
        algorithm: "1.2.840.10045.2.1",
        parameters: Uint8Array.of(6, 5, 43, 129, 4, 0, 34).buffer,
      }),
      subjectPublicKey: new Uint8Array(publicKey).buffer,
    }),
    extensions: new Extensions([
      new Extension({
        extnID: id_ce_basicConstraints,
        critical: true,
        extnValue: new OctetString(AsnConvert.serialize(new BasicConstraints({ cA: ca }))),
      }),
    ]),
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new Certificate({
        tbsCertificate,
        signatureAlgorithm: algorithm(),
        signatureValue: new Uint8Array(
          p384.sign(new Uint8Array(AsnConvert.serialize(tbsCertificate)), signer, {
            format: "der",
          }),
        ).buffer,
      }),
    ),
  );
}

export function fixtureAuthority() {
  const secret = p384.utils.randomSecretKey();
  const root = cert("fixture root", "fixture root", p384.getPublicKey(secret, false), secret, true);
  return {
    root,
    issuer() {
      const leaf = p384.utils.randomSecretKey();
      const certificate = cert(
        "fixture enclave",
        "fixture root",
        p384.getPublicKey(leaf, false),
        secret,
        false,
      );
      return (nonce, publicKey, measurements) => {
        const protectedHeader = encode(new Map([[1, -35]]));
        const payload = encode({
          module_id: "test-enclave",
          digest: "SHA384",
          timestamp: Date.now(),
          pcrs: new Map([
            [0, hexToBytes(measurements.pcr0)],
            [1, hexToBytes(measurements.pcr1)],
            [2, hexToBytes(measurements.pcr2)],
            [3, new Uint8Array(48)],
          ]),
          certificate,
          cabundle: [root],
          public_key: publicKey,
          nonce,
          user_data: reportData(nonce, publicKey, undefined),
        });
        const signed = encode(["Signature1", protectedHeader, new Uint8Array(), payload]);
        const document = encode(
          new Tagged(18, [protectedHeader, new Map(), payload, p384.sign(signed, leaf)]),
        );
        return {
          platform: "aws-nitro",
          hpke_public_key: bytesToHex(publicKey),
          gpu: null,
          evidence: { document: bytesToHex(document) },
        };
      };
    },
  };
}

export async function fixtureProver(authority, index) {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const keys = await suite.kem.generateKeyPair();
  const publicKey = new Uint8Array(await suite.kem.serializePublicKey(keys.publicKey));
  const id = recipientId(publicKey);
  const measurements = Object.fromEntries(
    [0, 1, 2].map((i) => [`pcr${i}`, (index * 3 + i + 1).toString(16).padStart(2, "0").repeat(48)]),
  );
  const quote = authority.issuer();
  const stats = { attestations: 0, decrypted: 0, failed: 0, requests: [], cancelled: 0 };
  const faults = { wrongNonce: false, delayMs: 0 };
  const handler = async (request, response) => {
    try {
      const url = new URL(request.url, "http://fixture.invalid");
      if (
        url.searchParams.has("api-key") ||
        request.headers.authorization ||
        request.headers["x-api-key"]
      )
        throw new Error("gateway leaked credential");
      if (url.pathname === `${PREFIX}/tee/v1/attestation`) {
        const nonce = hexToBytes(url.searchParams.get("nonce") ?? "");
        if (nonce.length !== 32) throw new Error("invalid nonce");
        stats.attestations++;
        if (faults.wrongNonce) nonce[0] ^= 1;
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify(quote(nonce, publicKey, measurements)));
        return;
      }
      if (request.headers[KEY_ID] !== id || request.headers["zolana-tee"] !== "v1")
        throw new Error("recipient missing or wrong");
      const enc = hexToBytes(request.headers["zolana-tee-enc"] ?? "");
      let ciphertext;
      if (request.method === "GET")
        ciphertext = hexToBytes(request.headers["zolana-tee-ciphertext"] ?? "");
      else {
        const chunks = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          if (size > 64 * 1024 * 1024 + 16) throw new Error("body limit");
          chunks.push(chunk);
        }
        ciphertext = Buffer.concat(chunks);
      }
      const context = await suite.createRecipientContext({
        recipientKey: keys.privateKey,
        enc,
        info: utf8ToBytes("zolana/prover-tee/v1"),
      });
      const plaintext = new Uint8Array(
        await context.open(ciphertext, utf8ToBytes(requestAad(request.method, request.url))),
      );
      stats.decrypted++;
      stats.requests.push({
        method: request.method,
        path: url.pathname,
        query: url.search,
        length: plaintext.length,
      });
      plaintext.fill(0);
      if (faults.delayMs) {
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, faults.delayMs);
          response.once("close", () => {
            clearTimeout(timer);
            stats.cancelled++;
            resolve();
          });
        });
        if (response.destroyed) return;
      }
      const key = new Uint8Array(
        await context.export(utf8ToBytes("zolana/prover-tee/v1/response"), 32),
      );
      const nonce = new Uint8Array(randomBytes(12));
      const body = utf8ToBytes(JSON.stringify({ status: `fixture-region-${index}`, circuits: [] }));
      const result = concatBytes(
        nonce,
        gcm(key, nonce).encrypt(concatBytes(Uint8Array.of(0, 200), body)),
      );
      key.fill(0);
      response.writeHead(200, { "content-type": "application/octet-stream", "zolana-tee": "v1" });
      response.end(result);
    } catch {
      stats.failed++;
      response.writeHead(400, { "content-type": "application/json" });
      response.end('{"code":"tee_request_malformed"}');
    }
  };
  return {
    handler,
    stats,
    faults,
    recipientId: id,
    policy: {
      platform: "aws-nitro",
      measurements: [measurements],
      hpke_public_key: bytesToHex(publicKey),
      gpu: "optional",
      max_age_secs: 600,
    },
  };
}
