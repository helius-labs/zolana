import { p384 } from "@noble/curves/nist.js";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { AsnConvert } from "@peculiar/asn1-schema";
import {
  BasicConstraints,
  Certificate,
  KeyUsage,
  KeyUsageFlags,
  id_ce_basicConstraints,
  id_ce_keyUsage,
} from "@peculiar/asn1-x509";
import {
  Tokenizer,
  Type,
  decode as decodeCbor,
  encode as encodeCbor,
  type DecodeOptions,
} from "cborg";

import {
  evidenceBytes,
  evidenceDecode as decode,
  refused,
  type AttestationClaims,
  type GpuRequirement,
  type PlatformModule,
  type PlatformVerdict,
} from "./platform.js";

const COSE_SIGN1_TAG = 18;
const COSE_ALG = 1;
const ES384 = -35;
const ECDSA_SHA384 = "1.2.840.10045.4.3.3";
const EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const SECP384R1 = Uint8Array.of(0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22);
const PCR_SIZE = 48;
const MAX_PCR_INDEX = 31;
const MAX_DOCUMENT_ENTRIES = 16;
const MAX_PCRS = 32;
const MAX_CABUNDLE = 8;
const MAX_DEPTH = 16;
/** Seconds a certificate's notBefore may lead the local clock. */
const NOT_BEFORE_SKEW_SECS = 300;
const CBOR: DecodeOptions = Object.freeze({
  useMaps: true,
  rejectDuplicateMapKeys: true,
  allowUndefined: false,
  // The Nitro Secure Module emits an indefinite map.
  allowIndefinite: true,
  allowBigInt: false,
});
const UTF8 = new TextDecoder("utf-8", { fatal: true });

/** Lowercase hex. */
export type NitroMeasurement = Readonly<{
  pcr0: string;
  pcr1: string;
  pcr2: string;
}>;

export type AwsNitroPolicy = Readonly<{
  platform: "aws-nitro";
  measurements: readonly NitroMeasurement[];
  gpu: GpuRequirement;
  maxAgeSecs: number;
}>;

type CoseSign1 = Readonly<{
  protectedHeader: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
}>;

type NitroDocument = Readonly<{
  digest: string;
  pcrs: ReadonlyMap<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: readonly Uint8Array[];
  publicKey: Uint8Array | undefined;
  userData: Uint8Array | undefined;
  nonce: Uint8Array | undefined;
}>;

type ParsedCertificate = Readonly<{
  tbs: Uint8Array;
  signature: Uint8Array;
  publicKey: Uint8Array;
  subject: Uint8Array;
  issuer: Uint8Array;
  notBefore: number;
  notAfter: number;
  basicConstraints: BasicConstraints | undefined;
  keyUsage: KeyUsage | undefined;
}>;

const AWS_NITRO_ROOT_G1 = hexToBytes(
  "3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d040303" +
    "3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c0341" +
    "5753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d313931303238313332" +
    "3830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c" +
    "06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e" +
    "636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90" +
    "be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66" +
    "e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f" +
    "0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df" +
    "4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9" +
    "bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf30231" +
    "00a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d" +
    "2302f3dff6",
);

export const AWS_NITRO: PlatformModule<AwsNitroPolicy> = Object.freeze({
  platform: "aws-nitro",
  hostsGpu: false,
  keyPerBoot: true,
  anchors: Object.freeze([AWS_NITRO_ROOT_G1]),
  policy: (fields, common) =>
    Object.freeze({
      platform: "aws-nitro",
      measurements: fields.records("measurements", (m) =>
        Object.freeze({
          pcr0: m.hex("pcr0", PCR_SIZE),
          pcr1: m.hex("pcr1", PCR_SIZE),
          pcr2: m.hex("pcr2", PCR_SIZE),
        }),
      ),
      ...common,
    }),
  pinsJson: (policy) => ({ measurements: policy.measurements }),
  verify: verifyAwsNitro,
});

/** Accepts only a document of an allowed image signed through a chain to `anchors` at `claims.nowSecs`. */
function verifyAwsNitro(
  json: unknown,
  policy: AwsNitroPolicy,
  claims: AttestationClaims,
  anchors: readonly Uint8Array[],
): PlatformVerdict {
  const evidence = decode.record(json, "evidence");
  const { protectedHeader, payload, signature } = coseSign1(
    evidenceBytes(evidence["document"], "document"),
  );
  const document = documentOf(payload);
  const leafKey = chainedLeafKey(document, anchors, claims.nowSecs);
  const signed = encodeCbor(["Signature1", protectedHeader, new Uint8Array(0), payload]);
  if (!ecdsaP384(signature, signed, leafKey, "compact")) throw refused("signature");

  if (document.digest !== "SHA384") throw refused("digest");
  const pcr0 = pcr(document, 0);
  if (pcr0.every((byte) => byte === 0)) throw refused("debug_enclave");
  const pcrs = [pcr0, pcr(document, 1), pcr(document, 2)].map(bytesToHex);
  if (!policy.measurements.some((m) => [m.pcr0, m.pcr1, m.pcr2].every((v, i) => v === pcrs[i]))) {
    throw refused("measurement");
  }

  if (document.nonce === undefined || !equalBytes(document.nonce, claims.nonce)) {
    throw refused("nonce");
  }
  if (document.publicKey === undefined || !equalBytes(document.publicKey, claims.hpkePublicKey)) {
    throw refused("public_key");
  }
  if (document.userData === undefined) throw refused("report_data");
  return Object.freeze({ reportData: document.userData, imageId: pcr0 });
}

function coseSign1(bytes: Uint8Array): CoseSign1 {
  const message = list(cbor(bytes, COSE_SIGN1_TAG));
  const [protectedHeader, unprotectedHeader, payload, signature] = message;
  if (message.length !== 4) throw malformed();
  const header = map(cbor(byteString(protectedHeader)));
  map(unprotectedHeader);
  if (header.get(COSE_ALG) !== ES384) throw refused("alg");
  return Object.freeze({
    protectedHeader: byteString(protectedHeader),
    payload: byteString(payload),
    signature: byteString(signature),
  });
}

function documentOf(payload: Uint8Array): NitroDocument {
  const document = map(cbor(payload));
  if (document.size > MAX_DOCUMENT_ENTRIES) throw malformed();
  const optional = (field: string): Uint8Array | undefined => {
    const value: unknown = document.get(field);
    return value === undefined || value === null ? undefined : byteString(value);
  };
  const moduleId: unknown = document.get("module_id");
  if (typeof moduleId !== "string" || moduleId === "") throw malformed();
  const timestamp: unknown = document.get("timestamp");
  if (typeof timestamp !== "number" || !Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw malformed();
  }
  const digest: unknown = document.get("digest");
  if (typeof digest !== "string") throw malformed();
  const pcrEntries = map(document.get("pcrs"));
  if (pcrEntries.size > MAX_PCRS) throw malformed();
  const cabundle = list(document.get("cabundle"));
  if (cabundle.length > MAX_CABUNDLE) throw malformed();
  const pcrs = new Map<number, Uint8Array>();
  for (const [index, value] of pcrEntries) {
    if (
      typeof index !== "number" ||
      !Number.isInteger(index) ||
      index < 0 ||
      index > MAX_PCR_INDEX
    ) {
      throw malformed();
    }
    pcrs.set(index, byteString(value));
  }
  return Object.freeze({
    digest,
    pcrs,
    certificate: byteString(document.get("certificate")),
    cabundle: Object.freeze(cabundle.map(byteString)),
    publicKey: optional("public_key"),
    userData: optional("user_data"),
    nonce: optional("nonce"),
  });
}

function chainedLeafKey(
  document: NitroDocument,
  anchors: readonly Uint8Array[],
  nowSecs: number,
): Uint8Array {
  const [root] = document.cabundle;
  if (root === undefined || !anchors.some((anchor) => equalBytes(anchor, root))) {
    throw refused("root");
  }
  const chain = [document.certificate, ...document.cabundle.toReversed()].map(certificateOf);
  chain.forEach((certificate, index) => {
    if (nowSecs + NOT_BEFORE_SKEW_SECS < certificate.notBefore || nowSecs > certificate.notAfter) {
      throw refused("certificate_validity");
    }
    const issuer = chain[index + 1];
    if (issuer === undefined) return;
    const constraints = issuer.basicConstraints;
    if (constraints?.cA !== true) throw refused("certificate_chain");
    if (constraints.pathLenConstraint !== undefined && constraints.pathLenConstraint < index) {
      throw refused("certificate_chain");
    }
    if (!permits(issuer.keyUsage, KeyUsageFlags.keyCertSign)) throw refused("certificate_chain");
    if (
      !equalBytes(certificate.issuer, issuer.subject) ||
      !ecdsaP384(certificate.signature, certificate.tbs, issuer.publicKey, "der")
    ) {
      throw refused("certificate_chain");
    }
  });
  const [leaf] = chain;
  if (leaf === undefined || !permits(leaf.keyUsage, KeyUsageFlags.digitalSignature)) {
    throw refused("certificate_chain");
  }
  return leaf.publicKey;
}

/** An absent key usage permits every use. */
function permits(usage: KeyUsage | undefined, flag: KeyUsageFlags): boolean {
  return usage === undefined || (usage.toNumber() & flag) !== 0;
}

/** Accepts only canonical DER with ECDSA P-384 SHA-384 keys and signatures. */
function certificateOf(der: Uint8Array): ParsedCertificate {
  let certificate: Certificate;
  try {
    certificate = AsnConvert.parse(der, Certificate);
    if (!equalBytes(new Uint8Array(AsnConvert.serialize(certificate)), der)) throw malformed();
  } catch {
    throw refused("certificate_chain");
  }
  const tbs = certificate.tbsCertificate;
  const key = tbs.subjectPublicKeyInfo;
  const parameters = key.algorithm.parameters;
  if (
    certificate.tbsCertificateRaw === undefined ||
    certificate.signatureAlgorithm.algorithm !== ECDSA_SHA384 ||
    certificate.signatureAlgorithm.parameters != null ||
    tbs.signature.algorithm !== ECDSA_SHA384 ||
    tbs.signature.parameters != null ||
    key.algorithm.algorithm !== EC_PUBLIC_KEY ||
    parameters == null ||
    !equalBytes(new Uint8Array(parameters), SECP384R1)
  ) {
    throw refused("certificate_chain");
  }
  let basicConstraints: BasicConstraints | undefined;
  let keyUsage: KeyUsage | undefined;
  for (const extension of tbs.extensions ?? []) {
    try {
      if (extension.extnID === id_ce_basicConstraints) {
        basicConstraints = AsnConvert.parse(extension.extnValue.buffer, BasicConstraints);
      } else if (extension.extnID === id_ce_keyUsage) {
        keyUsage = AsnConvert.parse(extension.extnValue.buffer, KeyUsage);
      } else if (extension.critical) {
        throw malformed();
      }
    } catch {
      throw refused("certificate_chain");
    }
  }
  return Object.freeze({
    tbs: new Uint8Array(certificate.tbsCertificateRaw),
    signature: new Uint8Array(certificate.signatureValue),
    publicKey: new Uint8Array(key.subjectPublicKey),
    subject: new Uint8Array(AsnConvert.serialize(tbs.subject)),
    issuer: new Uint8Array(AsnConvert.serialize(tbs.issuer)),
    notBefore: Math.floor(tbs.validity.notBefore.getTime().getTime() / 1000),
    notAfter: Math.floor(tbs.validity.notAfter.getTime().getTime() / 1000),
    basicConstraints,
    keyUsage,
  });
}

function ecdsaP384(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
  format: "compact" | "der",
): boolean {
  try {
    return p384.verify(signature, message, publicKey, { format, lowS: false });
  } catch {
    return false;
  }
}

function pcr(document: NitroDocument, index: number): Uint8Array {
  const value = document.pcrs.get(index);
  if (value?.length !== PCR_SIZE) throw malformed();
  return value;
}

function cbor(bytes: Uint8Array, outerTag?: number): unknown {
  const tags = outerTag === undefined ? {} : { [outerTag]: (content: () => unknown) => content() };
  try {
    scan(bytes, outerTag);
    const value: unknown = decodeCbor(bytes, { ...CBOR, tags });
    comparableKeys(value);
    return value;
  } catch {
    throw malformed();
  }
}

/** Admits one item in the CBOR subset both SDKs read alike. */
function scan(bytes: Uint8Array, outerTag: number | undefined): void {
  const tokens = new Tokenizer(bytes, { ...CBOR, retainStringBytes: true });
  // Items left in each open array or map, Infinity while indefinite.
  const open: number[] = [];
  for (;;) {
    const leading = tokens.pos() === 0;
    const token = tokens.next();
    switch (token.type) {
      case Type.tag:
        if (leading && token.value === outerTag) continue;
        throw malformed();
      case Type.uint:
      case Type.negint:
        if (!Number.isSafeInteger(token.value)) throw malformed();
        break;
      case Type.string:
        UTF8.decode(token.byteValue);
        break;
      case Type.bytes:
      case Type.false:
      case Type.true:
      case Type.null:
        break;
      case Type.array:
      case Type.map: {
        const items = token.type === Type.map ? 2 * token.value : token.value;
        if (items === 0) break;
        open.push(items);
        if (open.length > MAX_DEPTH) throw malformed();
        continue;
      }
      case Type.break:
        if (open.pop() !== Infinity) throw malformed();
        break;
      default:
        throw malformed();
    }
    if (closes(open)) {
      if (!tokens.done()) throw malformed();
      return;
    }
  }
}

/** True once the outermost item finishes. */
function closes(open: number[]): boolean {
  for (;;) {
    const left = open.pop();
    if (left === undefined) return true;
    if (left > 1) {
      open.push(left - 1);
      return false;
    }
  }
}

/** cborg finds a repeated key only among text and integer keys. */
function comparableKeys(value: unknown): void {
  if (value instanceof Map) {
    for (const [key, entry] of value) {
      if (typeof key !== "string" && typeof key !== "number") throw malformed();
      comparableKeys(entry);
    }
  } else if (Array.isArray(value)) {
    value.forEach(comparableKeys);
  }
}

function map(value: unknown): ReadonlyMap<unknown, unknown> {
  if (!(value instanceof Map)) throw malformed();
  return value;
}

function list(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) throw malformed();
  return value;
}

function byteString(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw malformed();
  return value;
}

const malformed = (): Error => refused("malformed_attestation");
