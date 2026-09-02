import { bn254 } from "@noble/curves/bn254.js";

import { wireDecoder } from "../../interface/decode.js";
import type { Bytes32, Bytes64, Bytes128, TransactProof } from "../../interface/types.js";

import { ClientError } from "../error.js";
import { bigintToBytes, bytesToBigInt, checkedBytes } from "../internal.js";
import type { CompressedProof, Proof } from "./types.js";

const BN254_BASE_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583n;

export const CUSTOM_RING_PROOF_LENGTH = 192;

export function compressProof(proof: Proof): CompressedProof {
  const a = compressG1(checkedBytes(proof.a, 64, "proof.a"), "proof.a");
  const b = compressG2(checkedBytes(proof.b, 128, "proof.b"));
  const c = compressG1(checkedBytes(proof.c, 64, "proof.c"), "proof.c");
  if (proof.commitment === undefined || proof.commitmentPok === undefined) {
    return compressedProof({ a, b, c });
  }
  return compressedProof({
    a,
    b,
    c,
    commitment: compressG1(
      checkedBytes(proof.commitment, 64, "proof.commitment"),
      "proof.commitment",
    ),
    commitmentPok: compressG1(
      checkedBytes(proof.commitmentPok, 64, "proof.commitmentPok"),
      "proof.commitmentPok",
    ),
  });
}

export function compressedProof(
  input: Readonly<{
    a: Uint8Array;
    b: Uint8Array;
    c: Uint8Array;
    commitment?: Uint8Array;
    commitmentPok?: Uint8Array;
  }>,
): CompressedProof {
  const a = checkedBytes(input.a, 32, "proof.a");
  const b = checkedBytes(input.b, 64, "proof.b");
  const c = checkedBytes(input.c, 32, "proof.c");
  const commitment =
    input.commitment === undefined
      ? undefined
      : checkedBytes(input.commitment, 32, "proof.commitment");
  const commitmentPok =
    input.commitmentPok === undefined
      ? undefined
      : checkedBytes(input.commitmentPok, 32, "proof.commitmentPok");
  return Object.freeze({
    a,
    b,
    c,
    ...(commitment === undefined ? {} : { commitment }),
    ...(commitmentPok === undefined ? {} : { commitmentPok }),
    toTransactProof(): TransactProof {
      return Object.freeze({
        a: new Uint8Array(a) as Bytes32,
        b: new Uint8Array(b) as Bytes64,
        c: new Uint8Array(c) as Bytes32,
      });
    },
    toCustomRingProof(): Uint8Array {
      if (commitment === undefined || commitmentPok === undefined) {
        throw new ClientError("CLIENT_PROOF_PARSE", {
          details: { path: "$.proof.proofCommitment", reason: "missing commitment" },
        });
      }
      const bytes = new Uint8Array(CUSTOM_RING_PROOF_LENGTH);
      bytes.set(a, 0);
      bytes.set(b, 32);
      bytes.set(c, 96);
      bytes.set(commitment, 128);
      bytes.set(commitmentPok, 160);
      return bytes;
    },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function parseProof(value: unknown): Proof {
  // Rust unwraps before it validates: `proof_from_value` reads `proof` off
  // whatever it was handed, falling back to the whole value, and only then
  // separates a proof the server declined to send from one it sent badly. A null
  // is `ProverServer`; anything with bytes in it can still be `ProofParse`.
  // Validating the envelope first turned an absent proof into a malformed one.
  const proofValue = isRecord(value) && Object.hasOwn(value, "proof") ? value["proof"] : value;
  if (proofValue === null) {
    throw new ClientError("CLIENT_PROVER_SERVER", { details: { reason: "null proof" } });
  }
  const proof = asObject(proofValue, "$.proof");
  const aRaw = parseG1(proof["ar"], "$.proof.ar");
  const a = new Uint8Array(aRaw);
  const y = bytesToBigInt(a.subarray(32));
  a.set(bigintToBytes(y === 0n ? 0n : BN254_BASE_MODULUS - y), 32);
  const b = parseG2(proof["bs"], "$.proof.bs");
  const c = parseG1(proof["krs"], "$.proof.krs");
  if (!present(proof["proofCommitment"]) && !present(proof["proofCommitmentPok"])) {
    return Object.freeze({ a: a as Bytes64, b, c });
  }
  return Object.freeze({
    a: a as Bytes64,
    b,
    c,
    commitment: parseG1(proof["proofCommitment"], "$.proof.proofCommitment"),
    commitmentPok: parseG1(proof["proofCommitmentPok"], "$.proof.proofCommitmentPok"),
  });
}

function compressG1(point: Bytes64, name: string): Bytes32 {
  const x = bytesToBigInt(point.subarray(0, 32));
  const y = bytesToBigInt(point.subarray(32));
  if (x === 0n && y === 0n) return new Uint8Array(32) as Bytes32;
  validateG1(x, y, name);
  const result = bigintToBytes(x);
  if (isLargest(y)) result[0] = (result[0] ?? 0) | 0x80;
  return result as Bytes32;
}

function compressG2(point: Bytes128): Bytes64 {
  const values = [0, 32, 64, 96].map((offset) =>
    bytesToBigInt(point.subarray(offset, offset + 32)),
  );
  if (values.some((value) => value >= BN254_BASE_MODULUS)) {
    throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
  }
  if (values.every((value) => value === 0n)) return new Uint8Array(64) as Bytes64;
  // Solana's big-endian G2 encoding stores each Fq2 value as c1 || c0.
  // Noble names the components in field order, so swap each pair only while
  // validating; the compressed wire value keeps the original x bytes.
  const [x1, x0, y1, y0] = values;
  if (x0 === undefined || x1 === undefined || y0 === undefined || y1 === undefined) {
    throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
  }
  try {
    bn254.G2.Point.fromAffine({
      x: { c0: x0, c1: x1 },
      y: { c0: y0, c1: y1 },
    }).assertValidity();
  } catch {
    throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
  }
  const result = new Uint8Array(point.subarray(0, 64)) as Bytes64;
  if (isLargest(y1) || (y1 === 0n && isLargest(y0))) {
    result[0] = (result[0] ?? 0) | 0x80;
  }
  return result;
}

function validateG1(x: bigint, y: bigint, name: string): void {
  if (
    x >= BN254_BASE_MODULUS ||
    y >= BN254_BASE_MODULUS ||
    (y * y - ((x * x) % BN254_BASE_MODULUS) * x - 3n) % BN254_BASE_MODULUS !== 0n
  ) {
    throw new ClientError("CLIENT_PROOF_POINT", { details: { field: name } });
  }
}

function isLargest(value: bigint): boolean {
  return value > (BN254_BASE_MODULUS - 1n) / 2n;
}

function parseG1(value: unknown, path: string): Bytes64 {
  const coordinates = asArray(value, path);
  if (coordinates.length !== 2) invalid(path);
  const x = parseCoordinate(coordinates[0], `${path}[0]`);
  const y = parseCoordinate(coordinates[1], `${path}[1]`);
  if (x !== 0n || y !== 0n) validateG1(x, y, path);
  const result = new Uint8Array(64);
  result.set(bigintToBytes(x));
  result.set(bigintToBytes(y), 32);
  return result as Bytes64;
}

function parseG2(value: unknown, path: string): Bytes128 {
  const rows = asArray(value, path);
  if (rows.length !== 2) invalid(path);
  const coordinates = rows.flatMap((row, rowIndex) => {
    const values = asArray(row, `${path}[${String(rowIndex)}]`);
    if (values.length !== 2) invalid(`${path}[${String(rowIndex)}]`);
    return values.map((item, index) =>
      parseCoordinate(item, `${path}[${String(rowIndex)}][${String(index)}]`),
    );
  });
  const result = new Uint8Array(128);
  coordinates.forEach((coordinate, index) => {
    result.set(bigintToBytes(coordinate), index * 32);
  });
  return result as Bytes128;
}

/// The prover writes every coordinate as `0x%064x`, but the Rust parser reads
/// it through `BigInt::from_str_radix(trim_start_matches("0x"), 16)`, which
/// takes the same digits with the prefix left off. Accept both so a producer
/// the Rust client handles is not rejected here; the digits are always read as
/// hexadecimal, prefix or not, exactly as Rust reads them.
function parseCoordinate(value: unknown, path: string): bigint {
  if (typeof value !== "string") invalid(path);
  const digits = /^0[xX]/u.test(value) ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]+$/u.test(digits)) invalid(path);
  const result = BigInt(`0x${digits}`);
  if (result >= BN254_BASE_MODULUS) invalid(path);
  return result;
}

/// Rust reads both commitment fields as `#[serde(default)] Vec<String>`, an explicit `[]` is absent.
function present(value: unknown): boolean {
  return value !== undefined && !(Array.isArray(value) && value.length === 0);
}

const invalidResponse = (path: string): ClientError =>
  new ClientError("CLIENT_PROOF_PARSE", { details: { path } });

const { record: asObject, list: asArray } = wireDecoder(invalidResponse);

function invalid(path: string): never {
  throw invalidResponse(path);
}
