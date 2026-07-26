import type { Bytes32, Bytes64, Bytes128, TransactProof } from "@zolana/interface";

import { ClientError } from "../error.js";
import { bigintToBytes, bytesToBigInt, checkedBytes } from "../internal.js";
import type { CompressedProof, P256Proof, Proof } from "./types.js";

const BN254_BASE_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583n;

export function compressProof(proof: Proof): CompressedProof {
  const a = compressG1(checkedBytes(proof.a, 64, "proof.a"), "proof.a");
  const b = compressG2(checkedBytes(proof.b, 128, "proof.b"));
  const c = compressG1(checkedBytes(proof.c, 64, "proof.c"), "proof.c");
  const commitment =
    proof.commitment === undefined
      ? undefined
      : Object.freeze({
          commitment: compressG1(
            checkedBytes(proof.commitment.commitment, 64, "proof.commitment"),
            "proof.commitment",
          ),
          commitmentPok: compressG1(
            checkedBytes(proof.commitment.commitmentPok, 64, "proof.commitmentPok"),
            "proof.commitmentPok",
          ),
        });
  return compressedProof({ a, b, c, ...(commitment === undefined ? {} : { commitment }) });
}

export function compressedProof(
  input: Readonly<{
    a: Uint8Array;
    b: Uint8Array;
    c: Uint8Array;
    commitment?: Readonly<{ commitment: Uint8Array; commitmentPok: Uint8Array }>;
  }>,
): CompressedProof {
  const a = checkedBytes(input.a, 32, "proof.a");
  const b = checkedBytes(input.b, 64, "proof.b");
  const c = checkedBytes(input.c, 32, "proof.c");
  const commitment =
    input.commitment === undefined
      ? undefined
      : Object.freeze({
          commitment: checkedBytes(input.commitment.commitment, 32, "proof.commitment"),
          commitmentPok: checkedBytes(input.commitment.commitmentPok, 32, "proof.commitmentPok"),
        });
  const p256Proof = (): P256Proof => {
    if (commitment === undefined) {
      throw new ClientError("CLIENT_PROOF_PARSE", {
        details: { path: "$.proof.proof_commitment" },
      });
    }
    return Object.freeze({
      a: new Uint8Array(a) as Bytes32,
      b: new Uint8Array(b) as Bytes64,
      c: new Uint8Array(c) as Bytes32,
      commitment: new Uint8Array(commitment.commitment) as Bytes32,
      commitmentPok: new Uint8Array(commitment.commitmentPok) as Bytes32,
    });
  };
  return Object.freeze({
    a,
    b,
    c,
    ...(commitment === undefined ? {} : { commitment }),
    toTransactProof(): TransactProof {
      if (commitment === undefined) {
        return Object.freeze({
          rail: "eddsa",
          a: new Uint8Array(a) as Bytes32,
          b: new Uint8Array(b) as Bytes64,
          c: new Uint8Array(c) as Bytes32,
        });
      }
      return Object.freeze({ rail: "p256", ...p256Proof() });
    },
    toP256Proof: p256Proof,
    toMergeProof: p256Proof,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function parseProof(value: unknown, requireCommitment: boolean): Proof {
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
  const hasCommitment =
    present(proof["proof_commitment"]) || present(proof["proof_commitment_pok"]);
  if (requireCommitment !== hasCommitment) {
    throw new ClientError("CLIENT_PROOF_RAIL_MISMATCH", {
      details: { expected: requireCommitment ? "p256" : "eddsa" },
    });
  }
  const commitment = hasCommitment
    ? Object.freeze({
        commitment: parseG1(proof["proof_commitment"], "$.proof.proof_commitment"),
        commitmentPok: parseG1(proof["proof_commitment_pok"], "$.proof.proof_commitment_pok"),
      })
    : undefined;
  return Object.freeze({
    a: a as Bytes64,
    b,
    c,
    ...(commitment === undefined ? {} : { commitment }),
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
  // gnark writes the c1 component of each Fq2 coordinate first, so the layout
  // is x.c1 || x.c0 || y.c1 || y.c0. Only the sign of y is read here, and the
  // range check above is the same one `alt_bn128_g2_compress_be` performs, so
  // an off-curve point is left for the on-chain verifier to reject.
  const [, , y1, y0] = values;
  if (y0 === undefined || y1 === undefined) {
    throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
  }
  const result = new Uint8Array(point.subarray(0, 64)) as Bytes64;
  // Fq2 orders on c1, so c0 only decides the sign when c1 ties with its own
  // negation, which happens only at zero.
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

/// Rust reads the two commitment fields as `#[serde(default)] Vec<String>` and
/// decides the rail on `is_empty()`, so an explicit `[]` means "no commitment"
/// there. Treat it the same rather than reading a present-but-empty array as a
/// commitment and failing the rail check.
function present(value: unknown): boolean {
  return value !== undefined && !(Array.isArray(value) && value.length === 0);
}

function asObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid(path);
  return value as Record<string, unknown>;
}

function asArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) invalid(path);
  return value;
}

function invalid(path: string): never {
  throw new ClientError("CLIENT_PROOF_PARSE", { details: { path } });
}
