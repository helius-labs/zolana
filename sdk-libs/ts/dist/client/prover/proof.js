import { bn254 } from "@noble/curves/bn254.js";
import { ClientError } from "../error.js";
import { bigintToBytes, bytesToBigInt, checkedBytes } from "../internal.js";
const BN254_BASE_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export function compressProof(proof) {
    const a = compressG1(checkedBytes(proof.a, 64, "proof.a"), "proof.a");
    const b = compressG2(checkedBytes(proof.b, 128, "proof.b"));
    const c = compressG1(checkedBytes(proof.c, 64, "proof.c"), "proof.c");
    return compressedProof({ a, b, c });
}
export function compressedProof(input) {
    const a = checkedBytes(input.a, 32, "proof.a");
    const b = checkedBytes(input.b, 64, "proof.b");
    const c = checkedBytes(input.c, 32, "proof.c");
    return Object.freeze({
        a,
        b,
        c,
        toTransactProof() {
            return Object.freeze({
                a: new Uint8Array(a),
                b: new Uint8Array(b),
                c: new Uint8Array(c),
            });
        },
    });
}
function isRecord(value) {
    return typeof value === "object" && value !== null;
}
export function parseProof(value) {
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
    const hasCommitment = present(proof["proof_commitment"]) || present(proof["proof_commitment_pok"]);
    if (hasCommitment) {
        throw new ClientError("CLIENT_PROOF_PARSE", {
            details: { path: "$.proof.proof_commitment", reason: "unsupported commitment proof" },
        });
    }
    return Object.freeze({
        a: a,
        b,
        c,
    });
}
function compressG1(point, name) {
    const x = bytesToBigInt(point.subarray(0, 32));
    const y = bytesToBigInt(point.subarray(32));
    if (x === 0n && y === 0n)
        return new Uint8Array(32);
    validateG1(x, y, name);
    const result = bigintToBytes(x);
    if (isLargest(y))
        result[0] = (result[0] ?? 0) | 0x80;
    return result;
}
function compressG2(point) {
    const values = [0, 32, 64, 96].map((offset) => bytesToBigInt(point.subarray(offset, offset + 32)));
    if (values.some((value) => value >= BN254_BASE_MODULUS)) {
        throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
    }
    if (values.every((value) => value === 0n))
        return new Uint8Array(64);
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
    }
    catch {
        throw new ClientError("CLIENT_PROOF_POINT", { details: { field: "proof.b" } });
    }
    const result = new Uint8Array(point.subarray(0, 64));
    if (isLargest(y1) || (y1 === 0n && isLargest(y0))) {
        result[0] = (result[0] ?? 0) | 0x80;
    }
    return result;
}
function validateG1(x, y, name) {
    if (x >= BN254_BASE_MODULUS ||
        y >= BN254_BASE_MODULUS ||
        (y * y - ((x * x) % BN254_BASE_MODULUS) * x - 3n) % BN254_BASE_MODULUS !== 0n) {
        throw new ClientError("CLIENT_PROOF_POINT", { details: { field: name } });
    }
}
function isLargest(value) {
    return value > (BN254_BASE_MODULUS - 1n) / 2n;
}
function parseG1(value, path) {
    const coordinates = asArray(value, path);
    if (coordinates.length !== 2)
        invalid(path);
    const x = parseCoordinate(coordinates[0], `${path}[0]`);
    const y = parseCoordinate(coordinates[1], `${path}[1]`);
    if (x !== 0n || y !== 0n)
        validateG1(x, y, path);
    const result = new Uint8Array(64);
    result.set(bigintToBytes(x));
    result.set(bigintToBytes(y), 32);
    return result;
}
function parseG2(value, path) {
    const rows = asArray(value, path);
    if (rows.length !== 2)
        invalid(path);
    const coordinates = rows.flatMap((row, rowIndex) => {
        const values = asArray(row, `${path}[${String(rowIndex)}]`);
        if (values.length !== 2)
            invalid(`${path}[${String(rowIndex)}]`);
        return values.map((item, index) => parseCoordinate(item, `${path}[${String(rowIndex)}][${String(index)}]`));
    });
    const result = new Uint8Array(128);
    coordinates.forEach((coordinate, index) => {
        result.set(bigintToBytes(coordinate), index * 32);
    });
    return result;
}
/// The prover writes every coordinate as `0x%064x`, but the Rust parser reads
/// it through `BigInt::from_str_radix(trim_start_matches("0x"), 16)`, which
/// takes the same digits with the prefix left off. Accept both so a producer
/// the Rust client handles is not rejected here; the digits are always read as
/// hexadecimal, prefix or not, exactly as Rust reads them.
function parseCoordinate(value, path) {
    if (typeof value !== "string")
        invalid(path);
    const digits = /^0[xX]/u.test(value) ? value.slice(2) : value;
    if (!/^[0-9a-fA-F]+$/u.test(digits))
        invalid(path);
    const result = BigInt(`0x${digits}`);
    if (result >= BN254_BASE_MODULUS)
        invalid(path);
    return result;
}
/// Rust reads the two commitment fields as `#[serde(default)] Vec<String>` and
/// decides the rail on `is_empty()`, so an explicit `[]` means "no commitment"
/// there. Treat it the same rather than reading a present-but-empty array as a
/// commitment and failing the rail check.
function present(value) {
    return value !== undefined && !(Array.isArray(value) && value.length === 0);
}
function asObject(value, path) {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        invalid(path);
    return value;
}
function asArray(value, path) {
    if (!Array.isArray(value))
        invalid(path);
    return value;
}
function invalid(path) {
    throw new ClientError("CLIENT_PROOF_PARSE", { details: { path } });
}
