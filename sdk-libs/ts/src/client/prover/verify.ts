import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import type { WeierstrassPoint } from "@noble/curves/abstract/weierstrass.js";
import { bn254 } from "@noble/curves/bn254.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";

import { bytesToBigInt } from "../../interface/bytes.js";
import type { ExpectedProvingKey } from "../../interface/proving-keys.js";
import { VERIFYING_KEYS, type Groth16VerifyingKey } from "../../interface/verifying-keys.js";

import { ClientError } from "../error.js";
import { setVerifyingKey, type ProvingKeySet } from "./key-set.js";
import type { Proof } from "./types.js";

type G1 = WeierstrassPoint<bigint>;
type G2 = ReturnType<typeof bn254.G2.Point.fromAffine>;

type PreparedKey = Readonly<{
  alpha: G1;
  beta: G2;
  gamma: G2;
  delta: G2;
  ic: readonly G1[];
  commitment?: Readonly<{ g2: G2; gSigmaNeg: G2 }>;
}>;

/** gnark's `constraint.CommitmentDst`, the domain of the BSB22 commitment hash. */
const BSB22_DST = "bsb22-commitment";
/** RFC 9380 output length for one BN254 scalar: 32 bytes of modulus and 16 of margin. */
const BSB22_HASH_BYTES = 48;
const { Fp12, Fr } = bn254.fields;

const prepared = new WeakMap<Groth16VerifyingKey, PreparedKey>();

/** A proof the statement does not accept, `check` naming the step that refused it. */
function refused(check: "commitment" | "encoding" | "pairing"): ClientError {
  return new ClientError("CLIENT_PROOF_VERIFICATION", { details: { check } });
}

/**
 * Throws `CLIENT_PROOF_VERIFICATION` unless `proof` proves the statement
 * whose public input hash is `publicInputHash` under the verifying key of
 * `key`: the runtime set's when `set` is given, else the compiled key the
 * program verifies with. Rust `StatementVerification::verify`.
 */
export function verifyProofStatement(
  proof: Proof,
  publicInputHash: bigint,
  key: ExpectedProvingKey,
  set: ProvingKeySet | undefined,
): void {
  verifyGroth16(proof, publicInputHash, verifyingKeyOf(key.name, set));
}

function verifyingKeyOf(name: string, set: ProvingKeySet | undefined): Groth16VerifyingKey {
  if (set !== undefined) return setVerifyingKey(set, name);
  const key = Object.hasOwn(VERIFYING_KEYS, name) ? VERIFYING_KEYS[name] : undefined;
  if (key === undefined) throw new ClientError("CLIENT_PROVER_INPUT");
  return key;
}

/**
 * The Groth16 check over BN254 the shielded pool runs, with gnark's BSB22
 * extension when the key carries a commitment key: the commitment's hash is
 * one more public input, the commitment point joins the input sum, and its
 * proof of knowledge must pair to one. `proof.a` is already negated, as the
 * instruction carries it. Mirrors `groth16_solana::Groth16Verifier::verify`.
 */
function verifyGroth16(proof: Proof, publicInput: bigint, key: Groth16VerifyingKey): void {
  const vk = preparedKey(key);
  const committed = proof.commitment !== undefined;
  if (
    committed !== (proof.commitmentPok !== undefined) ||
    committed !== (vk.commitment !== undefined)
  )
    throw refused("commitment");
  if (publicInput < 0n || publicInput >= Fr.ORDER || vk.ic.length !== (committed ? 3 : 2))
    throw refused("encoding");
  const [base, inputBase, commitmentBase] = vk.ic;
  if (base === undefined || inputBase === undefined) throw refused("encoding");
  let inputs = base.add(inputBase.multiplyUnsafe(publicInput));
  let pok: readonly [G1, G1] | undefined;
  if (proof.commitment !== undefined && proof.commitmentPok !== undefined) {
    if (commitmentBase === undefined) throw refused("encoding");
    const commitment = g1(proof.commitment);
    inputs = inputs
      .add(commitmentBase.multiplyUnsafe(commitmentHash(proof.commitment)))
      .add(commitment);
    pok = [commitment, g1(proof.commitmentPok)];
  }
  if (
    !pairsToOne([
      [g1(proof.a), g2(proof.b)],
      [inputs, vk.gamma],
      [g1(proof.c), vk.delta],
      [vk.alpha, vk.beta],
    ])
  )
    throw refused("pairing");
  if (
    pok !== undefined &&
    vk.commitment !== undefined &&
    !pairsToOne([
      [pok[0], vk.commitment.gSigmaNeg],
      [pok[1], vk.commitment.g2],
    ])
  )
    throw refused("pairing");
}

/** gnark's `fr.Hash(commitment, "bsb22-commitment", 1)` over the 64-byte `x || y` encoding. */
function commitmentHash(commitment: Uint8Array): bigint {
  return Fr.create(
    bytesToBigInt(expand_message_xmd(commitment, BSB22_DST, BSB22_HASH_BYTES, sha256)),
  );
}

/** A pair with the identity contributes one, as the alt_bn128 pairing treats it. */
function pairsToOne(pairs: readonly (readonly [G1, G2])[]): boolean {
  const terms = pairs.filter(([p, q]) => !p.is0() && !q.is0()).map(([p, q]) => ({ g1: p, g2: q }));
  try {
    return Fp12.eql(bn254.pairingBatch(terms), Fp12.ONE);
  } catch {
    throw refused("encoding");
  }
}

function preparedKey(key: Groth16VerifyingKey): PreparedKey {
  const cached = prepared.get(key);
  if (cached !== undefined) return cached;
  const decoded: PreparedKey = Object.freeze({
    alpha: g1(hex(key.alphaG1, 64)),
    beta: g2(hex(key.betaG2, 128)),
    gamma: g2(hex(key.gammaG2, 128)),
    delta: g2(hex(key.deltaG2, 128)),
    ic: Object.freeze(key.ic.map((point) => g1(hex(point, 64)))),
    ...(key.commitment === undefined
      ? {}
      : {
          commitment: Object.freeze({
            g2: g2(hex(key.commitment.g2, 128)),
            gSigmaNeg: g2(hex(key.commitment.gSigmaNegG2, 128)),
          }),
        }),
  });
  prepared.set(key, decoded);
  return decoded;
}

function hex(value: string, length: number): Uint8Array {
  if (value.length !== length * 2 || !/^[0-9a-f]*$/u.test(value)) throw refused("encoding");
  return hexToBytes(value);
}

/** `x || y`, all zeros the identity, as the alt_bn128 syscalls read it. */
function g1(bytes: Uint8Array): G1 {
  if (bytes.length !== 64) throw refused("encoding");
  const x = bytesToBigInt(bytes.subarray(0, 32));
  const y = bytesToBigInt(bytes.subarray(32, 64));
  if (x === 0n && y === 0n) return bn254.G1.Point.ZERO;
  try {
    const point = bn254.G1.Point.fromAffine({ x, y });
    point.assertValidity();
    return point;
  } catch {
    throw refused("encoding");
  }
}

/** `x.c1 || x.c0 || y.c1 || y.c0`, all zeros the identity, in the prime-order subgroup. */
function g2(bytes: Uint8Array): G2 {
  if (bytes.length !== 128) throw refused("encoding");
  const [x1, x0, y1, y0] = [0, 32, 64, 96].map((offset) =>
    bytesToBigInt(bytes.subarray(offset, offset + 32)),
  );
  if (x0 === undefined || x1 === undefined || y0 === undefined || y1 === undefined)
    throw refused("encoding");
  if (x0 === 0n && x1 === 0n && y0 === 0n && y1 === 0n) return bn254.G2.Point.ZERO;
  try {
    const point = bn254.G2.Point.fromAffine({ x: { c0: x0, c1: x1 }, y: { c0: y0, c1: y1 } });
    point.assertValidity();
    return point;
  } catch {
    throw refused("encoding");
  }
}
