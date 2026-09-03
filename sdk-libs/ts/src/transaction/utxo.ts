import { address } from "@solana/kit";

import type { Address, Bytes31, Bytes32 } from "../interface/types.js";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../interface/program.js";
import { randomBlinding } from "../keypair/bytes.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import type { ShieldedAddress, ShieldedKeypair } from "../keypair/shielded.js";

import { Data, type DataRecord } from "./data.js";
import { TransactionError } from "./error.js";
import {
  ZERO_32,
  checkU64,
  checked,
  commitmentPoseidon,
  copy,
  decodeAddress,
  hashBytes,
  poseidon,
  rightAlign,
  sha256Bytes,
} from "./internal.js";

export type Blinding = Bytes32;

export interface UtxoInit {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Blinding;
  readonly data?: Data;
  readonly ringProgramId?: Address;
}

/**
 * The ring binding a reconstructed UTXO carries, given the id its reader was
 * configured with. A reader that supplies none cannot bind ring data to a
 * policy nobody can enforce, so a payload carrying ring data is refused; a
 * payload carrying none drops the id rather than committing to a ring the
 * plaintext never mentioned. Mirrors Rust `resolve_ring_program_id`.
 */
export function resolveRingProgramId(
  ringProgramId: Address | undefined,
  data: Data,
): Address | undefined {
  if (!data.ringData()) return undefined;
  if (ringProgramId === undefined) {
    throw new TransactionError("TRANSACTION_MISSING_RING_PROGRAM_ID");
  }
  return ringProgramId;
}

export function deriveBlinding(seed: Bytes32, position: number): Blinding {
  const checkedSeed = checked<Bytes32>(seed, 32, "blinding seed");
  if (!Number.isInteger(position) || position < 0 || position > 0xff) {
    throw new TransactionError("TRANSACTION_INVALID_POSITION", { position });
  }
  const digest = sha256Bytes(Uint8Array.from([...checkedSeed.subarray(1), position]));
  const blinding = new Uint8Array(32);
  blinding.set(digest.subarray(1), 1);
  return blinding as Blinding;
}

const DEPOSIT_BLINDING_DOMAIN = new TextEncoder().encode("Deposit");

/**
 * Blinding SPP derives for the proofless `deposit` output landing at
 * `leafIndex` in `tree`. Mirrors Rust `deposit_blinding`. The pair never
 * repeats, so no two deposits share a blinding, hence none share a UTXO hash or
 * a nullifier. A depositor supplies none.
 *
 * This is the verification path, not the normal client path. A proofless
 * deposit's output is plaintext, so the blinding comes back with the indexed
 * UTXO and a client reads it from the indexer. Recompute it here only to check
 * an indexed record without trusting the indexer, given the `output_tree` and
 * `leafIndex` the deposit settled at. `leafIndex` is assigned during execution,
 * so a client that predicts it before sending races every other deposit into
 * the same tree.
 */
export function depositBlinding(tree: Address, leafIndex: bigint): Blinding {
  if (leafIndex < 0n || leafIndex > 0xffff_ffff_ffff_ffffn) {
    throw new TransactionError("TRANSACTION_INVALID_POSITION", {
      position: leafIndex.toString(),
    });
  }
  const index = new Uint8Array(8);
  new DataView(index.buffer).setBigUint64(0, leafIndex, false);
  const digest = sha256Bytes(
    Uint8Array.from([...DEPOSIT_BLINDING_DOMAIN, ...decodeAddress(tree), ...index]),
  );
  const blinding = new Uint8Array(32);
  blinding.set(digest.subarray(1), 1);
  return blinding as Blinding;
}

function commitmentFields(
  input: Readonly<{
    domain?: number;
    owner: Bytes32;
    asset: Address;
    amount: bigint;
    blinding: Bytes32;
    dataHash?: Bytes32;
    ringDataHash?: Bytes32;
    ringProgramId?: Address;
  }>,
): readonly Bytes32[] {
  checkU64(input.amount, "amount");
  const ringDataHash = input.ringDataHash
    ? checked<Bytes32>(input.ringDataHash, 32, "ring data hash")
    : ZERO_32;
  if (!input.ringProgramId && !isZero(ringDataHash)) {
    throw new TransactionError("TRANSACTION_MISSING_RING_PROGRAM_ID");
  }
  const ringProgramId = input.ringProgramId
    ? hashBytes(decodeAddress(input.ringProgramId))
    : ZERO_32;
  const ringHash = commitmentPoseidon([ringDataHash, ringProgramId]);
  const ownerCommitment = commitmentPoseidon([
    checked<Bytes32>(input.owner, 32, "owner hash"),
    checked<Bytes32>(input.blinding, 32, "blinding"),
  ]);
  return [
    rightAlign(Uint8Array.of(input.domain ?? UTXO_DOMAIN)),
    hashBytes(decodeAddress(input.asset)) as Bytes32,
    rightAlign(bigintToU64(input.amount)),
    input.dataHash ? checked<Bytes32>(input.dataHash, 32, "data hash") : ZERO_32,
    ringHash,
    ownerCommitment,
  ];
}

/**
 * An all-zero ring data hash reaches the commitment as the same field an absent
 * one does, so the two spellings must not survive as distinct stored values.
 * This normalizes the hash only; the ring address is deliberately left alone,
 * because a zero `ringProgramId` commits to `pk_field(0)`, a non-zero field the
 * circuit reads as ring-bound.
 */
function normalizeRingDataHash(ringDataHash?: Bytes32): Bytes32 | undefined {
  if (ringDataHash === undefined) return undefined;
  const value = checked<Bytes32>(ringDataHash, 32, "ring data hash");
  return isZero(value) ? undefined : value;
}

function bigintToU64(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, checkU64(value, "amount"), false);
  return output;
}

function fullOwnerUtxoHash(
  input: Readonly<{
    owner: Bytes32;
    asset: Address;
    amount: bigint;
    blinding: Bytes32;
    dataHash?: Bytes32;
    ringDataHash?: Bytes32;
    ringProgramId?: Address;
  }>,
  dummy = false,
): Bytes32 {
  if (dummy) {
    return commitmentPoseidon([
      rightAlign(Uint8Array.of(DUMMY_DOMAIN)),
      ZERO_32,
      ZERO_32,
      ZERO_32,
      commitmentPoseidon([ZERO_32, ZERO_32]),
      commitmentPoseidon([ZERO_32, checked<Bytes32>(input.blinding, 32, "blinding")]),
    ]);
  }
  return commitmentPoseidon(commitmentFields(input));
}

export function ownerUtxoHash(ownerHash: Bytes32, blinding: Bytes32): Bytes32;
export function ownerUtxoHash(
  input: Readonly<{
    owner: Bytes32;
    asset: Address;
    amount: bigint;
    blinding: Bytes32;
    dataHash?: Bytes32;
    ringDataHash?: Bytes32;
    ringProgramId?: Address;
  }>,
): Bytes32;
export function ownerUtxoHash(
  ownerOrInput:
    | Bytes32
    | Readonly<{
        owner: Bytes32;
        asset: Address;
        amount: bigint;
        blinding: Bytes32;
        dataHash?: Bytes32;
        ringDataHash?: Bytes32;
        ringProgramId?: Address;
      }>,
  blinding?: Bytes32,
): Bytes32 {
  if (ownerOrInput instanceof Uint8Array) {
    if (!blinding) throw new TransactionError("TRANSACTION_INVALID_BLINDING");
    return commitmentPoseidon([
      checked<Bytes32>(ownerOrInput, 32, "owner hash"),
      checked<Bytes32>(blinding, 32, "blinding"),
    ]);
  }
  return fullOwnerUtxoHash(ownerOrInput);
}

export class Utxo {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Blinding;
  readonly data: Data;
  readonly ringProgramId?: Address;

  constructor(input: UtxoInit) {
    this.owner = input.owner;
    this.asset = input.asset;
    this.amount = checkU64(input.amount, "amount");
    this.blinding = checked<Blinding>(input.blinding, 32, "blinding");
    this.data = new Data((input.data ?? new Data()).records());
    if (input.ringProgramId !== undefined) this.ringProgramId = input.ringProgramId;
  }

  proofInput(
    nullifierPublicKey: Bytes32,
    dataHash?: Bytes32,
    ringDataHash?: Bytes32,
  ): Readonly<{ hash(): Bytes32 }> {
    const owner = poseidon([
      this.owner.ownerProofInputHash(),
      checked<Bytes32>(nullifierPublicKey, 32, "nullifier public key"),
    ]);
    const input = {
      owner,
      asset: this.asset,
      amount: this.amount,
      blinding: this.blinding,
      ...(dataHash === undefined ? {} : { dataHash }),
      ...(ringDataHash === undefined ? {} : { ringDataHash }),
      ...(this.ringProgramId === undefined ? {} : { ringProgramId: this.ringProgramId }),
    };
    return Object.freeze({ hash: (): Bytes32 => fullOwnerUtxoHash(input) });
  }

  hash(nullifierPublicKey: Bytes32, dataHash?: Bytes32, ringDataHash?: Bytes32): Bytes32 {
    return this.proofInput(nullifierPublicKey, dataHash, ringDataHash).hash();
  }

  nullifier(utxoHash: Bytes32, nullifierKey: NullifierKey): Bytes32 {
    return nullifierKey.nullifier(checked<Bytes32>(utxoHash, 32, "UTXO hash"), this.blinding);
  }
}

export class ProofInputUtxo {
  readonly utxo: Utxo;
  readonly nullifierKey: NullifierKey;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;

  constructor(
    input: Readonly<{
      utxo: Utxo;
      nullifierKey: NullifierKey;
      dataHash?: Bytes32;
      ringDataHash?: Bytes32;
    }>,
  ) {
    if (!(input.utxo instanceof Utxo) || !(input.nullifierKey instanceof NullifierKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "proofInput" });
    }
    this.utxo = new Utxo({
      owner: input.utxo.owner.isZero()
        ? ShieldedPublicKey.zeroed()
        : ShieldedPublicKey.fromBytes(input.utxo.owner.toBytes()),
      asset: input.utxo.asset,
      amount: input.utxo.amount,
      blinding: input.utxo.blinding,
      data: input.utxo.data,
      ...(input.utxo.ringProgramId === undefined
        ? {}
        : { ringProgramId: input.utxo.ringProgramId }),
    });
    this.nullifierKey = cloneNullifierKey(input.nullifierKey);
    if (input.dataHash) {
      this.dataHash = checked<Bytes32>(input.dataHash, 32, "data hash");
    }
    const ringDataHash = normalizeRingDataHash(input.ringDataHash);
    if (ringDataHash !== undefined) {
      this.ringDataHash = ringDataHash;
    }
    this.checkCanonicalDummy();
  }

  static fromKeypair(utxo: Utxo, keypair: ShieldedKeypair): ProofInputUtxo {
    const nullifierKey = keypair.nullifierKey();
    try {
      return new ProofInputUtxo({ utxo, nullifierKey });
    } finally {
      nullifierKey.destroy();
    }
  }

  static dummy(blinding = randomBlinding()): ProofInputUtxo {
    const nullifierKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    try {
      return new ProofInputUtxo({
        utxo: new Utxo({
          owner: ShieldedPublicKey.zeroed(),
          asset: address("11111111111111111111111111111111"),
          amount: 0n,
          blinding: checked<Bytes32>(blinding, 32, "dummy blinding"),
        }),
        nullifierKey,
      });
    } finally {
      nullifierKey.destroy();
    }
  }

  isDummy(): boolean {
    return this.utxo.owner.isZero();
  }

  /** Destroys the cloned nullifier key, later proving throws. */
  destroy(): void {
    this.nullifierKey.destroy();
  }

  /**
   * A zero owner is not a parseable key, so a zero-owner input can only stand
   * for an unused slot. Every other field must be zero as well: the circuit
   * treats the slot as absent, and anything carried here would be committed
   * under an owner hash no key can reproduce.
   *
   * `ringProgramId` is checked for presence rather than for a zero value,
   * unlike the two hashes: the zero address commits to `pk_field(0)`, a
   * non-zero field, so it is carried rather than absent.
   */
  checkCanonicalDummy(): void {
    if (!this.isDummy()) return;
    const field = noncanonicalDummyField(this);
    if (field !== undefined) {
      throw new TransactionError("TRANSACTION_NONCANONICAL_DUMMY_INPUT", { field });
    }
  }

  hash(): Bytes32 {
    this.checkCanonicalDummy();
    const owner = this.isDummy()
      ? ZERO_32
      : poseidon([this.utxo.owner.ownerProofInputHash(), this.nullifierKey.publicKey()]);
    return fullOwnerUtxoHash(
      {
        owner,
        asset: this.utxo.asset,
        amount: this.utxo.amount,
        blinding: this.utxo.blinding,
        ...(this.dataHash === undefined ? {} : { dataHash: this.dataHash }),
        ...(this.ringDataHash === undefined ? {} : { ringDataHash: this.ringDataHash }),
        ...(this.utxo.ringProgramId === undefined
          ? {}
          : { ringProgramId: this.utxo.ringProgramId }),
      },
      this.isDummy(),
    );
  }

  nullifier(): Bytes32 {
    return this.nullifierKey.nullifier(this.hash(), this.utxo.blinding);
  }
}

const DUMMY_ASSET = address("11111111111111111111111111111111");

/**
 * What the commitment folds in. An absent hash and an explicit zero reach
 * `commitmentFields` as the same field, so a rule reading presence rather than
 * this one tells apart two inputs the commitment cannot. `dataHash` is stored
 * as given, so both spellings are reachable.
 */
function committedHash(hash?: Bytes32): Bytes32 {
  return hash ?? ZERO_32;
}

function noncanonicalDummyField(input: ProofInputUtxo): string | undefined {
  if (input.utxo.asset !== DUMMY_ASSET) return "asset";
  if (input.utxo.amount !== 0n) return "amount";
  if (!input.utxo.data.isEmpty()) return "data";
  if (input.utxo.ringProgramId !== undefined) return "ring_program_id";
  if (!isZero(committedHash(input.dataHash))) return "data_hash";
  if (!isZero(committedHash(input.ringDataHash))) return "ring_data_hash";
  if (!isZeroNullifierKey(input.nullifierKey)) return "nullifier_key";
  return undefined;
}

export interface ProofOutputUtxo {
  readonly ownerAddress?: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly ringProgramId?: Address;
  readonly ringDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ownerTag?: Bytes32;
  readonly data: Data;
  ownerHash(): Bytes32;
  hash(): Bytes32;
  isDummy(): boolean;
  withUtxoData(utxoData: Uint8Array, dataHash: Bytes32): ProofOutputUtxo;
  /**
   * A memo rides in the recipient's UTXO but no commitment covers it, so unlike
   * the data setter above it leaves `dataHash` alone.
   */
  withMemo(memo: Uint8Array): ProofOutputUtxo;
  /** Binds the UTXO to a ring, only that ring's transact can spend it. */
  withRingProgramId(ringProgramId: Address): ProofOutputUtxo;
}

export interface ProofOutputInit {
  readonly ownerAddress?: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding?: Bytes32;
  readonly ringProgramId?: Address;
  readonly ringDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ownerTag?: Bytes32;
  readonly data?: Data;
}

const DATA_RECORD_ORDER: Readonly<Record<DataRecord["kind"], number>> = Object.freeze({
  ringData: 0,
  utxoData: 1,
  memo: 2,
});

/** One record per kind, kept in the canonical order `Data.validate` requires. */
function withDataRecord(data: Data, record: DataRecord): Data {
  return new Data(
    [...data.records().filter((existing) => existing.kind !== record.kind), record].sort(
      (left, right) => DATA_RECORD_ORDER[left.kind] - DATA_RECORD_ORDER[right.kind],
    ),
  );
}

export function createProofOutput(input: ProofOutputInit): ProofOutputUtxo {
  const blinding = checked<Bytes32>(input.blinding ?? randomBlinding(), 32, "output blinding");
  const amount = checkU64(input.amount, "output amount");
  const data = new Data((input.data ?? new Data()).records());
  const { ringDataHash: suppliedRingDataHash, ...rest } = input;
  const ringDataHash = normalizeRingDataHash(suppliedRingDataHash);
  const init: ProofOutputInit = {
    ...rest,
    amount,
    blinding,
    data,
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
  };
  const ownerHash = (): Bytes32 =>
    input.ownerAddress ? input.ownerAddress.ownerHash() : copy(ZERO_32);
  return Object.freeze({
    ...init,
    amount,
    blinding,
    data,
    ownerHash,
    hash(): Bytes32 {
      return fullOwnerUtxoHash(
        {
          owner: ownerHash(),
          asset: input.asset,
          amount,
          blinding,
          ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
          ...(ringDataHash === undefined ? {} : { ringDataHash }),
          ...(input.ringProgramId === undefined ? {} : { ringProgramId: input.ringProgramId }),
        },
        input.ownerAddress === undefined,
      );
    },
    isDummy(): boolean {
      return input.ownerAddress === undefined;
    },
    withUtxoData(utxoData: Uint8Array, dataHash: Bytes32): ProofOutputUtxo {
      return createProofOutput({
        ...init,
        dataHash,
        data: withDataRecord(data, { kind: "utxoData", bytes: utxoData }),
      });
    },
    withMemo(memo: Uint8Array): ProofOutputUtxo {
      return createProofOutput({
        ...init,
        data: withDataRecord(data, { kind: "memo", bytes: memo }),
      });
    },
    withRingProgramId(ringProgramId: Address): ProofOutputUtxo {
      return createProofOutput({ ...init, ringProgramId });
    },
  });
}

function cloneNullifierKey(key: NullifierKey): NullifierKey {
  const secret = key.secretBytes();
  try {
    return NullifierKey.fromSecret(secret);
  } finally {
    secret.fill(0);
  }
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function isZeroNullifierKey(key: NullifierKey): boolean {
  const secret = key.secretBytes();
  try {
    return isZero(secret);
  } finally {
    secret.fill(0);
  }
}
