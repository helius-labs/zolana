import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedPublicKey, type ShieldedAddress } from "@zolana/keypair";

import { Data, type DataRecord } from "./data.js";
import { TransactionError } from "./error.js";
import {
  ZERO_32,
  checkU64,
  checked,
  copy,
  decodeAddress,
  hashField,
  poseidon,
  random31,
  rightAlign,
  sha256Bytes,
} from "./internal.js";

export type Blinding = Bytes31;

export interface UtxoInit {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Blinding;
  readonly data?: Data;
  readonly zoneProgramId?: Address;
}

export function deriveBlinding(seed: Bytes31, position: number): Blinding {
  const checkedSeed = checked<Bytes31>(seed, 31, "blinding seed");
  if (!Number.isInteger(position) || position < 0 || position > 0xff) {
    throw new TransactionError("TRANSACTION_INVALID_POSITION", { position });
  }
  const digest = sha256Bytes(Uint8Array.from([...checkedSeed, position]));
  return copy(digest.subarray(1)) as Blinding;
}

function commitmentFields(
  input: Readonly<{
    owner: Bytes32;
    asset: Address;
    amount: bigint;
    blinding: Bytes31;
    dataHash?: Bytes32;
    zoneDataHash?: Bytes32;
    zoneProgramId?: Address;
  }>,
): readonly Bytes32[] {
  checkU64(input.amount, "amount");
  const zoneDataHash = input.zoneDataHash
    ? checked<Bytes32>(input.zoneDataHash, 32, "zone data hash")
    : ZERO_32;
  if (!input.zoneProgramId && !isZero(zoneDataHash)) {
    throw new TransactionError("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
  }
  const zoneProgramId = input.zoneProgramId
    ? hashField(decodeAddress(input.zoneProgramId))
    : ZERO_32;
  const zoneHash = poseidon([zoneDataHash, zoneProgramId]);
  const ownerCommitment = poseidon([
    checked<Bytes32>(input.owner, 32, "owner hash"),
    rightAlign(checked<Bytes31>(input.blinding, 31, "blinding")),
  ]);
  return [
    rightAlign(Uint8Array.of(1)),
    hashField(decodeAddress(input.asset)),
    rightAlign(bigintToU64(input.amount)),
    input.dataHash ? checked<Bytes32>(input.dataHash, 32, "data hash") : ZERO_32,
    zoneHash,
    ownerCommitment,
  ];
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
    blinding: Bytes31;
    dataHash?: Bytes32;
    zoneDataHash?: Bytes32;
    zoneProgramId?: Address;
  }>,
): Bytes32 {
  return poseidon(commitmentFields(input));
}

export function ownerUtxoHash(ownerHash: Bytes32, blinding: Bytes31): Bytes32;
export function ownerUtxoHash(
  input: Readonly<{
    owner: Bytes32;
    asset: Address;
    amount: bigint;
    blinding: Bytes31;
    dataHash?: Bytes32;
    zoneDataHash?: Bytes32;
    zoneProgramId?: Address;
  }>,
): Bytes32;
export function ownerUtxoHash(
  ownerOrInput:
    | Bytes32
    | Readonly<{
        owner: Bytes32;
        asset: Address;
        amount: bigint;
        blinding: Bytes31;
        dataHash?: Bytes32;
        zoneDataHash?: Bytes32;
        zoneProgramId?: Address;
      }>,
  blinding?: Bytes31,
): Bytes32 {
  if (ownerOrInput instanceof Uint8Array) {
    if (!blinding) throw new TransactionError("TRANSACTION_INVALID_BLINDING");
    return poseidon([
      checked<Bytes32>(ownerOrInput, 32, "owner hash"),
      rightAlign(checked<Bytes31>(blinding, 31, "blinding")),
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
  readonly zoneProgramId?: Address;

  constructor(input: UtxoInit) {
    this.owner = input.owner;
    this.asset = input.asset;
    this.amount = checkU64(input.amount, "amount");
    this.blinding = checked<Blinding>(input.blinding, 31, "blinding");
    this.data = new Data((input.data ?? new Data()).records());
    if (input.zoneProgramId !== undefined) this.zoneProgramId = input.zoneProgramId;
    if (this.data.zoneData() && !this.zoneProgramId) {
      throw new TransactionError("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
    }
  }

  proofInput(
    nullifierPublicKey: Bytes32,
    dataHash?: Bytes32,
    zoneDataHash?: Bytes32,
  ): Readonly<{ hash(): Bytes32 }> {
    const owner = poseidon([
      this.owner.ownerPublicKeyField(),
      checked<Bytes32>(nullifierPublicKey, 32, "nullifier public key"),
    ]);
    const input = {
      owner,
      asset: this.asset,
      amount: this.amount,
      blinding: this.blinding,
      ...(dataHash === undefined ? {} : { dataHash }),
      ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
      ...(this.zoneProgramId === undefined ? {} : { zoneProgramId: this.zoneProgramId }),
    };
    return Object.freeze({ hash: (): Bytes32 => fullOwnerUtxoHash(input) });
  }

  hash(nullifierPublicKey: Bytes32, dataHash?: Bytes32, zoneDataHash?: Bytes32): Bytes32 {
    return this.proofInput(nullifierPublicKey, dataHash, zoneDataHash).hash();
  }

  nullifier(utxoHash: Bytes32, nullifierKey: NullifierKey): Bytes32 {
    return nullifierKey.nullifier(checked<Bytes32>(utxoHash, 32, "UTXO hash"), this.blinding);
  }
}

export class ProofInputUtxo {
  readonly utxo: Utxo;
  readonly nullifierKey: NullifierKey;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;

  constructor(
    input: Readonly<{
      utxo: Utxo;
      nullifierKey: NullifierKey;
      dataHash?: Bytes32;
      zoneDataHash?: Bytes32;
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
      ...(input.utxo.zoneProgramId === undefined
        ? {}
        : { zoneProgramId: input.utxo.zoneProgramId }),
    });
    this.nullifierKey = cloneNullifierKey(input.nullifierKey);
    if (input.dataHash) {
      this.dataHash = checked<Bytes32>(input.dataHash, 32, "data hash");
    }
    if (input.zoneDataHash) {
      this.zoneDataHash = checked<Bytes32>(input.zoneDataHash, 32, "zone data hash");
    }
    this.checkCanonicalDummy();
  }

  static dummy(blinding = random31()): ProofInputUtxo {
    const nullifierKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    try {
      return new ProofInputUtxo({
        utxo: new Utxo({
          owner: ShieldedPublicKey.zeroed(),
          asset: "11111111111111111111111111111111" as Address,
          amount: 0n,
          blinding: checked<Bytes31>(blinding, 31, "dummy blinding"),
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

  /**
   * A zero owner is not a parseable key, so a zero-owner input can only stand
   * for an unused slot. Every other field must be zero as well: the circuit
   * treats the slot as absent, and anything carried here would be committed
   * under an owner hash no key can reproduce.
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
      : poseidon([this.utxo.owner.ownerPublicKeyField(), this.nullifierKey.publicKey()]);
    return fullOwnerUtxoHash({
      owner,
      asset: this.utxo.asset,
      amount: this.utxo.amount,
      blinding: this.utxo.blinding,
      ...(this.dataHash === undefined ? {} : { dataHash: this.dataHash }),
      ...(this.zoneDataHash === undefined ? {} : { zoneDataHash: this.zoneDataHash }),
      ...(this.utxo.zoneProgramId === undefined ? {} : { zoneProgramId: this.utxo.zoneProgramId }),
    });
  }

  nullifier(): Bytes32 {
    return this.nullifierKey.nullifier(this.hash(), this.utxo.blinding);
  }
}

const DUMMY_ASSET = "11111111111111111111111111111111" as Address;

function noncanonicalDummyField(input: ProofInputUtxo): string | undefined {
  if (input.utxo.asset !== DUMMY_ASSET) return "asset";
  if (input.utxo.amount !== 0n) return "amount";
  if (!input.utxo.data.isEmpty()) return "data";
  if (input.utxo.zoneProgramId !== undefined) return "zone_program_id";
  if (input.dataHash !== undefined) return "data_hash";
  if (input.zoneDataHash !== undefined) return "zone_data_hash";
  if (!isZeroNullifierKey(input.nullifierKey)) return "nullifier_key";
  return undefined;
}

export interface ProofOutputUtxo {
  readonly ownerAddress?: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes31;
  readonly zoneProgramId?: Address;
  readonly zoneDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ownerTag?: Bytes32;
  readonly data: Data;
  ownerHash(): Bytes32;
  hash(): Bytes32;
  isDummy(): boolean;
  withZoneProgramId(zoneProgramId: Address): ProofOutputUtxo;
  withZoneData(
    zoneProgramId: Address,
    zoneData: Uint8Array,
    zoneDataHash: Bytes32,
  ): ProofOutputUtxo;
  /**
   * Bind an output to policy-zone state when only its commitment hash belongs in
   * the witness; the zone owes the owner the preimage under its own policy.
   */
  withZoneDataHash(zoneProgramId: Address, zoneDataHash: Bytes32): ProofOutputUtxo;
  withUtxoData(utxoData: Uint8Array, dataHash: Bytes32): ProofOutputUtxo;
  /**
   * A memo rides in the recipient's note but no commitment covers it, so unlike
   * the two data setters above it leaves `dataHash` alone.
   */
  withMemo(memo: Uint8Array): ProofOutputUtxo;
}

export interface ProofOutputInit {
  readonly ownerAddress?: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding?: Bytes31;
  readonly zoneProgramId?: Address;
  readonly zoneDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ownerTag?: Bytes32;
  readonly data?: Data;
}

const DATA_RECORD_ORDER: Readonly<Record<DataRecord["kind"], number>> = Object.freeze({
  zoneData: 0,
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
  const blinding = checked<Bytes31>(input.blinding ?? random31(), 31, "output blinding");
  const amount = checkU64(input.amount, "output amount");
  const data = new Data((input.data ?? new Data()).records());
  const init: ProofOutputInit = { ...input, amount, blinding, data };
  const ownerHash = (): Bytes32 =>
    input.ownerAddress ? input.ownerAddress.ownerHash() : copy(ZERO_32);
  return Object.freeze({
    ...init,
    amount,
    blinding,
    data,
    ownerHash,
    hash(): Bytes32 {
      return fullOwnerUtxoHash({
        owner: ownerHash(),
        asset: input.asset,
        amount,
        blinding,
        ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
        ...(input.zoneDataHash === undefined ? {} : { zoneDataHash: input.zoneDataHash }),
        ...(input.zoneProgramId === undefined ? {} : { zoneProgramId: input.zoneProgramId }),
      });
    },
    isDummy(): boolean {
      return input.ownerAddress === undefined;
    },
    withZoneProgramId(zoneProgramId: Address): ProofOutputUtxo {
      return createProofOutput({ ...init, zoneProgramId });
    },
    withZoneData(
      zoneProgramId: Address,
      zoneData: Uint8Array,
      zoneDataHash: Bytes32,
    ): ProofOutputUtxo {
      return createProofOutput({
        ...init,
        zoneProgramId,
        zoneDataHash,
        data: withDataRecord(data, { kind: "zoneData", bytes: zoneData }),
      });
    },
    withZoneDataHash(zoneProgramId: Address, zoneDataHash: Bytes32): ProofOutputUtxo {
      return createProofOutput({ ...init, zoneProgramId, zoneDataHash });
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
