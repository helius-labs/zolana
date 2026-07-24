import type { Address, Bytes31, Bytes32 } from "@zolana/interface";
import { NullifierKey, ShieldedPublicKey, SigningKey, type ShieldedAddress } from "@zolana/keypair";

import { Data } from "./data.js";
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

const DUMMY_INPUTS = new WeakSet<ProofInputUtxo>();

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
    this.utxo = input.utxo;
    this.nullifierKey = input.nullifierKey;
    if (input.dataHash) {
      this.dataHash = checked<Bytes32>(input.dataHash, 32, "data hash");
    }
    if (input.zoneDataHash) {
      this.zoneDataHash = checked<Bytes32>(input.zoneDataHash, 32, "zone data hash");
    }
  }

  static dummy(blinding = random31()): ProofInputUtxo {
    const signing = SigningKey.generate();
    const value = new ProofInputUtxo({
      utxo: new Utxo({
        owner: signing.publicKey(),
        asset: "11111111111111111111111111111111" as Address,
        amount: 0n,
        blinding: checked<Bytes31>(blinding, 31, "dummy blinding"),
      }),
      nullifierKey: NullifierKey.fromSecret(new Uint8Array(31) as Bytes31),
    });
    DUMMY_INPUTS.add(value);
    return value;
  }

  isDummy(): boolean {
    return DUMMY_INPUTS.has(this);
  }

  hash(): Bytes32 {
    if (this.isDummy()) {
      return fullOwnerUtxoHash({
        owner: ZERO_32,
        asset: this.utxo.asset,
        amount: 0n,
        blinding: this.utxo.blinding,
      });
    }
    return this.utxo.hash(this.nullifierKey.publicKey(), this.dataHash, this.zoneDataHash);
  }

  nullifier(): Bytes32 {
    return this.nullifierKey.nullifier(this.hash(), this.utxo.blinding);
  }
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
}

export function createProofOutput(
  input: Readonly<{
    ownerAddress?: ShieldedAddress;
    asset: Address;
    amount: bigint;
    blinding?: Bytes31;
    zoneProgramId?: Address;
    zoneDataHash?: Bytes32;
    dataHash?: Bytes32;
    ownerTag?: Bytes32;
    data?: Data;
  }>,
): ProofOutputUtxo {
  const blinding = input.blinding ?? random31();
  const amount = checkU64(input.amount, "output amount");
  const data = new Data((input.data ?? new Data()).records());
  const ownerHash = (): Bytes32 =>
    input.ownerAddress ? input.ownerAddress.ownerHash() : copy(ZERO_32);
  return Object.freeze({
    ...input,
    amount,
    blinding: checked<Bytes31>(blinding, 31, "output blinding"),
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
  });
}
