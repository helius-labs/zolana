import { PublicKey as SolanaPublicKey } from "@solana/web3.js";
import { BLINDING_LEN, SOL_ASSET_ID, SOL_MINT, UTXO_DOMAIN } from "./constants.js";
import { assertLength, bigIntToBytes, bytesEqual, publicKeyBytes, rightAlign, u64Be } from "./bytes.js";
import { Data } from "./data.js";
import { hashField, poseidon, sha256Be } from "./hash.js";
import { NullifierKey, ownerHash as shieldedOwnerHash, PublicKey } from "./keypair.js";

export type Address = SolanaPublicKey;

export interface UtxoFields {
  owner: PublicKey;
  asset: Address;
  amount: bigint | number;
  blinding: Uint8Array;
  zoneProgramId?: Address | null | undefined;
  data?: Data;
}

export class Utxo {
  readonly owner: PublicKey;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Uint8Array;
  readonly zoneProgramId: Address | undefined;
  readonly data: Data;

  constructor(fields: UtxoFields) {
    assertLength(fields.blinding, BLINDING_LEN, "blinding");
    this.owner = fields.owner;
    this.asset = fields.asset;
    this.amount = BigInt(fields.amount);
    this.blinding = new Uint8Array(fields.blinding);
    this.zoneProgramId = fields.zoneProgramId ?? undefined;
    this.data = fields.data ?? Data.empty();
  }

  ownerUtxoHash(nullifierPk: Uint8Array): Uint8Array {
    return ownerUtxoHash(shieldedOwnerHash(this.owner, nullifierPk), this.blinding);
  }

  hash(nullifierPk: Uint8Array, dataHash = new Uint8Array(32), zoneDataHash = new Uint8Array(32)) {
    return utxoHash({
      asset: this.asset,
      amount: this.amount,
      dataHash,
      zoneDataHash,
      zoneProgramId: this.zoneProgramId,
      ownerUtxoHash: this.ownerUtxoHash(nullifierPk),
    });
  }

  nullifier(utxoHashBytes: Uint8Array, nullifierKey: NullifierKey): Uint8Array {
    return nullifierKey.nullifier(utxoHashBytes, this.blinding);
  }
}

export function deriveBlinding(seed: Uint8Array, position: number): Uint8Array {
  assertLength(seed, BLINDING_LEN, "blinding seed");
  if (!Number.isInteger(position) || position < 0 || position > 0xff) {
    throw new Error("blinding position must fit in u8");
  }
  const digest = sha256Be(new Uint8Array([...seed, position]));
  return digest.slice(1);
}

export function programIdField(programId?: Address | null): Uint8Array {
  return programId ? hashField(publicKeyBytes(programId)) : new Uint8Array(32);
}

export function zoneProgramIdField(zoneProgramId?: Address | null): Uint8Array {
  return programIdField(zoneProgramId);
}

export function ownerUtxoHash(ownerHashBytes: Uint8Array, blinding: Uint8Array): Uint8Array {
  assertLength(ownerHashBytes, 32, "owner hash");
  assertLength(blinding, BLINDING_LEN, "blinding");
  return poseidon([ownerHashBytes, rightAlign(blinding)]);
}

export interface UtxoHashArgs {
  asset: Address;
  amount: bigint | number;
  dataHash: Uint8Array;
  zoneDataHash: Uint8Array;
  zoneProgramId?: Address | null | undefined;
  ownerUtxoHash: Uint8Array;
}

export function utxoHash(args: UtxoHashArgs): Uint8Array {
  assertLength(args.dataHash, 32, "data hash");
  assertLength(args.zoneDataHash, 32, "zone data hash");
  assertLength(args.ownerUtxoHash, 32, "owner utxo hash");
  const domain = rightAlign(bigIntToBytes(BigInt(UTXO_DOMAIN), 2));
  const asset = hashField(publicKeyBytes(args.asset));
  const amount = rightAlign(u64Be(args.amount));
  const zoneHash = poseidon([args.zoneDataHash, programIdField(args.zoneProgramId)]);
  return poseidon([domain, asset, amount, args.dataHash, zoneHash, args.ownerUtxoHash]);
}

export interface SpendUtxo {
  utxo: Utxo;
  nullifierKey: NullifierKey;
  dataHash?: Uint8Array;
  zoneDataHash?: Uint8Array;
}

export interface OutputContext {
  hash: Uint8Array;
  tree: Address;
  leafIndex: bigint;
}

export interface WalletUtxo {
  utxo: Utxo;
  outputContext: OutputContext;
  nullifier: Uint8Array;
  spent: boolean;
}

export class AssetRegistry {
  private readonly assets = new Map<number, Address>();

  constructor(entries: Iterable<[number, Address]> = []) {
    this.assets.set(SOL_ASSET_ID, SOL_MINT);
    for (const [id, address] of entries) {
      if (id === SOL_ASSET_ID && !address.equals(SOL_MINT)) {
        throw new Error("SOL asset id is reserved");
      }
      this.assets.set(id, address);
    }
  }

  static default(): AssetRegistry {
    return new AssetRegistry();
  }

  assetId(asset: Address): number {
    for (const [id, address] of this.assets.entries()) {
      if (bytesEqual(address.toBytes(), asset.toBytes())) return id;
    }
    throw new Error(`unknown asset ${asset.toBase58()}`);
  }

  asset(id: number): Address {
    const asset = this.assets.get(id);
    if (!asset) throw new Error(`unknown asset id ${id}`);
    return asset;
  }
}

export class Wallet {
  readonly utxos: WalletUtxo[] = [];

  constructor(readonly registry = AssetRegistry.default()) {}
}
