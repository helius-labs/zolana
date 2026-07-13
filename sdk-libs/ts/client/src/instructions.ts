import { AccountMeta, PublicKey, TransactionInstruction } from "@solana/web3.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID, SOL_MINT, SPL_TOKEN_PROGRAM_ID } from "./constants.js";
import { assertLength, writeU16Le, writeU64Le } from "./bytes.js";
import { solInterface } from "./pda.js";

export interface UtxoData {
  dataHash: Uint8Array;
  data: Uint8Array;
}

export interface DepositIxData {
  viewTag: Uint8Array;
  owner: Uint8Array;
  blinding: Uint8Array;
  publicAmount?: bigint | number | null;
  utxoData?: UtxoData | null;
  memo?: Uint8Array | null;
}

export interface DepositSplAccounts {
  userToken: PublicKey;
  splTokenInterface: PublicKey;
  registry: PublicKey;
  tokenProgram?: PublicKey;
}

export interface DepositInstructionArgs extends DepositIxData {
  tree: PublicKey;
  depositor: PublicKey;
  spl?: DepositSplAccounts | null | undefined;
}

export function serializeDepositIxData(data: DepositIxData): Uint8Array {
  assertLength(data.viewTag, 32, "deposit view tag");
  assertLength(data.owner, 32, "deposit owner");
  assertLength(data.blinding, 31, "deposit blinding");
  const out: number[] = [];
  out.push(...data.viewTag, ...data.owner, ...data.blinding);
  writeOptionU64(out, data.publicAmount);
  writeOptionUtxoData(out, data.utxoData);
  writeOptionBytesU16(out, data.memo);
  return new Uint8Array(out);
}

export function depositInstruction(args: DepositInstructionArgs): TransactionInstruction {
  const data = new Uint8Array([
    InstructionTag.Deposit,
    ...serializeDepositIxData(args),
  ]);
  const keys: AccountMeta[] = [
    { pubkey: args.tree, isSigner: false, isWritable: true },
    { pubkey: args.depositor, isSigner: true, isWritable: true },
  ];
  if (args.spl) {
    keys.push(
      { pubkey: args.spl.userToken, isSigner: false, isWritable: true },
      { pubkey: args.spl.splTokenInterface, isSigner: false, isWritable: true },
      { pubkey: args.spl.registry, isSigner: false, isWritable: false },
      { pubkey: args.spl.tokenProgram ?? SPL_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    );
  } else {
    keys.push(
      { pubkey: PublicKey.default, isSigner: false, isWritable: false },
      { pubkey: solInterface(), isSigner: false, isWritable: true },
      { pubkey: args.depositor, isSigner: false, isWritable: true },
    );
  }
  keys.push({ pubkey: SHIELDED_POOL_PROGRAM_ID, isSigner: false, isWritable: false });
  return new TransactionInstruction({
    programId: SHIELDED_POOL_PROGRAM_ID,
    keys,
    data: Buffer.from(data),
  });
}

export function writeOptionU64(out: number[], value?: bigint | number | null): void {
  if (value === undefined || value === null) {
    out.push(0);
    return;
  }
  out.push(1);
  writeU64Le(out, value);
}

export function writeOptionBytesU16(out: number[], value?: Uint8Array | null): void {
  if (value === undefined || value === null) {
    out.push(0);
    return;
  }
  out.push(1);
  writeU16Le(out, value.length);
  out.push(...value);
}

function writeOptionUtxoData(out: number[], value?: UtxoData | null): void {
  if (value === undefined || value === null) {
    out.push(0);
    return;
  }
  assertLength(value.dataHash, 32, "utxo data hash");
  out.push(1, ...value.dataHash);
  writeU16Le(out, value.data.length);
  out.push(...value.data);
}

export function isSolAsset(asset: PublicKey): boolean {
  return asset.equals(SOL_MINT);
}
