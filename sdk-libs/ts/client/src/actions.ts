import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { SOL_MINT, SPL_TOKEN_PROGRAM_ID } from "./constants.js";
import { randomBlinding, ShieldedAddress } from "./keypair.js";
import { ownerUtxoHash, utxoHash } from "./utxo.js";
import {
  DepositIxData,
  DepositSplAccounts,
  depositInstruction,
  UtxoData,
} from "./instructions.js";
import { splAssetRegistry, splAssetVault } from "./pda.js";

export interface CreateDeposit {
  recipient: ShieldedAddress;
  asset: PublicKey;
  amount: bigint | number;
  splTokenAccount?: PublicKey | null;
  memo?: Uint8Array | null;
  utxoData?: UtxoData | null;
}

export class Deposit {
  constructor(
    readonly data: DepositIxData,
    readonly utxoHash: Uint8Array,
    readonly asset: PublicKey,
    readonly spl?: DepositSplAccounts,
  ) {}

  static new(request: CreateDeposit): Deposit {
    const owner = request.recipient.ownerHash();
    const blinding = randomBlinding();
    const ownerHash = ownerUtxoHash(owner, blinding);
    const dataHash = request.utxoData?.dataHash ?? new Uint8Array(32);
    const hash = utxoHash({
      asset: request.asset,
      amount: request.amount,
      dataHash,
      zoneDataHash: new Uint8Array(32),
      zoneProgramId: undefined,
      ownerUtxoHash: ownerHash,
    });
    const spl = splAccounts(request.asset, request.splTokenAccount);
    return new Deposit(
      {
        viewTag: request.recipient.viewingPubkey.x(),
        owner,
        blinding,
        publicAmount: request.amount,
        utxoData: request.utxoData ?? null,
        memo: request.memo ?? null,
      },
      hash,
      request.asset,
      spl ?? undefined,
    );
  }

  instruction(tree: PublicKey, depositor: PublicKey): TransactionInstruction {
    return depositInstruction({
      tree,
      depositor,
      spl: this.spl,
      ...this.data,
    });
  }

  viewTag(): Uint8Array {
    return this.data.viewTag;
  }
}

export function createDeposit(request: CreateDeposit): Deposit {
  return Deposit.new(request);
}

export function splAccounts(
  asset: PublicKey,
  splTokenAccount?: PublicKey | null,
): DepositSplAccounts | undefined {
  if (asset.equals(SOL_MINT)) return undefined;
  if (!splTokenAccount) {
    throw new Error(`SPL token account is required for mint ${asset.toBase58()}`);
  }
  return {
    userToken: splTokenAccount,
    splTokenInterface: splAssetVault(asset),
    registry: splAssetRegistry(asset),
    tokenProgram: SPL_TOKEN_PROGRAM_ID,
  };
}
