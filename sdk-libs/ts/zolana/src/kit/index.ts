/**
 * App-facing Zolana surface plus `@solana/kit` adapters.
 * Install `@solana/kit` alongside this entry (peer of `@zolana/kit`).
 */
export { ZolanaClient, wait } from "@zolana/client";
export type { Instruction, Signature } from "@zolana/interface";
export { randomBlinding, type ShieldedKeypair } from "@zolana/keypair";
export {
  AssetRegistry,
  ConfidentialTransfer,
  SppProofInputUtxo,
  SOL_MINT,
  Wallet,
  decryptTransactions,
} from "@zolana/transaction";
export { createSolanaSigner, LocalWalletAuthority, syncWallet } from "@zolana/wallet";
export { createKitRpc, fromKitInstruction, fromKitSigner, toKitSigner } from "@zolana/kit";
export { depositInstruction, transactInstruction } from "@zolana/kit/instructions";
