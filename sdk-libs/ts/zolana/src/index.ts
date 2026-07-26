/**
 * App-facing Zolana surface for the default (`@zolana/client`) transport.
 * Fine-grained `@zolana/*` packages remain the source of truth for advanced use.
 */
export { SolanaRpc, ZolanaClient, wait } from "@zolana/client";
export { depositInstruction, transactInstruction } from "@zolana/interface/instructions";
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
