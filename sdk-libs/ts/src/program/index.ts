/**
 * Experimental clients for ZK programs that own SPP UTXOs: program-owned
 * identities, the generated circuit transactions, and the accounts of a CPI
 * into `transact`. Every export may change in any release.
 *
 * @experimental
 * @module
 */
export { ShieldedPda } from "./shielded-pda.js";
export { ProgramOwner, type ProgramOwnerSeed } from "./program-owner.js";
export {
  bindProgramTransaction,
  decodeProgramTransaction,
  toProgramWalletUtxo,
  type DecodedProgramTransaction,
  type ProgramData,
  type ProgramDataRecord,
  type ProgramEncryptOptions,
  type ProgramFinalizedTransaction,
  type ProgramMint,
  type ProgramOwnerTag,
  type ProgramProofInputUtxo,
  type ProgramProofOutputUtxo,
  type ProgramResolvedOwnerTag,
  type ProgramSettlementTransfer,
  type ProgramTransactionKeys,
  type ProgramTransaction,
  type ProgramUtxo,
  type ProgramWalletUtxo,
} from "./program-transaction.js";
export { transactCpiAccounts } from "../interface/instructions/index.js";
