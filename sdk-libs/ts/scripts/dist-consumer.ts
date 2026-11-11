export { bindProgramTransaction } from "@heliuslabs/spr/program";
export type { ProgramProofInputs, ProgramTransaction } from "@heliuslabs/spr/program";
import { AssetRegistry as ProgramAssets } from "@heliuslabs/spr/transaction";
import {
  bindProgramTransaction as bindStructuredTransaction,
  type ProgramTransaction as StructuredTransaction,
} from "@heliuslabs/spr/program";

/** The packed API binds a typed request and returns validated Xark inputs. */
export function structuredProgramBuilder(
  build: (input: { amount: bigint }, sender: Uint8Array, payer: string) => unknown,
): (
  input: { amount: bigint },
  sender: Uint8Array,
  payer: string,
) => Promise<StructuredTransaction> {
  return bindStructuredTransaction(build, { assets: new ProgramAssets() });
}
export { ed25519DerivationMessage, X25519PublicKey, X25519Keypair } from "@heliuslabs/spr/keypair";
export { ShieldedPda } from "@heliuslabs/spr/program";
/** Named exports the changelog promises, resolved through the package exports map. */
export {
  MAX_INPUT_TREES,
  ShieldedPoolError,
  UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
  decodeShieldedPoolError,
} from "@heliuslabs/spr/interface";
export type {
  ProvingKeyArtifact,
  ProvingKeyCheck,
  ProvingKeyReport,
  ProvingKeySet,
  ProvingKeySetKey,
  AuthorizedPrivateTransaction,
  ChainReader,
  IndexerReader,
  KitRpcAccess,
  MergeAssembler,
  MergeInputs,
  ProofAuthority,
  TransactKeys,
  ProofDataSource,
  ProofDataSourceContext,
  IndexedProofAuthority,
  IndexedProofInputs,
  IndexedProofResult,
  ProofResolution,
  ResolvedProofTree,
  PreparedTransferInput,
  PreparedTransferInputs,
  PreparedMergeInputs,
  ProofReader,
  ProofService,
  ProvedMerge,
  ProverInputs,
  TransactionAssembler,
  TreeContext,
  WalletKeys,
} from "@heliuslabs/spr/client";
export { LocalKeys, NullifierKeyProofAuthority, teePolicyFromJson } from "@heliuslabs/spr/client";
export type {
  DecryptRequest,
  DeriveRequest,
  MergeOutputCiphertext,
  ShieldedKeys,
  TransactionKeyRequest,
} from "@heliuslabs/spr/transaction";
export {
  LocalShieldedKeys,
  approveUnattended,
  encryptConfidentialTransfer,
} from "@heliuslabs/spr/transaction";
export {
  LocalKeys as RootLocalKeys,
  LocalShieldedKeys as RootLocalShieldedKeys,
  type ShieldedKeys as RootShieldedKeys,
  type WalletKeys as RootWalletKeys,
} from "@heliuslabs/spr";
export type {
  DepositClient,
  MergeClient,
  PrivateTransactionClient,
  SyncClient,
  SyncPersistedWalletResult,
  SyncWalletInput,
  WalletStateStore,
} from "@heliuslabs/spr/wallet";
export { syncPersistedWallet, syncWallet } from "@heliuslabs/spr/wallet";
export type {
  SerializedSyncCheckpoint,
  SerializedNoteReservation,
  SerializedSyncCheckpoints,
} from "@heliuslabs/spr/transaction";
export type { SettlementTransfer } from "@heliuslabs/spr/transaction";
export { encodeTransactInstructionData } from "@heliuslabs/spr/interface";
export { transactCpiAccounts } from "@heliuslabs/spr/program";
export type { TransactAccountsInput, TransactInstructionData } from "@heliuslabs/spr/interface";
export type { TransactAccountsInput as InstructionsTransactAccountsInput } from "@heliuslabs/spr/instructions";
export { bytes16, bytes31, bytes32, bytes33, bytes34, bytes64 } from "@heliuslabs/spr/keypair";
export type {
  DecodedProgramTransaction,
  ProgramData,
  ProgramDataRecord,
  ProgramEncryptOptions,
  ProgramFinalizedTransaction,
  ProgramMint,
  ProgramOwnerSeed,
  ProgramOwnerTag,
  ProgramProofInputUtxo,
  ProgramProofOutputUtxo,
  ProgramResolvedOwnerTag,
  ProgramSettlementTransfer,
  ProgramTransactionKeys,
  ProgramUtxo,
  ProgramWalletUtxo,
} from "@heliuslabs/spr/program";
export { Mint } from "@heliuslabs/spr/transaction";
export {
  ProgramOwner,
  decodeProgramTransaction,
  toProgramWalletUtxo,
} from "@heliuslabs/spr/program";
export type {
  SerializedSyncCheckpoint as RootSerializedSyncCheckpoint,
  SerializedNoteReservation as RootSerializedNoteReservation,
  SerializedSyncCheckpoints as RootSerializedSyncCheckpoints,
  SyncPersistedWalletResult as RootSyncPersistedWalletResult,
  SyncWalletInput as RootSyncWalletInput,
  WalletStateStore as RootWalletStateStore,
} from "@heliuslabs/spr";
export { ProverClient, indexerCodec } from "@heliuslabs/spr/internal";
