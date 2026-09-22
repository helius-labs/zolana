/** Named exports the changelog promises, resolved through the package exports map. */
export {
  MAX_INPUT_TREES,
  ShieldedPoolError,
  decodeShieldedPoolError,
} from "@heliuslabs/zolana/interface";
export type {
  AuthorizedPrivateTransaction,
  ChainReader,
  IndexerReader,
  KitRpcAccess,
  MergeAssembler,
  MergeInputs,
  ProofAuthority,
  ProofReader,
  ProofService,
  ProvedMerge,
  ProverInputs,
  TransactionAssembler,
  TreeContext,
  WalletKeys,
} from "@heliuslabs/zolana/client";
export { LocalKeys } from "@heliuslabs/zolana/client";
export type {
  DecryptRequest,
  DeriveRequest,
  ShieldedKeys,
  TransactionKeyRequest,
} from "@heliuslabs/zolana/transaction";
export {
  LocalShieldedKeys,
  approveUnattended,
  encryptConfidentialTransfer,
} from "@heliuslabs/zolana/transaction";
export {
  LocalKeys as RootLocalKeys,
  LocalShieldedKeys as RootLocalShieldedKeys,
  type ShieldedKeys as RootShieldedKeys,
  type WalletKeys as RootWalletKeys,
} from "@heliuslabs/zolana";
export type {
  DepositClient,
  MergeClient,
  PrivateTransactionClient,
  SyncClient,
  SyncPersistedWalletResult,
  SyncWalletInput,
  WalletStateStore,
} from "@heliuslabs/zolana/wallet";
export { syncPersistedWallet, syncWallet } from "@heliuslabs/zolana/wallet";
export type { RingAuditReader, RingRpcOptions, RingTransferClient } from "@heliuslabs/zolana/ring";
export type {
  SerializedCursor,
  SerializedNoteReservation,
  SerializedSyncCursors,
} from "@heliuslabs/zolana/transaction";
export type {
  RingRpcOptions as RootRingRpcOptions,
  SerializedCursor as RootSerializedCursor,
  SerializedNoteReservation as RootSerializedNoteReservation,
  SerializedSyncCursors as RootSerializedSyncCursors,
  SyncPersistedWalletResult as RootSyncPersistedWalletResult,
  SyncWalletInput as RootSyncWalletInput,
  WalletStateStore as RootWalletStateStore,
} from "@heliuslabs/zolana";

import poolIdl from "@heliuslabs/zolana/idl/shieldedPool.json" with { type: "json" };
import registryIdl from "@heliuslabs/zolana/idl/userRegistry.json" with { type: "json" };
void poolIdl.program.instructions;
void registryIdl.program.instructions;
