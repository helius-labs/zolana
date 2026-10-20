export { P256ReaderKey } from "@heliuslabs/zolana/ring";
export {
  memberRegistryLeaf,
  RING_DEPOSIT_AUDIT_SLOTS,
  encodeRingDepositCapsule,
  readRingDepositCapsule,
} from "@heliuslabs/zolana/ring/advanced";
export type {
  CustomRingBasePublicInput,
  MemberRegistryInsertProofInput,
} from "@heliuslabs/zolana/ring/advanced";
export { X25519PublicKey, X25519Keypair } from "@heliuslabs/zolana/keypair";
/** Named exports the changelog promises, resolved through the package exports map. */
export {
  MAX_INPUT_TREES,
  ShieldedPoolError,
  UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
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
  RingMemberRegistryReader,
  RingMemberProofRequest,
  RingMemberRequest,
  RingMemberRecordResponse,
  RingMemberRegistryTip,
  RingSubmissionTransport,
  CustomRingRecordWitness,
  CustomRingSubjectWitness,
  CustomRingUpdateMembersProofRequest,
  RingSealedNullifierKey,
  CustomRingRegisterKeyProofRequest,
  CustomRingDepositProofRequest,
  CustomRingMergeAnonymousProofRequest,
  CustomRingMergeSlot,
  WalletKeys,
} from "@heliuslabs/zolana/client";
export { outflowLimitsOff } from "@heliuslabs/zolana/client";
export { LocalKeys, NullifierKeyProofAuthority } from "@heliuslabs/zolana/client";
export type {
  DecryptRequest,
  DeriveRequest,
  MergeOutputCiphertext,
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
export type {
  DecryptedAnonymousRingTrace,
  RingAuditReader,
  RingRpcOptions,
  RingTransferClient,
} from "@heliuslabs/zolana/ring";
export {
  buildRingDelegateTransferTransaction,
  createRingDelegateSubmission,
  createRingTransferSubmission,
  createRingWithdrawalSubmission,
  createRingExitSubmission,
  createKitRingSubmissionTransport,
  createRingMemberRegistryRootInstruction,
  fetchRingMemberRegistryRoot,
  ringMemberRegistryRootAddress,
  decodeRingMemberRegistryRoot,
  prepareRingKeyRegistration,
  createRingKeyRegistrationSubmission,
  buildRingKeyRegistrationTransaction,
  sealNullifierKey,
  openNullifierKey,
  registeredKeyHash,
  registerKeyPublicInputHash,
  fetchRingSealedKey,
  openRingSealedKey,
  recoverRingMemberNotes,
  buildRingDelegateRecoveredTransaction,
  createRingDelegateRecoveredSubmission,
  registerRingKeyInstruction,
  buildRingDepositTransaction,
  initializeRingConfigInstructions,
  setRingDepositAuditInstruction,
  fetchRingDepositAudit,
  decodeRingDepositAudit,
  ringDepositAuditAddress,
  sealRingDepositOpenings,
  openRingDepositOpening,
  ConfirmedDeposit,
  ringDepositContextHash,
  ringDepositPublicInputHash,
} from "@heliuslabs/zolana/ring";
export type {
  RingDelegateTransferClient,
  RingDepositClient,
  RingDepositAudit,
  RingDepositOpening,
  AuditedDepositSource,
  RingDelegateTransferParams,
  RingTransactionSubmission,
  RingSubmissionResult,
  RingMemberRegistryRoot,
  RingKeyRegistrationClient,
  RingKeyRegistrationParams,
  RingKeyRegistrationPreparation,
  RingSealedKeyClient,
  RingSealedKeyEntry,
  SealedNullifierKey,
  NullifierKeyEnvelope,
  RegisterKeyStatement,
  RingRecoveryClient,
  RingRecoveryParams,
  RecoveredRingNotes,
  RingDelegateRecoveredParams,
} from "@heliuslabs/zolana/ring";
export type {
  SerializedCursor,
  SerializedNoteReservation,
  SerializedSyncCursors,
} from "@heliuslabs/zolana/transaction";
export type { SettlementTransfer } from "@heliuslabs/zolana/transaction";
export { encodeTransactInstructionData, transactCpiAccounts } from "@heliuslabs/zolana/interface";
export type { TransactAccountsInput, TransactInstructionData } from "@heliuslabs/zolana/interface";
export type { TransactAccountsInput as InstructionsTransactAccountsInput } from "@heliuslabs/zolana/instructions";
export { bytes16, bytes31, bytes32, bytes33, bytes34, bytes64 } from "@heliuslabs/zolana/keypair";
export type {
  RingRpcOptions as RootRingRpcOptions,
  SerializedCursor as RootSerializedCursor,
  SerializedNoteReservation as RootSerializedNoteReservation,
  SerializedSyncCursors as RootSerializedSyncCursors,
  SyncPersistedWalletResult as RootSyncPersistedWalletResult,
  SyncWalletInput as RootSyncWalletInput,
  WalletStateStore as RootWalletStateStore,
} from "@heliuslabs/zolana";

export {
  buildRingMergeTransaction,
  createRingMergeSubmission,
  customRingDepositPayload,
} from "@heliuslabs/zolana/ring";

export { MEMBER_REGISTRY_HEIGHT, MEMBER_REGISTRY_CAPACITY } from "@heliuslabs/zolana/interface";
export type {
  MemberRecord,
  MemberOpening,
  MemberUpdate,
  RecordUpdateWitness,
} from "@heliuslabs/zolana/interface";
export { RING_SUBJECT_SLOTS } from "@heliuslabs/zolana/client";
export {
  buildRingMemberUpdateTransaction,
  updateRingMembersInstruction,
  readRingMemberRecord,
  fetchRingMemberRecord,
} from "@heliuslabs/zolana/ring";

export { shareMemberSubtree } from "@heliuslabs/zolana/interface";
import type { CustomRingPolicyProofRequest } from "@heliuslabs/zolana/client";
import type { ProvenRingTransfer } from "@heliuslabs/zolana/ring";
import { ringTransactInstruction, ringDelegateTransactInstruction } from "@heliuslabs/zolana/ring";

export const fixedPolicyShape: Pick<CustomRingPolicyProofRequest, "twoByThree"> = {
  twoByThree: true,
};
export const fixedProvenShape: Pick<ProvenRingTransfer, "twoByThree"> = fixedPolicyShape;
export const fixedMemberInstruction: Pick<
  Parameters<typeof ringTransactInstruction>[0],
  "twoByThree"
> = fixedPolicyShape;
export const fixedDelegateInstruction: Pick<
  Parameters<typeof ringDelegateTransactInstruction>[0],
  "twoByThree"
> = fixedPolicyShape;
