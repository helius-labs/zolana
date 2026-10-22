export type { ErrorEnvelope } from "../errors/internal.js";
export { RING_ERROR_CODES, RingError, RingProgramError, wrapRingError } from "./error.js";
export type { RingErrorCode } from "./error.js";

export {
  ringAuthAddress,
  ringConfigAddress,
  ringMemberRegistryAddress,
  ringRecordQueueAddress,
} from "../interface/pda/index.js";
export {
  APPLY_DELAY_SLOTS,
  AUTHORITY_RESERVED_LEAVES,
  CUSTOM_RING_PROOF_LENGTH,
  DEFAULT_INSERT_FEE,
  GRACE_SLOTS,
  MEMBER_QUEUE_LIMIT,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_SCOPE_MASK,
  RING_COSIGN_THRESHOLD_SLOTS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  checkedCustomRingProof,
  decodeRingMemberRegistry,
  decodeRingProgramConfig,
  decodeRingRecordQueue,
  queueAdmitsMemberWrite,
  queueApplyDue,
  queueChainTail,
  queuePending,
  registryCurator,
  registryCuratorRoot,
  registryCurrentRoot,
  registryOwnRoot,
} from "./codecs.js";
export type {
  RingCoSignThreshold,
  RingCoSigner,
  RingMemberRegistry,
  RingMode,
  RingProgramConfig,
  RingQueueCheckpoint,
  RingRecordQueue,
  RingRootEntry,
  RingSourceSlot,
} from "./codecs.js";
export {
  BPF_LOADER_UPGRADEABLE_ID,
  fetchCuratorRegistry,
  fetchRingMemberRegistry,
  fetchRingProgramConfig,
  fetchRingRecordQueue,
  requireActiveRing,
  ringProgramDataAddress,
} from "./config.js";
export { ringRole, type RingRole } from "./role.js";
export { listRegisteredRings, type RegisteredRing } from "./registry.js";
export { ringTreeIdResolver } from "./trees.js";

export {
  RingInstructionTag,
  clearRingCoSignerInstruction,
  createMemberRegistryInstruction,
  createRingConfigInstruction,
  createRingPolicyInstruction,
  initSppRingConfigInstruction,
  ringComputeUnitLimit,
  setRingAuthorityInstruction,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  setRingInsertFeeInstruction,
  setRingPausedInstruction,
  setRingPolicyRulesInstruction,
  setRingPolicySourceInstruction,
} from "./admin.js";
export type {
  RingKind,
  RingPolicySourceOwner,
  RingPolicyTableInput,
  RingSharedSource,
} from "./admin.js";
export {
  buildRingCreatePolicyTransaction,
  buildRingSetPolicyRulesTransaction,
  buildRingSetPolicySourceTransaction,
} from "./policy-admin.js";
export type {
  RingCreatePolicyTransactionParams,
  RingPolicyAdminClient,
  RingSetPolicyRulesTransactionParams,
  RingSetPolicySourceTransactionParams,
} from "./policy-admin.js";
export {
  CLOCK_SYSVAR,
  RENT_SYSVAR,
  RingProgramBinary,
  closeBufferInstruction,
  decodeRingProgramData,
  deployRingProgram,
  deployWithMaxDataLenInstruction,
  extendProgramInstruction,
  fetchRingProgramData,
  initializeBufferInstruction,
  setUpgradeAuthorityInstruction,
  upgradeInstruction,
  verifyRingProgram,
  writeBufferInstruction,
} from "./program.js";
export type {
  RingProgramData,
  RingProgramDeployClient,
  RingProgramDeployOutcome,
  RingProgramDeployParams,
} from "./program.js";

export {
  AUTHORITY_WRITABLE_LISTS,
  AuthorityListWrite,
  MEMBER_WRITABLE_LISTS,
  RecordApplication,
  feeAccounts,
  listWrite,
  memberListWriteInstruction,
} from "./records.js";
export type {
  ListWrite,
  ProvenRecordWrite,
  RecordQueueBinding,
  RingRecordApplicationClient,
  RingRecordWriteClient,
} from "./records.js";
export { MemberOpeningRead } from "./member-registry.js";
export type { EscrowedRecord } from "./member-registry.js";
export { checkEscrowedRecipients, readMemberRecords } from "./registered-record.js";
export type { RingRecordReadClient } from "./registered-record.js";
export {
  NF_KEY_ENC_INFO,
  NullifierKeyEscrow,
  RegisterKey,
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  sealNullifierKey,
} from "./register-key.js";
export type {
  KeyEscrowAuthority,
  KeyEscrowRequest,
  NullifierKeyEnvelope,
  ProvenEscrow,
  ProvenKeyRegistration,
  RingKeyRegistrationClient,
  RingSealedKeyClient,
  RingSealedKeyEntry,
  SealedNullifierKey,
} from "./register-key.js";

export {
  PreparedRingDeposit,
  RING_DEPOSIT_COMPUTE_UNIT_LIMIT,
  buildRingDepositTransaction,
} from "./deposit.js";
export type {
  ProvenRingDeposit,
  RingDepositClient,
  RingDepositParams,
  RingDepositRecipient,
} from "./deposit.js";
export { ringDepositInstruction } from "./deposit-instruction.js";
export { customRingDepositPayload, decryptRingDepositUtxo } from "./deposit-payload.js";
export {
  decodeRingDepositOutput,
  decodeRingDepositPlaintext,
  encodeRingDepositPlaintext,
} from "../transaction/serialization/ring-deposit.js";
export type {
  RingDepositOutput,
  RingDepositPlaintext,
} from "../transaction/serialization/ring-deposit.js";
export {
  openRingDepositOpening,
  ringDepositContextHash,
  ringDepositPublicInputHash,
  sealRingDepositOpenings,
} from "./deposit-audit.js";
export type { RingDepositOpening } from "./deposit-audit.js";

export { ANCHOR_DECOYS, messageSignerSpendSigner, signingKeySpendSigner } from "./anonymous.js";
export type { AnonymousPayment, AnonymousSpendSigner } from "./anonymous.js";
export { AnonymousTransfer, CustomRingTransfer, DelegateTransfer } from "./rails.js";
export type {
  AnonymousTransferClient,
  CustomRingTransferClient,
  CustomRingTransferInput,
  DelegateOutput,
  DelegateTransferClient,
  DelegateTransferInput,
} from "./rails.js";
export { ProvenRingTransfer, ringTransactInstruction } from "./pipeline.js";
export type {
  PendingFirstContact,
  RingBoundState,
  RingProvingClient,
  RingTransactAccounts,
} from "./pipeline.js";
export type { BoundPolicy, BoundRoot } from "./policy-proof.js";
export type { BoundAnchor } from "./trees.js";
export { ringTransactAccounts } from "../interface/instructions/index.js";
export {
  buildRingEntryTransaction,
  buildRingExitTransaction,
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
  createRingExitSubmission,
  createRingTransferSubmission,
  createRingWithdrawalSubmission,
} from "./transfer.js";
export type {
  AnonymousRingSpend,
  RingEntryTransactionParams,
  RingExitTransactionParams,
  RingSpendParams,
  RingTransferClient,
  RingTransferTransactionParams,
  RingWithdrawalTransactionParams,
} from "./transfer.js";
export {
  buildRingDelegateRecoveredTransaction,
  buildRingDelegateTransferTransaction,
  createRingDelegateRecoveredSubmission,
  createRingDelegateSubmission,
} from "./delegate.js";
export type {
  RingDelegateRecoveredClient,
  RingDelegateRecoveredParams,
  RingDelegateTransferClient,
  RingDelegateTransferParams,
} from "./delegate.js";
export {
  RING_MERGE_COMPUTE_UNIT_LIMIT,
  buildRingMergeTransaction,
  createRingMergeSubmission,
  ringMergeInstruction,
} from "./merge.js";
export type { RingMergeTransactionParams } from "./merge.js";
export type { RingMergeClient } from "../client/ports.js";
export {
  RingTransactionSubmission,
  createKitRingSubmissionTransport,
  reconcileRingSubmissions,
} from "./submission.js";
export type {
  ReservationHold,
  RingSubmissionAttempt,
  RingSubmissionBuild,
  RingSubmissionResult,
} from "./submission.js";

export {
  auditRing,
  auditRingTransaction,
  auditedUtxos,
  auditorMessage,
  hasUnknownAssets,
  knownUtxoHash,
  openedUtxo,
  recoverTransactionViewingKey,
} from "./audit.js";
export type {
  AuditedInput,
  AuditedInputOpening,
  AuditedRingOutput,
  AuditedRingTransaction,
  AuditedSender,
  AuditedUtxo,
  CreatedRingUtxo,
  EscrowedKeys,
  InputRing,
  KnownUtxo,
  KnownUtxos,
  OutputOpening,
  OutputPayloadError,
  OutputPayloadErrorKind,
  RingAuditPage,
  RingAuditReader,
  UtxoOwner,
} from "./audit.js";
export { auditRingMerges } from "./audit-merge.js";
export { createdRingUtxos, scanCreatedRingUtxos } from "./created.js";
export type { CreatedRingUtxosPage } from "./created.js";
export type {
  AuditedRingMerge,
  MergeKeys,
  RingMergeAuditPage,
  RingMergeAuditReader,
  UnresolvedRingMerge,
} from "./audit-merge.js";
export {
  mergeDisclosureFieldCount,
  openRingMergeDisclosure,
  ringMergeAnonymousPublicInputHash,
} from "./merge-disclosure.js";
export type { RingMergeDisclosure, RingMergeOpening } from "./merge-disclosure.js";
export { recoverRingMemberNotes } from "./recover.js";
export type { RecoveredRingNotes, RingRecoveryClient, RingRecoveryParams } from "./recover.js";
export {
  ConfirmedDeposit,
  ORIGIN_TRANSACTION_CONFIG,
  RpcTransactionOrigin,
  confirmedInstructionGroups,
  confirmedRingWithdrawals,
  ringInstructionsIn,
  ringInvokedIn,
  ringWithdrawalsOf,
  senderOf,
} from "./origin.js";
export type {
  ConfirmedEventKind,
  ConfirmedRingTransaction,
  OriginInstruction,
  OriginInstructionGroup,
  RingWithdrawal,
  TransactionOrigin,
} from "./origin.js";
export {
  RING_AUDITED_UTXOS_LIMIT,
  RING_PAYLOAD_ERROR_KINDS,
  RING_READ_CURSOR_LIMIT,
  RING_READ_PAGE_LIMIT,
  RingAuditedUtxosRequest,
  RingAuditorKeyRequest,
  RingReadRequest,
  RingRpc,
  auditedUtxosAttestation,
  auditorKeyStatement,
  auditorKeyRequestAttestation,
  messageSignerReader,
  ringReadAttestation,
} from "./rpc.js";
export type {
  AuditedMergesPage,
  DecryptedOutputContext,
  DecryptedRingOutput,
  DecryptedRingTransaction,
  DecryptedRingTransactionsPage,
  DecryptedRingWithdrawal,
  RingActivation,
  RingAuditedUtxo,
  RingAuditedUtxosPage,
  RingAuditorKey,
  RingDeposit,
  RingDepositsPage,
  RingKeyMode,
  RingPagedRead,
  RingReadSigner,
  RingReadTarget,
  RingRegistryStatus,
  RingRpcHealth,
  RingRpcOptions,
  RingState,
  RingStatus,
  SignedAuditedUtxosRead,
  SignedAuditorKeyRequest,
  SignedRingRead,
  SkippedReason,
  SkippedRingTransaction,
  WebAuthnSignature,
} from "./rpc.js";
export {
  P256ReaderKey,
  checkedReaderKey,
  decodeReadAccessRecord,
  fetchReaderGrant,
  grantReadAccessInstruction,
  parseReaderKey,
  readAccessRecordAddress,
  readerKeyBytes,
  readerKeyEquals,
  readerKeyFromBytes,
  readerKeyToString,
  revokeReadAccessInstruction,
} from "./reader.js";
export type { ReadAccessRecord, ReaderKey } from "./reader.js";
export { createPasskey, passkeyReader, type Passkey } from "./passkey.js";
