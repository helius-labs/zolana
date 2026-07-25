# Public export manifest

This is the strict TypeScript allowlist for frozen Rust revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`. Symbols not declared here are
internal. `@zolana/interface` exports these shared types; every other package
imports them rather than defining a competing representation:

```ts
export type Address = string & { readonly __address: unique symbol };
export type Signature = string & { readonly __signature: unique symbol };
export type Bytes16 = Uint8Array & { readonly __bytes16: unique symbol };
export type Bytes31 = Uint8Array & { readonly __bytes31: unique symbol };
export type Bytes32 = Uint8Array & { readonly __bytes32: unique symbol };
export type Bytes33 = Uint8Array & { readonly __bytes33: unique symbol };
export type Bytes64 = Uint8Array & { readonly __bytes64: unique symbol };
export type Bytes128 = Uint8Array & { readonly __bytes128: unique symbol };
export type Transaction = Readonly<{
  messageBytes: Uint8Array;
  signatures: readonly (Signature | undefined)[];
}>;
export type Instruction = Readonly<{
  programAddress: Address;
  accounts: readonly Readonly<{
    address: Address;
    isSigner: boolean;
    isWritable: boolean;
  }>[];
  data: Uint8Array;
}>;
export interface RequestContext {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}
```

Checked byte constructors validate exact length and copy their input. Address,
signature, integer, enum, and collection validation occurs before I/O. Every
package error has `readonly code`, `readonly details?`, and `readonly cause?`.

## `@zolana/interface`

Source: [`program-libs/interface/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/lib.rs),
[`instruction/mod.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/mod.rs),
[`instruction/builders/mod.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/mod.rs),
and [`state/mod.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/state/mod.rs).

```ts
export const SHIELDED_POOL_PROGRAM_ID: Address;
export const DEFAULT_TREE_ADDRESS: Address;
export const SOL_INTERFACE: Address;
export const SHIELDED_POOL_CPI_AUTHORITY: Address;
export const SPL_TOKEN_PROGRAM_ID: Address;
export const ASSOCIATED_TOKEN_PROGRAM_ID: Address;
export const UTXO_DOMAIN: 1;

export const InstructionTag: Readonly<{
  transact: 0;
  deposit: 1;
  zoneTransact: 2;
  zoneAuthorityTransact: 3;
  createSplInterface: 4;
  createTree: 5;
  createProtocolConfig: 6;
  updateProtocolConfig: 7;
  pauseTree: 8;
  createZoneConfig: 9;
  updateZoneConfigOwner: 10;
  updateZoneConfig: 11;
  mergeTransact: 12;
  zoneMergeTransact: 13;
  emitEvent: 14;
  zoneDeposit: 15;
  createAssetCounter: 16;
  batchUpdateNullifierTree: 51;
}>;
export type InstructionTag = typeof InstructionTag[keyof typeof InstructionTag];

export interface DepositInstructionData {
  readonly viewTag: Bytes32;
  readonly owner: Bytes32;
  readonly blinding: Bytes31;
  readonly amount: bigint;
  readonly utxoData?: Readonly<{ dataHash: Bytes32; data: Uint8Array }>;
  readonly memo?: Uint8Array;
}
export interface DepositSplAccounts {
  readonly userToken: Address;
  readonly splTokenInterface: Address;
  readonly registry: Address;
  readonly tokenProgram: Address;
}
export interface InputUtxo {
  readonly nullifierHash: Bytes32;
  readonly nullifierTreeRootIndex: number;
  readonly utxoTreeRootIndex: number;
  readonly treeIndex: number;
  readonly eddsaSignerIndex: number;
}
export type OwnerTag =
  | Readonly<{ kind: "inline"; value: Bytes32 }>
  | Readonly<{ kind: "account"; index: number }>
  | Readonly<{ kind: "p256SigningKey" }>;
export interface TransactOutput {
  readonly utxoHash: Bytes32;
  readonly ownerTag: OwnerTag;
  readonly data?: Uint8Array;
}
export type TransactProof =
  | Readonly<{ rail: "eddsa"; a: Bytes32; b: Bytes64; c: Bytes32 }>
  | Readonly<{
      rail: "p256";
      a: Bytes32;
      b: Bytes64;
      c: Bytes32;
      commitment: Bytes32;
      commitmentPok: Bytes32;
    }>;
export interface TransactInstructionData {
  readonly proof: TransactProof;
  readonly expiryUnixTs: bigint;
  readonly relayerFee: number;
  readonly privateTxHash: Bytes32;
  readonly p256SigningPkX?: Bytes32;
  readonly txViewingPk: Bytes33;
  readonly salt: Bytes16;
  readonly inputs: readonly InputUtxo[];
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly outputs: readonly TransactOutput[];
  readonly messages: readonly Readonly<{ viewTag: Bytes32; data: Uint8Array }>[];
}
export type TransactWithdrawal =
  | Readonly<{ kind: "sol"; recipient: Address }>
  | Readonly<{
      kind: "spl";
      cpiAuthority?: Address;
      splTokenInterface: Address;
      recipient: Address;
      userTokenAccount: Address;
      tokenProgram: Address;
    }>;
export interface ProtocolConfigAccount {
  readonly authority: Address;
  readonly treeCreationAuthority: Address;
  readonly treeCreationIsPermissionless: boolean;
  readonly foresterAuthority: Address;
  readonly zoneCreationAuthority: Address;
  readonly zoneCreationIsPermissionless: boolean;
  readonly splInterfaceCreationIsPermissionless: boolean;
}
export interface SplAssetCounterAccount { readonly nextId: bigint }
export interface SplAssetRegistryAccount {
  readonly mint: Address;
  readonly assetId: bigint;
}
export interface ZoneConfigAccount {
  readonly authority: Address;
  readonly programId: Address;
  readonly zoneAuthorityTransactIsEnabled: boolean;
  readonly bump: number;
}

export class InterfaceError extends Error {
  readonly code: InterfaceErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export type InterfaceErrorCode =
  | "INTERFACE_INVALID_ADDRESS" | "INTERFACE_INVALID_LENGTH"
  | "INTERFACE_INVALID_INTEGER" | "INTERFACE_INVALID_DISCRIMINATOR"
  | "INTERFACE_INVALID_ACCOUNT_DATA" | "INTERFACE_INVALID_PDA"
  | "INTERFACE_CODEC";
export type ShieldedPoolErrorCode = 7000 | 7001 | 7002 | 7003 | 7004 | 7005
  | 7006 | 7007 | 7008 | 7009 | 7010 | 7011 | 7012 | 7013 | 7014 | 7015
  | 7016 | 7017 | 7018 | 7019 | 7020 | 7021 | 7022 | 7023 | 7024 | 7025;

export function decodeProtocolConfig(data: Uint8Array): ProtocolConfigAccount;
export function decodeSplAssetCounter(data: Uint8Array): SplAssetCounterAccount;
export function decodeSplAssetRegistry(data: Uint8Array): SplAssetRegistryAccount;
export function decodeZoneConfig(data: Uint8Array): ZoneConfigAccount;
```

`InstructionTag` is the complete numeric map from frozen
[`event/src/tag.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/event/src/tag.rs);
TypeScript changes only Rust PascalCase names to camelCase. In particular,
`zoneMergeTransact` is tag `13`, `emitEvent` is tag `14`, and ATA creation has
no shielded-pool tag because it targets the SPL associated-token program.
`InputUtxo`, `OwnerTag`, `TransactOutput`, `TransactProof`, and
`TransactInstructionData` map every frozen field from
[`instruction_data/transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/instruction_data/transact.rs).
The P256 commitment and proof-of-knowledge are compressed 32-byte G1 points;
`relayerFee` is a validated `number` because its wire type is `u16`.

The decoders are synchronous, return owned readonly values, require exact
account size and discriminator, and throw `InterfaceError`. They map
`ProtocolConfig`, `SplAssetCounter`, `SplAssetRegistry::from_account_bytes`,
and `ZoneConfig` in
[`state/`](https://github.com/helius-labs/zolana/tree/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/state). TypeScript deliberately
does not expose mutable account initialization methods.

`@zolana/interface/pda`:

```ts
export function protocolConfigAddress(): Address;
export function solInterfaceAddress(): Address;
export function shieldedPoolCpiAuthorityAddress(): Address;
export function splAssetCounterAddress(): Address;
export function splAssetRegistryAddress(mint: Address): Address;
export function splAssetVaultAddress(mint: Address): Address;
export function zoneConfigAddress(zoneProgram: Address): readonly [Address, number];
export function associatedTokenAddress(owner: Address, mint: Address): Address;
```

These synchronous functions map the same-named helpers in
[`pda.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/pda.rs). They validate addresses,
return canonical addresses plus a bump only where Rust returns one, and throw
`InterfaceError`; no RPC lookup occurs.

`@zolana/interface/codecs`:

```ts
export interface Codec<T> {
  encode(value: T): Uint8Array;
  decode(bytes: Uint8Array): T;
}
export const depositInstructionDataCodec: Codec<DepositInstructionData>;
export const transactInstructionDataCodec: Codec<TransactInstructionData>;
export const protocolConfigAccountCodec: Codec<ProtocolConfigAccount>;
export const splAssetCounterAccountCodec: Codec<SplAssetCounterAccount>;
export const splAssetRegistryAccountCodec: Codec<SplAssetRegistryAccount>;
export const zoneConfigAccountCodec: Codec<ZoneConfigAccount>;
```

Codecs are synchronous, own encoded/decoded bytes, reject trailing or malformed
data with `InterfaceError`, and preserve the exact frozen Rust Borsh/wincode/
fixed layouts. They are not generic serialization utilities.

`@zolana/interface/instructions` maps each Rust builder struct's public fields
to one object parameter and `.instruction()` to a function:

One Rust builder has no counterpart. `BatchUpdateNullifierTree` is withdrawn:
its `compressedProof` comes from the `address-append` circuit, and no TypeScript
path can prove it, so the builder advertised the last step of a pipeline whose
earlier steps this SDK does not ship. `batchUpdateNullifierTreeDataCodec` stays,
because a tool that finds the instruction in a transaction can still read it.
`interface/test/exports.test.ts` fails if the builder returns.

```ts
export function createAssetCounterInstruction(input: Readonly<{
  authority: Address;
}>): Instruction;
export function createAssociatedTokenAccountInstruction(input: Readonly<{
  payer: Address; owner: Address; mint: Address;
}>): Instruction;
export function createSplInterfaceInstruction(input: Readonly<{
  authority: Address; mint: Address;
}>): Instruction;
export function createTreeInstruction(input: Readonly<{
  authority: Address; tree: Address; owner: Address;
}>): Instruction;
export function depositInstruction(input: Readonly<{
  tree: Address; depositor: Address; spl?: DepositSplAccounts;
  data: DepositInstructionData;
}>): Instruction;
export function transactInstruction(input: Readonly<{
  payer: Address; tree: Address; withdrawal?: TransactWithdrawal;
  data: TransactInstructionData;
}>): Instruction;
export function createProtocolConfigInstruction(input: Readonly<{
  authority: Address; protocolAuthority: Address;
  treeCreationAuthority: Address; treeCreationIsPermissionless: boolean;
  foresterAuthority: Address; zoneCreationAuthority: Address;
  zoneCreationIsPermissionless: boolean;
  splInterfaceCreationIsPermissionless: boolean;
}>): Instruction;
export type ProtocolConfigUpdate =
  | Readonly<{ field: "protocolAuthority"; value: Address }>
  | Readonly<{ field: "treeCreationAuthority"; value: Address }>
  | Readonly<{ field: "foresterAuthority"; value: Address }>
  | Readonly<{ field: "zoneCreationAuthority"; value: Address }>
  | Readonly<{ field: "treeCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "zoneCreationPermissionless"; value: boolean }>
  | Readonly<{ field: "splInterfaceCreationPermissionless"; value: boolean }>;
export function updateProtocolConfigInstruction(input: Readonly<{
  authority: Address; update: ProtocolConfigUpdate;
}>): Instruction;
export function pauseTreeInstruction(input: Readonly<{
  authority: Address; tree: Address; paused: boolean;
}>): Instruction;
export function createZoneConfigInstruction(input: Readonly<{
  payer: Address; programId: Address; authority: Address;
  zoneAuthorityTransactIsEnabled: boolean;
}>): Instruction;
export function updateZoneConfigInstruction(input: Readonly<{
  authority: Address; zoneConfig: Address;
  zoneAuthorityTransactIsEnabled: boolean;
}>): Instruction;
export function updateZoneConfigOwnerInstruction(input: Readonly<{
  authority: Address; zoneConfig: Address; newAuthority: Address;
}>): Instruction;
export function zoneDepositInstruction(input: Readonly<{
  tree: Address; depositor: Address; spl?: DepositSplAccounts;
  viewTag: Bytes32; owner: Bytes32; blinding: Bytes31; amount: bigint;
  zoneProgramId: Address; zoneDataHash: Bytes32; zoneData: Uint8Array;
  utxoData?: Readonly<{ dataHash: Bytes32; data: Uint8Array }>;
  memo?: Uint8Array; cpi?: boolean;
}>): Instruction;
export function zoneTransactInstruction(input: Readonly<{
  payer: Address; tree: Address; zoneProgramId: Address;
  withdrawal?: TransactWithdrawal; data: TransactInstructionData; cpi?: boolean;
}>): Instruction;
export function zoneAuthorityTransactInstruction(input: Readonly<{
  payer: Address; tree: Address; zoneProgramId: Address;
  withdrawal?: TransactWithdrawal; data: TransactInstructionData; cpi?: boolean;
}>): Instruction;
export interface MergeTransactInstructionData {
  readonly expiryUnixTs: bigint;
  readonly proof: Readonly<{
    a: Bytes32; b: Bytes64; c: Bytes32;
    commitment: Bytes32; commitmentPok: Bytes32;
  }>;
  readonly outputUtxoHash: Bytes32;
  readonly nullifiers: readonly Bytes32[];
  readonly utxoTreeRootIndexes: readonly number[];
  readonly nullifierTreeRootIndexes: readonly number[];
  readonly privateTxHash: Bytes32;
  readonly encryptedUtxo: Uint8Array;
  readonly eddsaOwner: boolean;
}
export function mergeTransactInstruction(input: Readonly<{
  tree: Address; payer: Address; userRecord: Address;
  data: MergeTransactInstructionData;
}>): Instruction;
export function mergeZoneInstruction(input: Readonly<{
  tree: Address; zoneProgramId: Address; payer: Address;
  data: MergeTransactInstructionData; mergeViewTag: Bytes32; cpi?: boolean;
}>): Instruction;

export const MERGE_INPUTS: 8;
```

All builders are synchronous, return a newly owned `Instruction`, validate
integer/byte bounds and incompatible settlement variants, and throw
`InterfaceError`. The merge declarations map field-for-field from
[`merge_transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/merge_transact.rs)
and [`merge_zone.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/merge_zone.rs);
their fixed shape requires eight nullifiers, eight indexes in each root-index
array, and a 110-byte encrypted UTXO.

## `@zolana/keypair`

Source: [`sdk-libs/keypair/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/lib.rs) and
the linked implementation modules.

```ts
export type SignatureType = "p256" | "ed25519";
export type ViewTag = Bytes32;
export type Salt = Bytes16;
export type EcdsaSignature = Bytes64;
export class KeypairError extends Error {
  readonly code: KeypairErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export type KeypairErrorCode =
  | "KEYPAIR_INVALID_LENGTH" | "KEYPAIR_INVALID_PUBLIC_KEY"
  | "KEYPAIR_INVALID_SECRET_KEY" | "KEYPAIR_INVALID_SIGNATURE_TYPE"
  | "KEYPAIR_INVALID_SIGNATURE" | "KEYPAIR_ENCRYPTION"
  | "KEYPAIR_DECRYPTION" | "KEYPAIR_HASH";

export class P256PublicKey {
  static fromBytes(bytes: Bytes33): P256PublicKey;
  toBytes(): Bytes33;
  x(): Bytes32;
  yIsOdd(): boolean;
}
export class ShieldedPublicKey {
  static zeroed(): ShieldedPublicKey;
  static fromP256(key: P256PublicKey): ShieldedPublicKey;
  static fromEd25519(bytes: Bytes32): ShieldedPublicKey;
  static fromBytes(bytes: Bytes33): ShieldedPublicKey;
  toBytes(): Bytes33;
  isZero(): boolean;
  signatureType(): SignatureType;
  confidentialViewTag(): ViewTag;
  hash(): Bytes32;
  ownerPublicKeyField(): Bytes32;
}
export class SigningKey {
  static generate(type?: SignatureType): SigningKey;
  static fromBytes(bytes: Bytes32): SigningKey;
  static fromEd25519Bytes(bytes: Bytes32): SigningKey;
  publicKey(): ShieldedPublicKey;
  sign(message: Uint8Array): Bytes64;
  verify(message: Uint8Array, signature: Bytes64): boolean;
  secretBytes(): Bytes32;
  destroy(): void;
}
export class NullifierKey {
  static fromSigningKey(key: SigningKey): NullifierKey;
  static fromSigningSecret(bytes: Uint8Array): NullifierKey;
  static fromSecret(bytes: Bytes31): NullifierKey;
  publicKey(): Bytes32;
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32;
  secretBytes(): Bytes31;
  destroy(): void;
}
export class ViewingKey {
  static generate(): ViewingKey;
  static fromBytes(bytes: Bytes32): ViewingKey;
  static fromSeed(walletSeed: Bytes32, account: number): ViewingKey;
  publicKey(): P256PublicKey;
  secretBytes(): Bytes32;
  ecdh(counterparty: P256PublicKey): Bytes32;
  senderViewTag(txCount: bigint): ViewTag;
  recipientRequestViewTag(requestCount: bigint): ViewTag;
  mergeViewTag(mergeCount: bigint): ViewTag;
  sendSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag;
  recipientSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag;
  recipientBootstrapViewTag(): ViewTag;
  transactionViewingKey(firstNullifier: Bytes32): ViewingKey;
  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array;
  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array;
  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array;
  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ): Readonly<{
    ciphertext: Uint8Array;
    txViewingPublicKey: P256PublicKey;
  }>;
  decryptVerifiable(
    txViewingPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
  ): Uint8Array;
  destroy(): void;
}
export interface ShieldedAddress {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
  readonly viewingPublicKey: P256PublicKey;
  ownerHash(): Bytes32;
  solanaAddress(): Address;
  confidentialViewTag(): ViewTag;
}
export interface CompressedShieldedAddress { readonly bytes: Uint8Array }
export class ShieldedKeypair {
  static generate(): ShieldedKeypair;
  static fromKeys(signing: SigningKey, nullifier: NullifierKey, viewing: ViewingKey): ShieldedKeypair;
  static fromEd25519(secret: Bytes32, account: number): ShieldedKeypair;
  signingPublicKey(): ShieldedPublicKey;
  viewingPublicKey(): P256PublicKey;
  shieldedAddress(): ShieldedAddress;
  compressedAddress(): CompressedShieldedAddress;
  sign(message: Uint8Array): Bytes64;
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32;
  destroy(): void;
}
export interface ShieldedKeypairLike {
  shieldedAddress(): ShieldedAddress;
  sign(message: Uint8Array): Bytes64 | Promise<Bytes64>;
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32 | Promise<Bytes32>;
}
export interface ViewingKeyLike {
  publicKey(): P256PublicKey;
  transactionViewingKey(firstNullifier: Bytes32): ViewingKey | Promise<ViewingKey>;
}
export function randomBlinding(): Bytes31;
export function randomSalt(): Salt;
```

Factories and pure methods are synchronous and map
[`pubkey.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/pubkey.rs),
[`signing_key.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/signing_key.rs),
[`nullifier_key.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/nullifier_key.rs),
[`viewing_key.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/viewing_key.rs), and
[`shielded.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/shielded.rs). They validate lengths,
curve points, counters, and signatures; return owned copies; and throw
`KeypairError`. `destroy()` is a TypeScript-only best-effort zeroization method.
`P256Pubkey` and scheme-tagged `PublicKey` are deliberately renamed.
`senderViewTag`, `recipientRequestViewTag`, `mergeViewTag`,
`sendSharedViewTag`, and `recipientSharedViewTag` only camel-case and shorten
the corresponding Rust `get_*` names. Their required counters and
counterparties are unchanged.

The slot methods preserve the recipient or transaction viewing public key,
transaction salt, and `u32` slot index from
[`encryption.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/encryption.rs)
and
[`ViewingKeyTrait`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/traits/view_key.rs).
`transactionViewingKey` takes only the first nullifier and returns the derived
`ViewingKey`; the transaction salt belongs to slot encryption, not key
derivation. `ViewingKeyLike` is the deliberately minimal, optionally async
TypeScript authority boundary rather than a rename of the complete Rust trait,
but its retained method has the same input and result. The slot signatures and
separation behavior are pinned by
[`tests/steps/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/tests/steps/transaction.rs);
view-tag and transaction-viewing-key derivation are pinned by
[`tests/steps/viewing.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/tests/steps/viewing.rs).

`@zolana/keypair/hash`:

```ts
export function splitBigEndian128(value: Uint8Array): readonly [Uint8Array, Uint8Array];
export function hashField(value: Uint8Array): Bytes32;
export function hashPublicKeyX(x: Uint8Array, yIsOdd: boolean): Uint8Array;
export function ownerHash(ownerPublicKeyField: Uint8Array, nullifierPublicKey: Uint8Array): Uint8Array;
export function pack33(bytes: Uint8Array): readonly [Uint8Array, Uint8Array];
export function sha256Bytes(bytes: Uint8Array): Bytes32;
export function sha256Be(bytes: Uint8Array): Bytes32;
export function fieldFromBytes(bytes: Uint8Array): Uint8Array;
```

These pure helpers map Rust `zolana_keypair::hash`. Dependent packages import
this subpath instead of maintaining independent implementations.

`@zolana/keypair/merge`:

```ts
export const MERGE_INFO: Uint8Array;
export interface MergeCiphertextPublicInputs {
  readonly txViewingPublicKeyLow: Bytes32;
  readonly txViewingPublicKeyHigh: Bytes32;
  readonly ciphertextHash: Bytes32;
}
export function encryptVerifiable(
  txViewingSecret: Bytes32,
  userViewingPublicKey: P256PublicKey,
  plaintext: Uint8Array,
): Readonly<{
  ciphertext: Uint8Array;
  txViewingPublicKey: P256PublicKey;
}>;
export function decryptVerifiable(
  userViewingSecret: Bytes32,
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
): Uint8Array;
export function mergePublicContribution(
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
): MergeCiphertextPublicInputs;
export function mergeCiphertextHash(ciphertext: Uint8Array): Bytes32;
```

These synchronous functions map [`merge.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/merge.rs),
copy outputs, validate secret-key lengths and public keys, and throw
`KeypairError`. TypeScript replaces Rust's
`(Vec<u8>, P256Pubkey)` encryption tuple with the named readonly
`{ ciphertext, txViewingPublicKey }` object. `MergeCiphertextPublicInputs`
renames Rust's `tx_viewing_pk_lo` and `tx_viewing_pk_hi` fields but preserves
both limbs and `ciphertext_hash`; it does not collapse them into a synthetic
contribution. `symmetric_apply` remains internal.

## `@zolana/transaction`

Source: [`sdk-libs/transaction/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/lib.rs).

```ts
export class TransactionError extends Error {
  readonly code: TransactionErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export type TransactionErrorCode = `TRANSACTION_${string}`;
export type DataRecord =
  | Readonly<{ kind: "zoneData"; bytes: Uint8Array }>
  | Readonly<{ kind: "utxoData"; bytes: Uint8Array }>
  | Readonly<{ kind: "memo"; bytes: Uint8Array }>;
export class Data {
  constructor(records?: readonly DataRecord[]);
  validate(): void;
  zoneData(): Uint8Array | undefined;
  utxoData(): Uint8Array | undefined;
  memo(): Uint8Array | undefined;
}
export type Blinding = Bytes31;
export interface UtxoInit {
  readonly owner: ShieldedPublicKey; readonly asset: Address;
  readonly amount: bigint; readonly blinding: Blinding;
  readonly data?: Data; readonly zoneProgramId?: Address;
}
export class Utxo {
  readonly owner: ShieldedPublicKey;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Blinding;
  readonly data: Data;
  readonly zoneProgramId?: Address;
  constructor(input: UtxoInit);
  proofInput(nullifierPublicKey: Bytes32, dataHash?: Bytes32, zoneDataHash?: Bytes32): Readonly<{
    hash(): Bytes32;
  }>;
  hash(nullifierPublicKey: Bytes32, dataHash?: Bytes32, zoneDataHash?: Bytes32): Bytes32;
  nullifier(utxoHash: Bytes32, nullifierKey: NullifierKey): Bytes32;
}
export class ProofInputUtxo {
  readonly utxo: Utxo;
  readonly nullifierKey: NullifierKey;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  constructor(input: Readonly<{
    utxo: Utxo; nullifierKey: NullifierKey;
    dataHash?: Bytes32; zoneDataHash?: Bytes32;
  }>);
  static dummy(): ProofInputUtxo;
  isDummy(): boolean;
  hash(): Bytes32;
  nullifier(): Bytes32;
}
export function deriveBlinding(seed: Bytes31, position: number): Blinding;
export function ownerUtxoHash(ownerHash: Bytes32, blinding: Bytes31): Bytes32;
export function ownerUtxoHash(input: Readonly<{
  owner: Bytes32; asset: Address; amount: bigint; blinding: Bytes31;
  dataHash?: Bytes32; zoneDataHash?: Bytes32; zoneProgramId?: Address;
}>): Bytes32;

export const SOL_ASSET_ID: 1n;
export const SOL_MINT: Address;
export class AssetRegistry {
  constructor(entries?: readonly (readonly [bigint, Address])[]);
  insert(assetId: bigint, mint: Address): void;
  resolve(assetId: bigint): Address;
  assetId(mint: Address): bigint;
}
export interface AssetBalance {
  readonly mint: Address; readonly amount: bigint;
  readonly spendableAmount: bigint;
}
export interface PrivateTransaction {
  readonly id: Readonly<{ signature: Signature; index: number }>;
  readonly kind: "deposit" | "transfer" | "withdrawal" | "split" | "merge";
  readonly direction: "incoming" | "outgoing" | "self";
  readonly status: "pending" | "confirmed";
  readonly slot: bigint;
}
export interface SyncReport {
  readonly received: number; readonly spent: number;
  readonly transactions: number; readonly unknownAssetIds: readonly bigint[];
}
export interface WalletUtxo {
  readonly utxo: Utxo;
  readonly outputContext: Readonly<{
    hash: Bytes32; tree: Address; leafIndex: bigint;
  }>;
  readonly nullifier: Bytes32;
  readonly dataHash?: Bytes32;
  readonly zoneDataHash?: Bytes32;
  readonly spent: boolean;
}
export class Wallet {
  readonly identity: ShieldedAddress;
  readonly registry: AssetRegistry;
  constructor(input: Readonly<{ identity: ShieldedAddress; registry: AssetRegistry }>);
  utxos(): readonly WalletUtxo[];
  privateTransactions(): readonly PrivateTransaction[];
  balance(mint: Address): AssetBalance | undefined;
  balances(options?: Readonly<{ skipUtxos?: boolean }>): readonly AssetBalance[];
}
```

Constructors and methods are synchronous pure state operations from
[`data.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/data.rs),
[`utxo.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/utxo.rs), and
[`wallet/state.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/wallet/state.rs). They copy
retained input, return snapshots, validate amounts, duplicate records/assets,
and layouts, and throw `TransactionError`.

Additional `@zolana/transaction` root exports used by independent instruction
workflows:

```ts
export type WithdrawalTarget =
  | Readonly<{ kind: "sol"; recipient: Address }>
  | Readonly<{
      kind: "spl";
      userTokenAccount: Address;
      splTokenInterface: Address;
    }>;
export interface ProofOutputUtxo {
  readonly ownerAddress?: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes31;
  readonly zoneProgramId?: Address;
  readonly zoneDataHash?: Bytes32;
  readonly dataHash?: Bytes32;
  readonly ownerTag?: Bytes32;
  readonly data: Data;
  ownerHash(): Bytes32;
  hash(): Bytes32;
  isDummy(): boolean;
}
export interface PreparedTransfer {
  readonly owner: ShieldedAddress;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly firstNullifier: Bytes32;
  readonly shape: Readonly<{ inputs: number; outputs: number }>;
  readonly payerPublicKeyHash: Bytes32;
  readonly publicSolAmount?: bigint;
  readonly publicSplAmount?: bigint;
  readonly userSolAccount: Address;
  readonly userSplToken: Address;
  readonly splTokenInterface: Address;
  finalize(input: Readonly<{
    txViewingPublicKey: P256PublicKey;
    salt: Bytes16;
    payload: readonly (Readonly<{ viewTag: Bytes32; data: Uint8Array }> | undefined)[];
  }>): SppProofInputs;
}
export class ConfidentialTransfer {
  constructor(owner: ShieldedAddress, inputs: readonly ProofInputUtxo[], payer: Address);
  withShape(shape: Readonly<{ inputs: number; outputs: number }>): ConfidentialTransfer;
  requiresP256Owner(): boolean;
  send(recipient: ShieldedAddress, asset: Address, amount: bigint): void;
  withdraw(asset: Address, amount: bigint, target: WithdrawalTarget): void;
  prepare(): PreparedTransfer;
}
export interface PublicAmounts {
  readonly sol?: bigint; readonly spl?: bigint;
}
export interface P256Signature {
  readonly publicKey: P256PublicKey;
  readonly r: Bytes32;
  readonly s: Bytes32;
}
export interface EncryptedTransfer {
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly payload: readonly (Readonly<{
    viewTag: Bytes32;
    data: Uint8Array;
  }> | undefined)[];
}
export interface SplitBundlePlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly numOutputs: number;
  readonly assetId: bigint;
  readonly assetAmount: bigint;
  readonly blindingSeed: Bytes31;
  readonly data: Data;
}
export interface EncryptedSplit {
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly payload: Readonly<{ viewTag: Bytes32; data: Uint8Array }>;
}
export interface WalletSyncMaterial {
  readonly identity: ShieldedAddress;
  readonly viewingKeys: readonly ViewingKey[];
  readonly nullifierKey: NullifierKey;
}
export interface SppProofInputs {
  readonly payerPublicKeyHash: Bytes32;
  readonly inputUtxos: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  checkShape(): Readonly<{ inputs: number; outputs: number }>;
  publicAmounts(): PublicAmounts;
  inputUtxoHashes(): readonly Bytes32[];
  messageHash(): Bytes32;
  applyP256Signature(signature: P256Signature): void;
}
export interface InputUtxoContext {
  readonly index: number;
  readonly utxoHash: Bytes32;
  readonly nullifier: Bytes32;
}
export class PreparedMerge {
  readonly inputs: readonly ProofInputUtxo[];
  readonly output: ProofOutputUtxo;
  readonly expiryUnixTs: bigint;
  readonly signingPublicKey: ShieldedPublicKey;
  readonly userViewingPublicKey: P256PublicKey;
  /**
   * Sensitive ephemeral scalar required by merge proving. Implementations must
   * not serialize, log, or expose this value outside the submit boundary.
   */
  readonly txViewingSecret: Bytes32;
  inputUtxoHashes(): readonly InputUtxoContext[];
}
export function canonicalShape(inputs: number, outputs: number): Readonly<{ inputs: number; outputs: number }>;
export function resolveShape(inputs: number, outputs: number): Readonly<{ inputs: number; outputs: number }>;
```

These map
[`instructions/transact/transfer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/transfer.rs),
[`spp_proof_inputs.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs),
and [`shape.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/shape.rs).
They are synchronous, return owned prepared/proof-input values, enforce
supported shapes, balance/change, one-withdrawal, and field bounds, and throw
`TransactionError`. Low-level slot encoders, split/merge/zone structs, and
mutable Rust assembly helpers remain internal until a workflow requires them
independently.

The object overload of `ownerUtxoHash` is a TypeScript convenience for the raw
deposit workflow. It composes Rust `ProofInputUtxo::new(...).hash()` and optional
data/zone fields; the two-argument overload is the direct
[`owner_utxo_hash`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/utxo.rs) mapping.

The TypeScript root deliberately names Rust
`instructions::types::SppProofInputUtxo` as `ProofInputUtxo`; Rust's
field-encoded `utxo::ProofInputUtxo` stays internal to avoid a public collision.
`ProofOutputUtxo` maps `SppProofOutputUtxo`. `applyP256Signature` is the checked
TypeScript replacement for mutating Rust's raw `p256_signature` field: it
validates the owner key and copies `r || s`.

Also at the `@zolana/transaction` root:

```ts
export interface WalletSyncConfig { readonly tagWindow?: bigint }
export function decryptTransactions(input: Readonly<{
  wallet: Wallet; authority: WalletAuthority;
  transactions: readonly IndexedShieldedTransaction[];
  config?: WalletSyncConfig;
}>): Promise<SyncReport>;
```

This Promise operation maps the Rust `decrypt_transactions` state transform
in [`wallet/sync.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/wallet/sync.rs) through the
single async TypeScript authority. It mutates only the supplied wallet,
validates ordering/ciphertexts, and rejects with `TransactionError`. Network
fetching remains in `@zolana/wallet`.

## `@zolana/indexer-api`

Source: [`sdk-libs/indexer-api/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/indexer-api/src/lib.rs).

```ts
export const MIN_PAGE_LIMIT: 1n;
export const PAGE_LIMIT: 1000n;
export const GET_ENCRYPTED_UTXOS_BY_TAGS: "get_encrypted_utxos_by_tags";
export const GET_SHIELDED_TRANSACTIONS_BY_TAGS: "get_shielded_transactions_by_tags";
export const GET_MERKLE_PROOFS: "get_merkle_proofs";
export const GET_NON_INCLUSION_PROOFS: "get_non_inclusion_proofs";
export const GET_NULLIFIER_QUEUE_ELEMENTS: "get_nullifier_queue_elements";
export type Base64String = string & { readonly __base64: unique symbol };
export type Hash = string & { readonly __hash32Base58: unique symbol };
export type Limit = bigint & { readonly __limit1To1000: unique symbol };
export interface IndexerContext { readonly blockTime: bigint }
export interface GetRingsByTagsRequest {
  readonly tags: readonly Hash[]; readonly cursor?: Base64String; readonly limit?: Limit;
}
export interface RingsOutputContext {
  readonly hash: Hash; readonly tree: Address; readonly leafIndex: bigint;
}
export interface RingsOutputSlot {
  readonly viewTag: Hash; readonly outputContext: RingsOutputContext;
  readonly payload: Base64String;
}
export interface RingsMessage { readonly viewTag: Hash; readonly payload: Base64String }
export interface EncryptedUtxoMatch {
  readonly slot: bigint; readonly txSignature: Signature;
  readonly outputSlot: RingsOutputSlot; readonly txViewingPk?: Base64String;
  readonly salt?: Base64String;
}
export interface GetEncryptedUtxosByTagsResponse {
  readonly context: IndexerContext; readonly matches: readonly EncryptedUtxoMatch[];
  readonly nextCursor?: Base64String;
}
export interface IndexedShieldedTransaction {
  readonly slot: bigint; readonly txSignature: Signature;
  readonly txViewingPk?: Base64String; readonly salt?: Base64String;
  readonly outputSlots: readonly RingsOutputSlot[];
  readonly messages: readonly RingsMessage[]; readonly nullifiers: readonly Hash[];
  readonly proofless: boolean;
}
export interface GetShieldedTransactionsByTagsResponse {
  readonly context: IndexerContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Base64String;
}
export interface GetMerkleProofsRequest {
  readonly treeAccount: Address; readonly leaves: readonly Hash[];
}
export interface MerkleProof {
  readonly leaf: Hash;
  readonly merkleContext: Readonly<{ treeType: number; tree: Address }>;
  readonly path: readonly Hash[]; readonly leafIndex: bigint;
  readonly root: Hash; readonly rootSeq: bigint; readonly rootIndex: number;
}
export interface GetMerkleProofsResponse {
  readonly context: IndexerContext; readonly proofs: readonly MerkleProof[];
}
export interface GetNonInclusionProofsRequest {
  readonly treeAccount: Address; readonly leaves: readonly Hash[];
}
export interface NonInclusionProof {
  readonly leaf: Hash;
  readonly merkleContext: Readonly<{ treeType: number; tree: Address }>;
  readonly path: readonly Hash[];
  readonly lowElement: Hash; readonly lowElementIndex: bigint;
  readonly highElement: Hash; readonly highElementIndex: bigint;
  readonly root: Hash; readonly rootSeq: bigint; readonly rootIndex: number;
}
export interface GetNonInclusionProofsResponse {
  readonly context: IndexerContext; readonly proofs: readonly NonInclusionProof[];
}
export interface GetNullifierQueueElementsRequest {
  readonly treeAccount: Address; readonly startSeq?: bigint; readonly limit: Limit;
}
export interface NullifierQueueElement { readonly seq: bigint; readonly value: Hash }
export interface GetNullifierQueueElementsResponse {
  readonly context: IndexerContext; readonly elements: readonly NullifierQueueElement[];
}
export class IndexerSchemaError extends Error {
  readonly code: `INDEXER_SCHEMA_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export function base64String(value: string | Uint8Array): Base64String;
export function hash(value: string | Bytes32): Hash;
export function hashBytes(value: Hash): Bytes32;
export function limit(value: bigint): Limit;
```

Scalar constructors and `hashBytes` are synchronous, return validated,
copied immutable wire values,
and throw `IndexerSchemaError`. JSON names are camelCase in TypeScript and
converted to frozen snake_case wire keys internally. Unknown fields, malformed
base58/base64, and limits outside 1–1000 are rejected. Rust `RpcMethod` marker
types become the five constants rather than constructible classes.

`@zolana/indexer-api` owns the JSON schema form of both proof types. Each
`NonInclusionProof` wire object has exactly `leaf`, `merkle_context`, `path`,
`low_element`, `low_element_index`, `high_element`, `high_element_index`,
`root`, `root_seq`, and `root_index`; it has no `leaf_index`. Hash fields and
every path item are canonical base58 strings decoding to 32 bytes,
`merkle_context.tree` is a canonical Solana address, `tree_type` and
`root_index` are unsigned 16-bit integers, and the remaining indexes and
sequence are unsigned 64-bit integers represented as `bigint` after decoding.
The strict decoder rejects missing or unknown fields, non-canonical encodings,
unsafe JSON integers, out-of-range integers, and malformed nested objects.
These fields and encodings are pinned by frozen
[`indexer-api/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/indexer-api/src/lib.rs).

## `@zolana/api`

Source: [`sdk-libs/zolana-api/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/zolana-api/src/lib.rs).

```ts
export class ApiError extends Error {
  readonly code: `API_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export interface ZolanaApiConfig {
  readonly url: URL | string;
  readonly apiKey?: string;
  readonly fetch?: typeof globalThis.fetch;
}
export class ZolanaApi {
  constructor(config: ZolanaApiConfig);
  getEncryptedUtxosByTags(request: GetRingsByTagsRequest, context?: RequestContext): Promise<GetEncryptedUtxosByTagsResponse>;
  getShieldedTransactionsByTags(request: GetRingsByTagsRequest, context?: RequestContext): Promise<GetShieldedTransactionsByTagsResponse>;
  getMerkleProofs(request: GetMerkleProofsRequest, context?: RequestContext): Promise<GetMerkleProofsResponse>;
  getNonInclusionProofs(request: GetNonInclusionProofsRequest, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
  getNullifierQueueElements(request: GetNullifierQueueElementsRequest, context?: RequestContext): Promise<GetNullifierQueueElementsResponse>;
}
```

The constructor validates the URL and copies configuration. Methods map
`ZolanaApi::request` through each indexer method type, return schema-owned
values, and reject with `ApiError` for abort/timeout, transport, HTTP,
JSON-RPC, or strict response errors. The API key and response body are never
included in errors. Rust `BlockingZolanaApi` is deliberately absent.

## `@zolana/client`

Source: [`sdk-libs/client/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/lib.rs),
[`client.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/client.rs),
[`rpc.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/rpc.rs),
[`indexer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/indexer.rs), and
[`retry.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/retry.rs).

```ts
export const CANONICAL_CLIENT_ERROR_CODES: readonly CanonicalClientErrorCode[];
export type CanonicalClientErrorCode =
  (typeof CANONICAL_CLIENT_ERROR_CODES)[number];
export type ClientErrorCode = keyof ClientErrorDetailsMap;
export interface ClientErrorDetailsMap {
  readonly CLIENT_POLL_TIMED_OUT: Readonly<{
    attempts: number;
    lastCause?: RetryErrorCause;
  }>;
  readonly CLIENT_INDEXER: Readonly<{ method: string; retryable: boolean }>;
}
export type ClientErrorDetails<Code extends ClientErrorCode = ClientErrorCode> =
  ClientErrorDetailsMap[Code];
export type HasherErrorCode =
  | "HASHER_INTEGER_OVERFLOW" | "HASHER_POSEIDON" | "HASHER_UNKNOWN"
  | "HASHER_EMPTY_INPUT" | "HASHER_INVALID_INPUT_LENGTH"
  | "HASHER_INVALID_NUM_INPUTS" | "HASHER_BORSH";
export type RetryErrorCause = Readonly<{
  category: "rpc" | "indexer" | "indexerTimeout";
}>;
export type ClientErrorCause =
  | Readonly<{ category: "client"; code: ClientErrorCode }>
  | Readonly<{ category: "keypair"; code: KeypairErrorCode; details?: Readonly<Record<string, unknown>> }>
  | Readonly<{ category: "transaction"; code: TransactionErrorCode; details?: Readonly<Record<string, unknown>> }>
  | Readonly<{ category: "hasher"; code: HasherErrorCode }>
  | RetryErrorCause
  | Readonly<{ category: "external"; code?: string }>;
export class ClientError<Code extends ClientErrorCode = ClientErrorCode> extends Error {
  readonly code: Code;
  readonly details?: ClientErrorDetails<Code>;
  readonly cause?: ClientErrorCause;
}
export interface IndexerPollConfig {
  readonly numRetries: number;
  readonly delayMs: bigint;
  readonly maxDelayMs: bigint;
}
export interface IndexerRpcConfig {
  readonly waitForIndexer: boolean;
  readonly poll: IndexerPollConfig;
}
export const DEFAULT_INDEXER_POLL_CONFIG: IndexerPollConfig;
export const DEFAULT_INDEXER_RPC_CONFIG: IndexerRpcConfig;
export function createIndexerPollConfig(
  numRetries: number, delayMs: bigint, maxDelayMs: bigint,
): IndexerPollConfig;
export function createIndexerRpcConfig(
  waitForIndexer?: boolean, poll?: IndexerPollConfig,
): IndexerRpcConfig;
export function waitForIndexer(poll?: IndexerPollConfig): IndexerRpcConfig;
export function validatePollConfig(config: IndexerPollConfig): IndexerPollConfig;
export function attempts(config: IndexerPollConfig): number;
export function backoff(config: IndexerPollConfig): IterableIterator<bigint>;
export function retryCause(error: unknown): RetryErrorCause | undefined;
export function isRetryable(cause: unknown): cause is ClientError;
export interface PollUntilOptions {
  readonly config?: IndexerPollConfig;
  readonly context?: RequestContext;
}
export function pollUntil<T>(
  request: () => Promise<T>,
  accept: (response: T) => boolean,
  options?: PollUntilOptions,
): Promise<T>;
export interface RpcAccount {
  readonly owner: Address;
  readonly data: Uint8Array;
  readonly lamports: bigint;
}
export interface RpcContext {
  readonly blockTime: bigint;
}
export interface MerkleContext {
  readonly treeType: number;
  readonly tree: Address;
}
export interface MerkleProof {
  readonly leaf: Bytes32;
  readonly merkleContext: MerkleContext;
  readonly path: readonly Bytes32[];
  readonly leafIndex: bigint;
  readonly root: Bytes32;
  readonly rootSeq: bigint;
  readonly rootIndex: number;
}
export interface NonInclusionProof {
  readonly leaf: Bytes32;
  readonly merkleContext: MerkleContext;
  readonly path: readonly Bytes32[];
  readonly lowElement: Bytes32;
  readonly lowElementIndex: bigint;
  readonly highElement: Bytes32;
  readonly highElementIndex: bigint;
  readonly root: Bytes32;
  readonly rootSeq: bigint;
  readonly rootIndex: number;
}
export interface GetMerkleProofsResponse {
  readonly context: RpcContext;
  readonly proofs: readonly MerkleProof[];
}
export interface GetNonInclusionProofsResponse {
  readonly context: RpcContext;
  readonly proofs: readonly NonInclusionProof[];
}
export interface GetByTagsRequest {
  readonly tags: readonly Bytes32[];
  readonly cursor?: Uint8Array;
  readonly limit?: number;
}
export interface EncryptedUtxoMatch {
  readonly slot: bigint;
  readonly txSignature: Signature;
  readonly outputSlot: IndexedShieldedTransaction["outputSlots"][number];
  readonly txViewingPk?: P256PublicKey;
  readonly salt?: Bytes16;
}
export interface GetEncryptedUtxosByTagsResponse {
  readonly context: RpcContext;
  readonly matches: readonly EncryptedUtxoMatch[];
  readonly nextCursor?: Uint8Array;
}
export interface GetShieldedTransactionsByTagsResponse {
  readonly context: RpcContext;
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly nextCursor?: Uint8Array;
}
export interface SpendProof {
  readonly state: MerkleProof;
  readonly nullifier: NonInclusionProof;
}
export interface Rpc {
  getAccount(address: Address, context?: RequestContext): Promise<Readonly<{ owner: Address; data: Uint8Array; lamports: bigint }> | undefined>;
  getMultipleAccounts(addresses: readonly Address[], context?: RequestContext): Promise<readonly (Readonly<{ owner: Address; data: Uint8Array; lamports: bigint }> | undefined)[]>;
  getBalance(address: Address, context?: RequestContext): Promise<bigint>;
  getLatestBlockhash(context?: RequestContext): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>>;
  sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature>;
  confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean>;
  transactOutputViewTags(signature: Signature, context?: RequestContext): Promise<readonly Bytes32[]>;
  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse>;
  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse>;
  getInputMerkleProofs(
    inputUtxoCommitments: readonly InputUtxoContext[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<readonly SpendProof[]>;
}
export class SolanaRpc implements Rpc {
  constructor(input: Readonly<{ url: URL | string; fetch?: typeof globalThis.fetch }>);
  getAccount(address: Address, context?: RequestContext): Promise<Readonly<{ owner: Address; data: Uint8Array; lamports: bigint }> | undefined>;
  getMultipleAccounts(addresses: readonly Address[], context?: RequestContext): Promise<readonly (Readonly<{ owner: Address; data: Uint8Array; lamports: bigint }> | undefined)[]>;
  getBalance(address: Address, context?: RequestContext): Promise<bigint>;
  getLatestBlockhash(context?: RequestContext): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>>;
  sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature>;
  confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean>;
  transactOutputViewTags(signature: Signature, context?: RequestContext): Promise<readonly Bytes32[]>;
  getMerkleProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetMerkleProofsResponse>;
  getNonInclusionProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
  getInputMerkleProofs(inputUtxoCommitments: readonly InputUtxoContext[], config?: IndexerRpcConfig, context?: RequestContext): Promise<readonly SpendProof[]>;
}
export class ZolanaIndexer {
  constructor(api: ZolanaApi);
  getEncryptedUtxosByTags(request: GetByTagsRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetEncryptedUtxosByTagsResponse>;
  getShieldedTransactionsByTags(request: GetByTagsRequest, config?: IndexerRpcConfig, context?: RequestContext): Promise<GetShieldedTransactionsByTagsResponse>;
  getMerkleProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetMerkleProofsResponse>;
  getNonInclusionProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
}
export interface SignedPrivateTransaction {
  readonly transaction: SppProofInputs;
  readonly withdrawal?: TransactWithdrawal;
  readonly tree: Address;
}
export interface MergeMaterialInput {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;
  readonly nullifierKey: NullifierKey;
}
export interface ProvedMerge {
  readonly data: MergeTransactInstructionData;
  readonly outputHash: Bytes32;
}
export interface ProvedMergeZone extends ProvedMerge {
  readonly zoneProgramId: Address;
}
export class ZolanaClient {
  constructor(input: Readonly<{
    rpc: Rpc; indexer: ZolanaIndexer; prover: ProverClient; tree: Address;
    computeUnitLimit?: number; computeUnitPriceMicroLamports?: bigint;
  }>);
  readonly tree: Address;
  readonly rpc: Rpc;
  readonly indexer: ZolanaIndexer;
  getAccount(address: Address, context?: RequestContext): Promise<Readonly<{ owner: Address; data: Uint8Array; lamports: bigint }> | undefined>;
  getMultipleAccounts(addresses: readonly Address[], context?: RequestContext): Promise<readonly (Readonly<{ owner: Address; data: Uint8Array; lamports: bigint }> | undefined)[]>;
  getBalance(address: Address, context?: RequestContext): Promise<bigint>;
  getLatestBlockhash(context?: RequestContext): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>>;
  sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature>;
  confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean>;
  transactOutputViewTags(signature: Signature, context?: RequestContext): Promise<readonly Bytes32[]>;
  getMerkleProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetMerkleProofsResponse>;
  getNonInclusionProofs(treeAccount: Address, leaves: readonly Bytes32[], config?: IndexerRpcConfig, context?: RequestContext): Promise<GetNonInclusionProofsResponse>;
  getInputMerkleProofs(inputUtxoCommitments: readonly InputUtxoContext[], config?: IndexerRpcConfig, context?: RequestContext): Promise<readonly SpendProof[]>;
  proveTransact(proofInputs: SppProofInputs, context?: RequestContext): Promise<TransactInstructionData>;
  proveMerge(input: Readonly<{
    prepared: PreparedMerge; material: MergeMaterialInput;
    indexer?: Pick<Rpc, "getInputMerkleProofs">;
  }>, context?: RequestContext): Promise<ProvedMerge>;
  finishMergeSubmissionUnsigned(input: Readonly<{
    proved: ProvedMerge; feePayer: Address;
    userRecord: Address; recentBlockhash: string;
  }>): Transaction;
  finishSubmissionUnsigned(input: Readonly<{
    signed: SignedPrivateTransaction; feePayer: Address; recentBlockhash: string;
  }>, context?: RequestContext): Promise<Transaction>;
  confirmPrivateTransaction(signature: Signature, context?: RequestContext): Promise<void>;
}
```

Constructors validate URLs, tree, limits, and retained adapters. RPC methods
validate arguments and reject with `ClientError`. `proveTransact` fetches input
Merkle proofs, proves, and returns owned transact data; confirmation waits for
both Solana confirmation and Photon indexing bound to the signature's output
view tags. The Promise methods deliberately collapse Rust blocking/async pairs.
The root `Rpc` includes frozen `getMerkleProofs`,
`getNonInclusionProofs`, and `getInputMerkleProofs`; `SpendProof` is rooted in
`@zolana/client` and re-exported from `@zolana/client/prover`. `RpcContext` is
the deliberate TypeScript name for Rust's broad `rpc::Context`. `SolanaRpc`
retains Rust's trait-default behavior and rejects unsupported proof methods,
while `ZolanaClient` delegates them to its indexer. This keeps
`SubmitMergeTransaction.indexer: Rpc` source-exact without adding a wallet
dependency on the concrete indexer adapter.
No wallet action, authority, registry, balance, history, or sync export is
permitted here.

The root also carries the prover block, so `import { ProverClient } from
"@zolana/client"` resolves the same declaration as the `@zolana/client/prover`
subpath: `assemble`, `intoProver`, `compressProof`, `canonicalShape`,
`resolveShape`, `SPP_SUPPORTED_SHAPES`, `ProverClient`, and the
`AssembledTransfer`, `AsyncPollConfig`, `CompressedProof`, `Field`, `Proof`,
`ProverInputs`, `Shape`, `TransferInput`, `TransferInputs`, `TransferOutput`,
and `TransferP256Inputs` types. The retry surface above is additionally
published from `@zolana/client/retry`.

Every crate-root name of `zolana-client` is either carried here or
dispositioned. `fixtures/client/lib.json` records the crate-root modules and
re-exports generated from `lib.rs`, and
`client/test/vectors/crate-root-exports.test.ts` fails when a name enters or
leaves either side without a disposition. The names Rust re-exports from
`zolana_transaction` reach a caller through `@zolana/transaction`, which
`@zolana/client` depends on, rather than through a duplicate export.
`ZoneTransferProver`, `ZoneTransferP256Prover`, `ZoneAuthorityProver`, and
their result and witness types are deferred to PKP-05 by review-checklist rows
C13, C14, and C18.

The client proof interfaces are semantic byte-valued types owned by
`@zolana/client`; they are not aliases or re-exports of
`@zolana/indexer-api` wire types. `ZolanaIndexer` explicitly converts every
wire hash and path item to a copied `Bytes32`, converts the wire tree to
`Address`, and preserves every integer and response context. The client
`NonInclusionProof` has the same ten fields as the wire proof and likewise has
no `leafIndex`. `SpendProof.state.leafIndex` supplies the state path index;
`SpendProof.nullifier.lowElementIndex` supplies the nullifier low-leaf path
index. Assembly writes the state and nullifier `rootIndex` values to the
separate `utxoTreeRootIndex` and `nullifierTreeRootIndex` instruction fields;
`@zolana/interface` does not own or share either proof object. Frozen
[`indexer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/indexer.rs)
defines this conversion, and
[`p256_and_eddsa.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/transact/p256_and_eddsa.rs)
defines the distinct path-index consumers. The instruction fields are pinned by
[`transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/instruction_data/transact.rs).

`@zolana/client/prover`:

```ts
export type Shape = Readonly<{ inputs: number; outputs: number }>;
export type Field = bigint & { readonly __bn254Field: unique symbol };
export type { SpendProof } from "@zolana/client";
export interface TransferInput {
  readonly utxo: ProofInputUtxo; readonly isDummy: Field;
  readonly statePathElements: readonly Field[]; readonly statePathIndex: Field;
  readonly nullifierLowValue: Field; readonly nullifierNextValue: Field;
  readonly nullifierLowPathElements: readonly Field[];
  readonly nullifierLowPathIndex: Field; readonly utxoTreeRoot: Field;
  readonly nullifierTreeRoot: Field; readonly nullifier: Field;
  readonly ownerPublicKeyHash: Field; readonly nullifierSecret: Field;
}
export interface TransferOutput {
  readonly utxo: ProofInputUtxo; readonly isDummy: Field;
  readonly hash: Field; readonly ownerPublicKeyHash: Field;
  readonly nullifierPublicKey: Field;
}
export interface TransferInputs {
  readonly inputs: readonly TransferInput[]; readonly outputs: readonly TransferOutput[];
  readonly externalDataHash: Field; readonly privateTxHash: Field;
  readonly publicSolAmount: Field; readonly publicSplAmount: Field;
  readonly publicSplAssetPublicKey: Field; readonly zoneProgramId: Field;
  readonly payerPublicKeyHash: Field; readonly publicInputHash: Field;
}
export interface TransferP256Inputs extends TransferInputs {
  readonly p256PublicKeyX: Field; readonly p256PublicKeyY: Field;
  readonly p256SignatureR: Field; readonly p256SignatureS: Field;
  readonly p256MessageHashLow: Field; readonly p256MessageHashHigh: Field;
  readonly p256SigningPublicKeyField: Field;
}
export type ProverInputs =
  | Readonly<{ circuit: "transfer"; payload: TransferInputs }>
  | Readonly<{ circuit: "transferP256"; payload: TransferP256Inputs }>;
export interface AssembledTransfer {
  readonly instructionData: TransactInstructionData;
  readonly proverInputs: ProverInputs;
  withProof(proof: TransactProof): TransactInstructionData;
}
export interface Proof {
  readonly a: Bytes64;
  readonly b: Bytes128;
  readonly c: Bytes64;
  readonly commitment?: Readonly<{
    commitment: Bytes64;
    commitmentPok: Bytes64;
  }>;
}
export interface CompressedProof {
  readonly a: Bytes32;
  readonly b: Bytes64;
  readonly c: Bytes32;
  readonly commitment?: Readonly<{
    commitment: Bytes32;
    commitmentPok: Bytes32;
  }>;
  toTransactProof(): TransactProof;
}
export class ProverClient {
  constructor(input: Readonly<{ url: URL | string; fetch?: typeof globalThis.fetch }>);
  prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof>;
}
export function assemble(proofInputs: SppProofInputs, spendProofs: readonly SpendProof[]): AssembledTransfer;
export function intoProver(proofInputs: SppProofInputs, spendProofs: readonly SpendProof[]): ProverInputs;
export function compressProof(proof: Proof): CompressedProof;
export function canonicalShape(inputs: number, outputs: number): Shape;
export function resolveShape(inputs: number, outputs: number): Shape;
```

`assemble`, `intoProver`, compression, and shape functions are synchronous and
throw `ClientError`; they validate proof count/order, path lengths, fields,
shapes, and proof points. `ProverClient.prove` is async and rejects with
`ClientError` for URL, abort/timeout, server, JSON, circuit, or proof errors.
These map [`prover/mod.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/mod.rs) and
[`prover/transact/witness.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/transact/witness.rs).
Rail-specific Rust prover structs, `spawn_prover`, server defaults, field
helpers, and raw JSON converters remain internal.

## `@zolana/wallet`

Source: [`sdk-libs/wallet/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/lib.rs),
[`actions/deposit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/deposit.rs),
[`actions/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/transaction.rs),
[`actions/submit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/submit.rs),
[`actions/create_associated_token_account.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/create_associated_token_account.rs),
[`wallet_authority.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/wallet_authority.rs),
[`wallet_sync.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/wallet_sync.rs), and
[`user_registry.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/user_registry.rs).

```ts
export class WalletError extends Error {
  readonly code: `WALLET_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export interface ApprovalRequest { readonly solanaPublicKey: Address; readonly summary: string }
export interface WalletAuthority {
  solanaPublicKey(): Address;
  shieldedAddress(): Promise<ShieldedAddress>;
  viewingKeys(): Promise<readonly ViewingKey[]>;
  spendNullifierKey(): Promise<NullifierKey>;
  syncMaterial(): Promise<WalletSyncMaterial>;
  encryptConfidentialTransfer(input: Readonly<{
    firstNullifier: Bytes32;
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
  }>): Promise<EncryptedTransfer>;
  encryptSplit(input: Readonly<{
    firstNullifier: Bytes32;
    viewTag: Bytes32;
    bundle: SplitBundlePlaintext;
  }>): Promise<EncryptedSplit>;
  requestUserApproval(request: ApprovalRequest): Promise<void>;
  signP256(messageHash: Bytes32): Promise<P256Signature>;
}
export class LocalWalletAuthority implements WalletAuthority {
  constructor(input: Readonly<{ solanaPublicKey: Address; keypair: ShieldedKeypair }>);
  solanaPublicKey(): Address;
  shieldedAddress(): Promise<ShieldedAddress>;
  viewingKeys(): Promise<readonly ViewingKey[]>;
  spendNullifierKey(): Promise<NullifierKey>;
  syncMaterial(): Promise<WalletSyncMaterial>;
  encryptConfidentialTransfer(input: Readonly<{
    firstNullifier: Bytes32;
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
  }>): Promise<EncryptedTransfer>;
  encryptSplit(input: Readonly<{
    firstNullifier: Bytes32;
    viewTag: Bytes32;
    bundle: SplitBundlePlaintext;
  }>): Promise<EncryptedSplit>;
  requestUserApproval(request: ApprovalRequest): Promise<void>;
  signP256(messageHash: Bytes32): Promise<P256Signature>;
}
export interface DepositParams {
  readonly recipient: ShieldedAddress; readonly asset: Address;
  readonly amount: bigint; readonly splTokenAccount?: Address;
  readonly memo?: Uint8Array;
}
export class Deposit {
  readonly data: DepositInstructionData;
  readonly utxoHash: Bytes32;
  readonly asset: Address;
  readonly spl?: DepositSplAccounts;
  instruction(tree: Address, depositor: Address): Instruction;
  viewTag(): Bytes32;
}
export function createDeposit(params: DepositParams): Deposit;
export function buildDepositTransaction(input: Readonly<{
  rpc: Rpc; payer: Address; tree: Address; depositor: Address; deposit: Deposit;
}>, context?: RequestContext): Promise<Transaction>;

export interface TransferParams {
  readonly rpc: Rpc; readonly wallet: Wallet; readonly payer: Address;
  readonly recipient: Address; readonly asset: Address; readonly amount: bigint;
}
export interface WithdrawalParams {
  readonly wallet: Wallet; readonly payer: Address; readonly recipient: Address;
  readonly asset: Address; readonly amount: bigint;
}
export class UnsignedPrivateTransaction {
  payer(): Address;
  tree(): Address;
  inputCount(): number;
}
export type TransferRecipient =
  | Readonly<{ kind: "registered"; owner: Address; address: ShieldedAddress; viewTag: Bytes32 }>
  | Readonly<{ kind: "publicWithdrawal"; recipient: Address; withdrawal: TransactWithdrawal }>;
export interface CreatedTransfer {
  readonly transaction: UnsignedPrivateTransaction;
  readonly recipient: TransferRecipient;
}
export interface CreatedWithdrawal {
  readonly transaction: UnsignedPrivateTransaction;
  readonly withdrawal: TransactWithdrawal;
}
export function createTransfer(params: TransferParams, context?: RequestContext): Promise<CreatedTransfer>;
export function createWithdrawal(params: WithdrawalParams): CreatedWithdrawal;
export interface SplitParams {
  readonly wallet: Wallet;
  readonly payer: Address;
  readonly asset: Address;
  readonly parts: number;
  readonly input?: Bytes32;
}
export interface CreatedSplit {
  readonly transaction: UnsignedPrivateTransaction;
  readonly numOutputs: number;
  readonly perOutputAmount: bigint;
}
export function createSplit(params: SplitParams): CreatedSplit;

export interface MergeParams {
  readonly wallet: Wallet;
  readonly keypair: ShieldedKeypair;
  readonly asset: Address;
  readonly inputs?: readonly Bytes32[];
}
export interface CreatedMerge {
  readonly prepared: PreparedMerge;
  readonly numInputs: number;
  readonly mergedAmount: bigint;
  readonly tree: Address;
}
export function createMerge(params: MergeParams): CreatedMerge;

export class MergeMaterial {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;
  readonly nullifierKey: NullifierKey;
  static fromKeypair(keypair: ShieldedKeypair): MergeMaterial;
}
export interface SubmitMergeTransaction {
  readonly rpc: Rpc;
  readonly indexer: Rpc;
  readonly owner: Address;
  readonly payer: TransactionSigner;
  readonly material: MergeMaterial;
  readonly tree: Address;
  readonly proverUrl: string;
  readonly prepared: PreparedMerge;
}
export interface SubmittedMerge {
  readonly signature: Signature;
  readonly outputHash: Bytes32;
}
export function submitMergeTransaction(
  request: SubmitMergeTransaction,
  context?: RequestContext,
): Promise<SubmittedMerge>;

export function createAssociatedTokenAccount(input: Readonly<{
  rpc: Rpc;
  payer: TransactionSigner;
  owner: Address;
  mint: Address;
}>, context?: RequestContext): Promise<Readonly<{
  signature: Signature;
  address: Address;
}>>;
export function buildPrivateTransaction(input: Readonly<{
  transaction: UnsignedPrivateTransaction; wallet: Wallet;
  authority: WalletAuthority; client: ZolanaClient; feePayer: Address;
}>, context?: RequestContext): Promise<Transaction>;
export function signPrivateTransaction(input: Readonly<{
  transaction: UnsignedPrivateTransaction; wallet: Wallet;
  authority: WalletAuthority; client: ZolanaClient; feePayer: TransactionSigner;
}>, context?: RequestContext): Promise<Transaction>;
export interface TransactionSigner {
  readonly address: Address;
  signNativeTransaction(transaction: Transaction): Promise<Transaction>;
}

export interface SyncWalletConfig {
  readonly tagWindow?: bigint; readonly tagQueryChunk?: number;
  readonly pageLimit?: number; readonly rounds?: number;
  readonly waitForIndexer?: boolean;
}
export function syncWallet(input: Readonly<{
  wallet: Wallet; authority: WalletAuthority; indexer: ZolanaIndexer;
  config?: SyncWalletConfig;
}>, context?: RequestContext): Promise<SyncReport>;
export function getPrivateTokenBalances(wallet: Wallet): readonly AssetBalance[];
export function getPrivateTransactions(wallet: Wallet): readonly PrivateTransaction[];

export interface ResolvedAddress {
  readonly owner: Address; readonly address: ShieldedAddress; readonly viewTag: Bytes32;
}
export function buildRegistrationTransaction(input: Readonly<{
  rpc: Rpc; owner: Address; address: ShieldedAddress;
}>, context?: RequestContext): Promise<Transaction | undefined>;
export function fetchUserRecord(input: Readonly<{ rpc: Rpc; owner: Address }>, context?: RequestContext): Promise<Readonly<{
  owner: Address; ownerP256?: Bytes33; nullifierPublicKey: Bytes32;
  viewingPublicKey: Bytes33; bump: number;
}> | undefined>;
export function isWalletRegistered(input: Readonly<{ rpc: Rpc; owner: Address }>, context?: RequestContext): Promise<boolean>;
export function resolveRegisteredAddress(input: Readonly<{ rpc: Rpc; owner: Address }>, context?: RequestContext): Promise<ResolvedAddress | undefined>;
```

Pure action creation validates positive `bigint` amounts, asset/source-account
consistency, spendability, one-tree selection, and withdrawal target before
returning owned values. Async builders, signing, registry, and sync reject with
`WalletError` and preserve `ClientError`, `TransactionError`, or `KeypairError`
as `cause`. `buildPrivateTransaction` returns an unsigned native transaction
for external custody; `signPrivateTransaction` additionally invokes the
supplied native signer. The authority approves and encrypts before proving.
There are no `signTransaction`, `signTransactionSync`, or `_sync` aliases.

Split validates `parts` in `2..=8`, selects one plain input, and requires exact
divisibility. Merge accepts two to eight (`2..=8`) plain, same-owner,
same-asset inputs on one tree and exposes the frozen prepared value needed by
submission. Fewer than two returns frozen `NothingToMerge`; more than eight
returns `TooManyInputs`.
`submitMergeTransaction` checks registry opt-in and key identity, resolves both
proofs for every real input, proves, and sends; the TypeScript adaptation uses
`TransactionSigner` instead of Rust `Keypair` and is therefore asynchronous.
`MergeMaterial` is included because the frozen root-exported
`SubmitMergeTransaction` contains that public type even though Rust omitted its
root re-export. ATA creation is idempotent and likewise replaces Rust `Keypair`
with `TransactionSigner`. Blocking registry helpers and hidden shielded signing
helpers remain excluded because Promise APIs already cover their behavior.

## Workflow defect reconciliation

1. `WalletAuthority`, `LocalWalletAuthority`, `WalletSyncMaterial`,
   `EncryptedTransfer`, and structured `P256Signature` now expose the scanning,
   encryption, approval, and signing capabilities in
   [`transaction/src/wallet/authority.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/wallet/authority.rs).
2. `PreparedTransfer` now preserves its owner, spend inputs, proof outputs,
   first nullifier, shape, payer/public settlement fields, external accounts,
   and `finalize` boundary from
   [`transfer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/transfer.rs).
3. `Wallet.utxos()` returns readonly `WalletUtxo` snapshots containing the
   commitment context, tree/leaf index, nullifier, optional data hashes, and
   spent state from
   [`wallet/state.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/wallet/state.rs).
4. `decryptTransactions` uses the one Promise-based `WalletAuthority` contract
   and returns `Promise<SyncReport>`; the blocking Rust authority remains
   internal.
5. Nullifier methods accept the frozen 31-byte UTXO blinding, not a leaf index,
   matching [`nullifier_key.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/nullifier_key.rs).
6. The SPL `WithdrawalTarget` carries `userTokenAccount` and
   `splTokenInterface`, matching
   [`transfer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/transfer.rs).
7. Public `ProofInputUtxo` maps constructible Rust `SppProofInputUtxo`, owns
   optional data hashes, and exposes canonical `hash()` and `nullifier()` from
   [`instructions/types.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/types.rs).
8. `SpendProof` contains separate state-inclusion and
   nullifier-non-inclusion proofs from
   [`witness.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/transact/witness.rs).

The workflow's strict hash conversion also uses `hash(Bytes32)` and
`hashBytes(Hash)` from `@zolana/indexer-api`; no snippet needs a cast between
wire base58 strings and bytes. These corrections require no product decision.

## `@zolana/merkle-tree`

Source: [`sdk-libs/merkle-tree/src/lib.rs`](https://github.com/helius-labs/zolana/blob/975783aa38b65734585f7749e347201fd67a2b71/sdk-libs/merkle-tree/src/lib.rs)
and [`indexed.rs`](https://github.com/helius-labs/zolana/blob/975783aa38b65734585f7749e347201fd67a2b71/sdk-libs/merkle-tree/src/indexed.rs).

```ts
export interface Hasher32 { hash(left: Bytes32, right: Bytes32): Bytes32 }
export interface Hasher32WithBytes extends Hasher32 {
  hashBytes(value: Bytes32): Bytes32;
}
export const poseidonHasher: Hasher32WithBytes;
export const sha256Hasher: Hasher32WithBytes;
export const keccakHasher: Hasher32WithBytes;
export class MerkleTreeError extends Error { readonly code: `MERKLE_TREE_${string}` }
export class IndexedMerkleTreeError extends Error { readonly code: `INDEXED_MERKLE_TREE_${string}` }
export interface MerkleTreeOptions {
  readonly canopyDepth?: number;
  readonly rootHistoryStartOffset?: bigint;
  readonly rootHistoryArrayLength?: number;
}
export class MerkleTree {
  constructor(height: number, hasher: Hasher32, options?: MerkleTreeOptions);
  append(leaf: Bytes32): bigint;
  appendBatch(leaves: readonly Bytes32[]): readonly bigint[];
  update(index: bigint, leaf: Bytes32): void;
  root(): Bytes32;
  path(index: bigint, full?: boolean): readonly Bytes32[];
  proof(index: bigint, full?: boolean): readonly Bytes32[];
  proofs(indices: readonly bigint[]): readonly (readonly Bytes32[])[];
  verify(leaf: Bytes32, proof: readonly Bytes32[], index: bigint): boolean;
  canopy(): readonly Bytes32[];
  canopySize(): bigint;
  history(): readonly Bytes32[];
  historyRootIndex(): number;
  historyRootIndexV2(): number;
  leaf(index: bigint): Bytes32;
  getLeaf(index: bigint): Bytes32;
  leafIndex(leaf: Bytes32): bigint | undefined;
  leaves(): readonly Bytes32[];
  subtrees(): readonly Bytes32[];
  leafCount(): bigint;
  nextIndex(): bigint;
  sequenceNumber(): bigint;
  insertNode(nodeIndex: bigint, hash: Bytes32): void;
  insertLeaf(index: bigint, hash: Bytes32): void;
  ensureLayerCapacity(level: number, minimumIndex: bigint): void;
}
export interface NonInclusionProof {
  readonly root: Bytes32;
  readonly value: Bytes32;
  readonly leafLowerRangeValue: Bytes32;
  readonly leafHigherRangeValue: Bytes32;
  readonly leafIndex: bigint;
  readonly nextIndex: bigint;
  readonly merkleProof: readonly Bytes32[];
}
export interface IndexedElement {
  readonly index: bigint;
  readonly value: Bytes32;
  readonly nextIndex: bigint;
}
export interface IndexedMerkleTreeOptions {
  readonly canopyDepth?: number;
  readonly highestValue?: Bytes32;
}
export class IndexedMerkleTree {
  constructor(height: number, hasher: Hasher32, options?: IndexedMerkleTreeOptions);
  insert(value: Bytes32): bigint;
  root(): Bytes32;
  path(index: bigint, full?: boolean): readonly Bytes32[];
  proof(index: bigint, full?: boolean): readonly Bytes32[];
  update(
    newLowElement: IndexedElement,
    newElement: IndexedElement,
    newElementNextValue: Bytes32,
  ): void;
  verifyNonInclusionProof(proof: NonInclusionProof): boolean;
  highestValue(): Bytes32;
  element(index: bigint): IndexedElement;
  elementCount(): bigint;
  nonInclusionProof(value: Bytes32): NonInclusionProof;
}
export function verifyNonInclusionProof(
  hasher: Hasher32,
  proof: NonInclusionProof,
  expectedRoot: Bytes32,
  height: number,
): boolean;
```

All operations are synchronous. They validate configuration, capacity, u64
indexes, ordering, exclusive sentinel bounds, proof length, trusted roots, and
byte lengths. Failed state changes are atomic, and returned bytes are owned.
The concrete Poseidon, SHA-256, and Keccak hashers use browser-safe Noble entry
points and match the current Rust vectors.

This `NonInclusionProof` is the reference indexed-tree result from current
[`indexed.rs`](https://github.com/helius-labs/zolana/blob/975783aa38b65734585f7749e347201fd67a2b71/sdk-libs/merkle-tree/src/indexed.rs).
It reconstructs the indexed leaf from `leafLowerRangeValue`, `nextIndex`, and
`leafHigherRangeValue`; it is not the Photon wire proof or the client
`SpendProof.nullifier` type. `@zolana/merkle-tree` has no client or indexer
dependency, and no implicit conversion between these package-local proof types
is public.

## `@zolana/smart-account-client`

Source: [`sdk-libs/smart-account-client/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/smart-account-client/src/lib.rs).

```ts
export const SMART_ACCOUNT_PROGRAM_ID: Address;
export interface Permissions { readonly mask: number }
export interface SmartAccountSigner { readonly key: Address; readonly permissions: Permissions }
export class SmartAccountClientError extends Error {
  readonly code: `SMART_ACCOUNT_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export function allPermissions(): Permissions;
export function programConfigAddress(): readonly [Address, number];
export function treasuryAddress(): Address;
export function settingsAddress(seed: bigint): readonly [Address, number];
export function smartAccountAddress(settings: Address, accountIndex: number): readonly [Address, number];
export function createSmartAccountInstruction(input: Readonly<{
  creator: Address; treasury: Address; settingsSeed: bigint;
  settingsAuthority?: Address; signers: readonly SmartAccountSigner[];
  threshold: number; timeLock: number;
}>): Instruction;
export function executeSyncInstruction(input: Readonly<{
  settings: Address; accountIndex: number; signerKeys: readonly Address[];
  innerInstructions: readonly Instruction[];
}>): Instruction;
```

These functions are synchronous and return owned values. They validate
`u128/u8/u16/u32` ranges, unique signers, threshold, instruction/account counts
that fit one byte, instruction data that fits `u16`, and compiled payload size;
they throw `SmartAccountClientError`. `executeSyncInstruction` unions duplicate
account privileges, preserves inner account order references, and clears the
vault's outer signer bit. Function names deliberately expand Rust's `_pda` and
`_ix` suffixes.

## `@zolana/test-kit` (private)

Source: [`sdk-libs/program-test/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/program-test/src/lib.rs).

```ts
export class TestKitError extends Error {
  readonly code: `TEST_KIT_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}
export interface LocalStack {
  readonly rpcUrl: URL; readonly indexerUrl: URL; readonly proverUrl: URL;
  stop(): Promise<void>;
}
export function startLocalStack(input?: Readonly<{
  programPath?: string; portOffset?: number; signal?: AbortSignal;
}>): Promise<LocalStack>;
export function fixtureBytes(name: string): Promise<Uint8Array>;
export function createTestWallet(seed: Bytes32): Readonly<{
  wallet: Wallet; authority: LocalWalletAuthority;
}>;
```

This Node-only unpublished surface owns process/filesystem behavior and rejects
with `TestKitError`. Rust admin, event, indexer, instruction, SPL, proofless,
wallet-data, and zone helpers remain test implementation details rather than
SDK semver.

## Rust-root reconciliation

- `@zolana/client` intentionally omits blocking types, `spawn_prover`, raw
  rail-specific prover classes, and wallet-owned exports.
- `@zolana/wallet` intentionally omits every Rust `_sync` function and hidden
  `sign_shielded_transaction`; it does not expose stale `signTransaction`
  aliases.
- `@zolana/transaction` intentionally narrows mutable/internal builders and
  codec schemas; action-required transfer/proof-input values remain public.
- `@zolana/interface` keeps raw instruction builders canonical and maps builder
  structs to object-parameter functions. It does not reimplement layouts in
  wallet or client.
- `@zolana/indexer-api` owns schema and method names; `@zolana/api` owns only
  transport.
- The frozen `program-test` root maps only to private `@zolana/test-kit`.

An API-report check must fail for every runtime export absent from this file,
every declaration emitted from the wrong entry point, and every allowlisted
symbol missing from implementation.
