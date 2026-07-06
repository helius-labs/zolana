import { randomBytes } from "node:crypto";
import { PublicKey as SolanaPublicKey, TransactionInstruction } from "@solana/web3.js";
import { p256 } from "@noble/curves/nist.js";
import {
  InstructionTag,
  BLINDING_LEN,
  SALT_LEN,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SOL_MINT,
  SPL_TOKEN_PROGRAM_ID,
} from "./constants.js";
import {
  assertLength,
  bigIntToBytes,
  bytesToBigInt,
  concatBytes,
  publicKeyBytes,
  rightAlign,
  u64Be,
  writeU16Le,
  writeU64Le,
} from "./bytes.js";
import { Data } from "./data.js";
import { hashField, poseidon, sha256, sha256Be } from "./hash.js";
import {
  NullifierKey,
  P256Pubkey,
  PublicKey,
  ShieldedAddress,
  ShieldedKeypair,
  ViewingKey,
  randomBlinding,
  randomSalt,
} from "./keypair.js";
import {
  Address,
  AssetRegistry,
  OutputContext,
  SpendUtxo,
  Utxo,
  deriveBlinding,
  ownerUtxoHash,
  programIdField,
  utxoHash,
} from "./utxo.js";
import {
  MerkleProof,
  NonInclusionProof,
  NULLIFIER_TREE_HEIGHT,
  STATE_TREE_HEIGHT,
} from "./rpc.js";
import {
  TransferInput,
  TransferInputs,
  TransferOutput,
  TransferP256Inputs,
  UtxoInputs,
  TransactProof,
  ProverClient,
} from "./prover.js";

const TRANSACT_DISCRIMINATOR = 0;
const SPL_CHANGE_POSITION = 0;
const SOL_CHANGE_POSITION = 1;
const RECIPIENT_POSITION_BASE = 2;
export const SENDER_SLOT_COUNT = 2;
export const BN254_MODULUS_DEC =
  "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const BN254_MODULUS = BigInt(BN254_MODULUS_DEC);

export interface TransactionShape {
  nInputs: number;
  nOutputs: number;
}

export const TRANSACTION_SUPPORTED_SHAPES: readonly TransactionShape[] = [{ nInputs: 2, nOutputs: 3 }];

export interface TransferRecipientPlaintext {
  assetId: bigint | number;
  amount: bigint | number;
  blinding: Uint8Array;
  zoneProgramId?: Address | null;
  data?: Data;
}

export interface TransferSenderPlaintext {
  ownerPubkey: PublicKey;
  splAssetId: bigint | number;
  splAmount: bigint | number;
  solAmount: bigint | number;
  blindingSeed: Uint8Array;
  recipientViewingPks: P256Pubkey[];
  splData?: Data;
  solData?: Data;
}

export interface PreparedRecipient {
  viewTag: Uint8Array;
  recipientPubkey: P256Pubkey;
  plaintext: TransferRecipientPlaintext;
}

export interface PreparedTransaction {
  inputs: SpendUtxo[];
  outputs: OutputUtxo[];
  senderPlaintext: TransferSenderPlaintext;
  recipients: PreparedRecipient[];
  firstNullifier: Uint8Array;
  publicAmounts: PublicAmounts;
  shape: TransactionShape;
  maxRecipients: number;
  payerPubkeyHash: Uint8Array;
  expiryUnixTs: bigint;
  publicSolAmount?: bigint;
  publicSplAmount?: bigint;
  userSolAccount: Address;
  userSplToken: Address;
  splTokenInterface: Address;
}

export type WithdrawalTarget =
  | { kind: "sol"; userSolAccount: Address }
  | { kind: "spl"; userSplToken: Address; splTokenInterface: Address };

interface Recipient {
  address: ShieldedAddress;
  asset: Address;
  amount: bigint;
}

interface Withdrawal {
  asset: Address;
  amount: bigint;
  target: WithdrawalTarget;
}

export class OutputUtxo {
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Uint8Array;
  readonly zoneProgramId: Address | undefined;
  readonly zoneDataHash: Uint8Array | undefined;
  readonly dataHash: Uint8Array | undefined;
  readonly ownerAddress: ShieldedAddress | undefined;
  readonly ownerTag: Uint8Array | undefined;
  readonly data: Data;

  constructor(fields: {
    asset?: Address;
    amount?: bigint | number;
    blinding?: Uint8Array;
    zoneProgramId?: Address | null;
    zoneDataHash?: Uint8Array | null;
    dataHash?: Uint8Array | null;
    ownerAddress?: ShieldedAddress | null;
    ownerTag?: Uint8Array | null;
    data?: Data;
  } = {}) {
    this.asset = fields.asset ?? SOL_MINT;
    this.amount = BigInt(fields.amount ?? 0);
    this.blinding = fields.blinding ? new Uint8Array(fields.blinding) : new Uint8Array(BLINDING_LEN);
    assertLength(this.blinding, BLINDING_LEN, "output blinding");
    this.zoneProgramId = fields.zoneProgramId ?? undefined;
    this.zoneDataHash = fields.zoneDataHash ? new Uint8Array(fields.zoneDataHash) : undefined;
    this.dataHash = fields.dataHash ? new Uint8Array(fields.dataHash) : undefined;
    this.ownerAddress = fields.ownerAddress ?? undefined;
    this.ownerTag = fields.ownerTag ? new Uint8Array(fields.ownerTag) : undefined;
    this.data = fields.data ?? Data.empty();
  }

  ownerHash(): Uint8Array {
    return this.ownerAddress?.ownerHash() ?? new Uint8Array(32);
  }

  hash(): Uint8Array {
    return utxoHash({
      asset: this.asset,
      amount: this.amount,
      dataHash: this.dataHash ?? new Uint8Array(32),
      zoneDataHash: this.zoneDataHash ?? new Uint8Array(32),
      zoneProgramId: this.zoneProgramId,
      ownerUtxoHash: ownerUtxoHash(this.ownerHash(), this.blinding),
    });
  }

  isDummy(): boolean {
    return this.ownerAddress === undefined;
  }
}

export interface PublicAmounts {
  sol: Uint8Array;
  spl: Uint8Array;
  asset: Uint8Array;
}

export interface OutputCiphertext {
  viewTag: Uint8Array;
  data: Uint8Array;
}

export interface ExternalData {
  instructionDiscriminator: number;
  expiryUnixTs: bigint;
  relayerFee: number;
  publicSolAmount?: bigint;
  publicSplAmount?: bigint;
  userSolAccount: Address;
  userSplToken: Address;
  splTokenInterface: Address;
  dataHash?: Uint8Array;
  zoneDataHash?: Uint8Array;
  txViewingPk: Uint8Array;
  salt: Uint8Array;
  outputUtxoHashes: Uint8Array[];
  outputCiphertexts: OutputCiphertext[];
}

export interface InputCommitment {
  index: number;
  utxoHash: Uint8Array;
  nullifier: Uint8Array;
}

export class SignedTransaction {
  p256Owner?: Uint8Array;

  constructor(
    readonly inputs: SpendUtxo[],
    readonly outputs: OutputUtxo[],
    readonly publicAmounts: PublicAmounts,
    readonly externalData: ExternalData,
    readonly payerPubkeyHash: Uint8Array,
    readonly shape: TransactionShape,
  ) {}

  inputCommitments(): InputCommitment[] {
    return this.inputs
      .filter((spend) => !isDummySpend(spend))
      .map((spend, index) => {
        const nullifierPubkey = spend.nullifierKey.pubkey();
        const hash = spend.utxo.hash(
          new Uint8Array(nullifierPubkey),
          new Uint8Array(spend.dataHash ?? new Uint8Array(32)),
          new Uint8Array(spend.zoneDataHash ?? new Uint8Array(32)),
        );
        return {
          index,
          utxoHash: hash,
          nullifier: spend.nullifierKey.nullifier(hash, spend.utxo.blinding),
        };
      });
  }

  messageHash(): Uint8Array {
    const inputHashes = this.inputs.map((spend) => {
      if (isDummySpend(spend)) return new Uint8Array(32);
      return spend.utxo.hash(
        new Uint8Array(spend.nullifierKey.pubkey()),
        new Uint8Array(spend.dataHash ?? new Uint8Array(32)),
        new Uint8Array(spend.zoneDataHash ?? new Uint8Array(32)),
      );
    });
    const outputHashes = this.outputs.map((output) =>
      output.isDummy() ? new Uint8Array(32) : output.hash(),
    );
    const privateTx = privateTxHash(
      inputHashes,
      outputHashes,
      noAddressHashes(this.shape.nInputs),
      externalDataHash(this.externalData),
    );
    return sha256(privateTx);
  }
}

export class Transaction {
  private readonly recipients: Recipient[] = [];
  private readonly customOutputs: OutputUtxo[] = [];
  private withdrawal?: Withdrawal;
  private readonly payerPubkeyHash: Uint8Array;
  private readonly blindingSeed: Uint8Array;
  private declaredShape?: TransactionShape;
  private expiryUnixTs = (1n << 64n) - 1n;

  constructor(
    private readonly owner: ShieldedAddress,
    private readonly inputs: SpendUtxo[],
    payer: Address,
  ) {
    this.payerPubkeyHash = sha256Be(publicKeyBytes(payer));
    this.blindingSeed = randomBlinding();
  }

  send(recipient: ShieldedAddress, asset: Address, amount: bigint | number): this {
    this.recipients.push({ address: recipient, asset, amount: BigInt(amount) });
    return this;
  }

  withdraw(asset: Address, amount: bigint | number, target: WithdrawalTarget): this {
    if (this.withdrawal) throw new Error("a transaction supports a single withdrawal");
    this.withdrawal = { asset, amount: BigInt(amount), target };
    return this;
  }

  withShape(shape: TransactionShape): this {
    this.declaredShape = shape;
    return this;
  }

  withExpiry(expiryUnixTs: bigint | number): this {
    this.expiryUnixTs = BigInt(expiryUnixTs);
    return this;
  }

  addOutput(output: OutputUtxo): this {
    if (!output.ownerAddress) throw new Error("custom output must have an owner address");
    this.customOutputs.push(output);
    return this;
  }

  requiresP256Owner(): boolean {
    return inputsRequireP256(this.inputs);
  }

  sign(keypair: ShieldedKeypair, assets: AssetRegistry): SignedTransaction {
    const signed = this.assembleWithKeypair(keypair, assets);
    if (keypair.signingPubkey().signatureType() === "p256") {
      signed.p256Owner = keypair.sign(signed.messageHash());
    }
    return signed;
  }

  prepare(assets: AssetRegistry): PreparedTransaction {
    const splAsset = this.splAsset();
    const [publicSol, publicSpl] = this.publicAmounts();
    const solChange = this.change(SOL_MINT, publicSol);
    const splChange = splAsset ? this.change(splAsset, publicSpl) : 0n;
    const outputs: OutputUtxo[] = [];

    outputs.push(
      splAsset && splChange > 0n
        ? new OutputUtxo({
            ownerAddress: this.owner,
            asset: splAsset,
            amount: splChange,
            blinding: deriveBlinding(this.blindingSeed, SPL_CHANGE_POSITION),
          })
        : new OutputUtxo({
            blinding: deriveBlinding(this.blindingSeed, SPL_CHANGE_POSITION),
            ownerTag: this.owner.signingPubkey.confidentialViewTag(),
          }),
    );

    outputs.push(
      solChange > 0n
        ? new OutputUtxo({
            ownerAddress: this.owner,
            asset: SOL_MINT,
            amount: solChange,
            blinding: deriveBlinding(this.blindingSeed, SOL_CHANGE_POSITION),
          })
        : new OutputUtxo({
            blinding: deriveBlinding(this.blindingSeed, SOL_CHANGE_POSITION),
            ownerTag: this.owner.signingPubkey.confidentialViewTag(),
          }),
    );

    const recipients: PreparedRecipient[] = [];
    const recipientViewingPks: P256Pubkey[] = [];
    for (const [i, recipient] of this.recipients.entries()) {
      const position = RECIPIENT_POSITION_BASE + i;
      const blinding = deriveBlinding(this.blindingSeed, position);
      const assetId = assetIdFor(assets, recipient.asset);
      outputs.push(
        new OutputUtxo({
          ownerAddress: recipient.address,
          asset: recipient.asset,
          amount: recipient.amount,
          blinding,
        }),
      );
      recipientViewingPks.push(recipient.address.viewingPubkey);
      recipients.push({
        viewTag: recipient.address.signingPubkey.confidentialViewTag(),
        recipientPubkey: recipient.address.viewingPubkey,
        plaintext: {
          assetId,
          amount: recipient.amount,
          blinding,
          data: Data.empty(),
        },
      });
    }

    for (const output of this.customOutputs) {
      const address = output.ownerAddress;
      if (!address) throw new Error("missing custom output owner");
      recipientViewingPks.push(address.viewingPubkey);
      recipients.push({
        viewTag: address.signingPubkey.confidentialViewTag(),
        recipientPubkey: address.viewingPubkey,
        plaintext: {
          assetId: assetIdFor(assets, output.asset),
          amount: output.amount,
          blinding: output.blinding,
          ...(output.zoneProgramId ? { zoneProgramId: output.zoneProgramId } : {}),
          data: output.data,
        },
      });
      outputs.push(output);
    }

    const shape = resolveTransactionShape(this.declaredShape, this.inputs.length, outputs.length);
    const maxRecipients = shape.nOutputs - SENDER_SLOT_COUNT;
    while (recipientViewingPks.length < maxRecipients) {
      recipientViewingPks.push(this.owner.viewingPubkey);
    }

    const splAssetId = splAsset ? assetIdFor(assets, splAsset) : 0;
    const senderPlaintext: TransferSenderPlaintext = {
      ownerPubkey: this.owner.signingPubkey,
      splAssetId,
      splAmount: splChange,
      solAmount: solChange,
      blindingSeed: this.blindingSeed,
      recipientViewingPks,
      splData: Data.empty(),
      solData: Data.empty(),
    };
    const [userSolAccount, userSplToken, splTokenInterface] = this.externalAccounts();
    return {
      inputs: this.inputs,
      outputs,
      senderPlaintext,
      recipients,
      firstNullifier: this.firstNullifier(),
      publicAmounts: {
        sol: signedToField(publicSol),
        spl: signedToField(publicSpl),
        asset: publicSpl !== 0n && splAsset ? hashField(publicKeyBytes(splAsset)) : new Uint8Array(32),
      },
      shape,
      maxRecipients,
      payerPubkeyHash: this.payerPubkeyHash,
      expiryUnixTs: this.expiryUnixTs,
      ...(publicSol !== 0n ? { publicSolAmount: publicSol } : {}),
      ...(publicSpl !== 0n ? { publicSplAmount: publicSpl } : {}),
      userSolAccount,
      userSplToken,
      splTokenInterface,
    };
  }

  private assembleWithKeypair(keypair: ShieldedKeypair, assets: AssetRegistry): SignedTransaction {
    const prepared = this.prepare(assets);
    const txViewingKey = keypair.viewingKey.getTransactionViewingKey(prepared.firstNullifier);
    const salt = randomSalt();
    const txViewingPk = txViewingKey.pubkey();
    const senderTag = prepared.senderPlaintext.ownerPubkey.confidentialViewTag();
    const slots: OutputCiphertext[] = [
      encodeConfidentialSender(prepared.senderPlaintext, senderTag, {
        tx: txViewingKey,
        selfPubkey: keypair.viewingPubkey(),
        salt,
        slotIndex: 0,
      }),
    ];
    for (const [i, recipient] of prepared.recipients.entries()) {
      slots.push(
        encodeConfidentialRecipient(recipient.plaintext, recipient.viewTag, {
          tx: txViewingKey,
          recipientPubkey: recipient.recipientPubkey,
          salt,
          slotIndex: i + 1,
        }),
      );
    }
    return finalizePrepared(prepared, txViewingPk, salt, slots, assets);
  }

  private splAsset(): Address | undefined {
    let found: Address | undefined;
    for (const asset of [
      ...this.inputs.map((spend) => spend.utxo.asset),
      ...this.recipients.map((recipient) => recipient.asset),
      ...this.customOutputs.map((output) => output.asset),
      ...(this.withdrawal ? [this.withdrawal.asset] : []),
    ]) {
      if (!asset.equals(SOL_MINT)) {
        if (found && !found.equals(asset)) {
          throw new Error("a transaction supports a single public SPL asset");
        }
        found = asset;
      }
    }
    return found;
  }

  private publicAmounts(): [bigint, bigint] {
    if (!this.withdrawal) return [0n, 0n];
    return this.withdrawal.asset.equals(SOL_MINT)
      ? [-this.withdrawal.amount, 0n]
      : [0n, -this.withdrawal.amount];
  }

  private change(asset: Address, publicAmount: bigint): bigint {
    const leftover =
      this.inputSum(asset) +
      publicAmount -
      this.recipientSum(asset) -
      this.customOutputSum(asset);
    if (leftover < 0n) {
      throw new Error(`insufficient balance: requested ${-leftover}, available 0`);
    }
    return leftover;
  }

  private inputSum(asset: Address): bigint {
    return this.inputs
      .filter((spend) => spend.utxo.asset.equals(asset))
      .reduce((sum, spend) => sum + spend.utxo.amount, 0n);
  }

  private recipientSum(asset: Address): bigint {
    return this.recipients
      .filter((recipient) => recipient.asset.equals(asset))
      .reduce((sum, recipient) => sum + recipient.amount, 0n);
  }

  private customOutputSum(asset: Address): bigint {
    return this.customOutputs
      .filter((output) => output.asset.equals(asset))
      .reduce((sum, output) => sum + output.amount, 0n);
  }

  private firstNullifier(): Uint8Array {
    const spend = this.inputs[0];
    if (!spend) throw new Error("a transaction must spend at least one input");
    const nullifierPubkey = spend.nullifierKey.pubkey();
    const hash = spend.utxo.hash(
      new Uint8Array(nullifierPubkey),
      new Uint8Array(spend.dataHash ?? new Uint8Array(32)),
      new Uint8Array(spend.zoneDataHash ?? new Uint8Array(32)),
    );
    return spend.nullifierKey.nullifier(hash, spend.utxo.blinding);
  }

  private externalAccounts(): [Address, Address, Address] {
    if (!this.withdrawal) return [SolanaPublicKey.default, SolanaPublicKey.default, SolanaPublicKey.default];
    if (this.withdrawal.target.kind === "sol") {
      return [this.withdrawal.target.userSolAccount, SolanaPublicKey.default, SolanaPublicKey.default];
    }
    return [
      SolanaPublicKey.default,
      this.withdrawal.target.userSplToken,
      this.withdrawal.target.splTokenInterface,
    ];
  }
}

export function spendUtxoFromKeypair(utxo: Utxo, keypair: ShieldedKeypair): SpendUtxo {
  return { utxo, nullifierKey: keypair.nullifierKey };
}

export function finalizePrepared(
  prepared: PreparedTransaction,
  txViewingPk: P256Pubkey,
  salt: Uint8Array,
  slots: OutputCiphertext[],
  assets: AssetRegistry,
): SignedTransaction {
  assertLength(salt, SALT_LEN, "salt");
  const inputs = [...prepared.inputs];
  const outputs = [...prepared.outputs];
  const dummyRecipientCount = Math.max(0, prepared.shape.nOutputs - outputs.length);
  const dummyTags = Array.from({ length: dummyRecipientCount }, randomViewTag);
  for (const tag of dummyTags) {
    outputs.push(new OutputUtxo({ blinding: randomBlinding(), ownerTag: tag }));
  }
  while (inputs.length < prepared.shape.nInputs) {
    inputs.push(newDummySpend());
  }
  const outputUtxoHashes = outputs.map((output) => output.hash());
  const outputCiphertexts = [...slots];
  if (outputCiphertexts.length < 1 + prepared.maxRecipients) {
    const throwaway = ViewingKey.new();
    const dummyLen = dummyCiphertextLen(throwaway, throwaway.pubkey(), salt, assets);
    let tagIndex = 0;
    while (outputCiphertexts.length < 1 + prepared.maxRecipients) {
      outputCiphertexts.push({
        viewTag: dummyTags[tagIndex++] ?? randomViewTag(),
        data: randomBytes(dummyLen),
      });
    }
  }
  const externalData: ExternalData = {
    instructionDiscriminator: TRANSACT_DISCRIMINATOR,
    expiryUnixTs: prepared.expiryUnixTs,
    relayerFee: 0,
    ...(prepared.publicSolAmount !== undefined ? { publicSolAmount: prepared.publicSolAmount } : {}),
    ...(prepared.publicSplAmount !== undefined ? { publicSplAmount: prepared.publicSplAmount } : {}),
    userSolAccount: prepared.userSolAccount,
    userSplToken: prepared.userSplToken,
    splTokenInterface: prepared.splTokenInterface,
    txViewingPk: txViewingPk.asBytes(),
    salt,
    outputUtxoHashes,
    outputCiphertexts,
  };
  return new SignedTransaction(
    inputs,
    outputs,
    prepared.publicAmounts,
    externalData,
    prepared.payerPubkeyHash,
    prepared.shape,
  );
}

export interface SpendProof {
  state: MerkleProof;
  nullifier: NonInclusionProof;
}

export type ProverInputs =
  | { kind: "p256"; inputs: TransferP256Inputs }
  | { kind: "eddsa"; inputs: TransferInputs };

export interface AssembledTransfer {
  proverInputs: ProverInputs;
  publicInputHash: Uint8Array;
  ix: TransactIxData;
}

export function assembleTransfer(tx: SignedTransaction, inputProofs: SpendProof[]): AssembledTransfer {
  const requiresP256 = inputsRequireP256(tx.inputs);
  const spendInputs = tx.inputs.map((spend, index) => {
    if (isDummySpend(spend)) return { spend };
    const proof = inputProofs[index];
    if (!proof) throw new Error(`missing input merkle proof for input ${index}`);
    return { spend, proof };
  });
  const assembledInputs = assembleInputs(spendInputs, requiresP256 ? "p256" : "eddsa", tx);
  const assembledOutputs = assembleOutputs(tx.outputs);
  const externalHash = externalDataHash(tx.externalData);
  const privateTx = privateTxHash(
    assembledInputs.inputHashes,
    assembledOutputs.privateTxOutputHashes,
    noAddressHashes(assembledInputs.inputHashes.length),
    externalHash,
  );
  const p256MessageHash = requiresP256 ? sha256(privateTx) : new Uint8Array(32);
  const p256SigningPkField = requiresP256 ? p256OwnerPkField(tx) : new Uint8Array(32);
  const publicInputHash = publicInputsHash({
    nullifiers: assembledInputs.nullifiers,
    outputHashes: assembledOutputs.outputHashes,
    utxoRoots: assembledInputs.utxoRoots,
    nullifierTreeRoots: assembledInputs.nullifierTreeRoots,
    privateTx,
    p256MessageHash,
    externalDataHash: externalHash,
    publicAmounts: tx.publicAmounts,
    zoneProgramId: new Uint8Array(32),
    payerPubkeyHash: tx.payerPubkeyHash,
    inputOwnerPkHashes: assembledInputs.inputOwnerPkHashes,
    outputOwnerPkHashes: assembledOutputs.outputOwnerPkHashes,
    p256SigningPkField,
  });

  const base = {
    inputs: assembledInputs.inputs,
    outputs: assembledOutputs.outputs,
    externalDataHash: bytesToBigInt(externalHash),
    privateTxHash: bytesToBigInt(privateTx),
    publicSolAmount: bytesToBigInt(tx.publicAmounts.sol),
    publicSplAmount: bytesToBigInt(tx.publicAmounts.spl),
    publicSplAssetPubkey: bytesToBigInt(tx.publicAmounts.asset),
    zoneProgramId: 0n,
    payerPubkeyHash: bytesToBigInt(tx.payerPubkeyHash),
    publicInputHash: bytesToBigInt(publicInputHash),
  };
  const proverInputs: ProverInputs = requiresP256
    ? {
        kind: "p256",
        inputs: {
          ...base,
          ...p256Witness(tx, privateTx, p256SigningPkField),
        },
      }
    : { kind: "eddsa", inputs: base };

  const ixInputs = assembledInputs.nullifiers.map((nullifierHash, index) => ({
    nullifierHash,
    nullifierTreeRootIndex: assembledInputs.rootIndices[index]?.[1] ?? 0,
    utxoTreeRootIndex: assembledInputs.rootIndices[index]?.[0] ?? 0,
    treeIndex: 0,
    eddsaSignerIndex: requiresP256 ? 255 : 0,
  }));
  return {
    proverInputs,
    publicInputHash,
    ix: {
      expiryUnixTs: tx.externalData.expiryUnixTs,
      relayerFee: tx.externalData.relayerFee,
      privateTxHash: privateTx,
      ...(requiresP256 ? { p256SigningPkField } : {}),
      txViewingPk: tx.externalData.txViewingPk,
      salt: tx.externalData.salt,
      proof: { kind: "eddsa", a: new Uint8Array(32), b: new Uint8Array(64), c: new Uint8Array(32) },
      inputs: ixInputs,
      ...(tx.externalData.publicSolAmount !== undefined ? { publicSolAmount: tx.externalData.publicSolAmount } : {}),
      ...(tx.externalData.publicSplAmount !== undefined ? { publicSplAmount: tx.externalData.publicSplAmount } : {}),
      ...(tx.externalData.dataHash ? { dataHash: tx.externalData.dataHash } : {}),
      ...(tx.externalData.zoneDataHash ? { zoneDataHash: tx.externalData.zoneDataHash } : {}),
      outputUtxoHashes: tx.externalData.outputUtxoHashes,
      outputCiphertexts: tx.externalData.outputCiphertexts,
    },
  };
}

export async function proveAssembledTransfer(
  client: ProverClient,
  assembled: AssembledTransfer,
): Promise<TransactIxData> {
  const proof =
    assembled.proverInputs.kind === "p256"
      ? await client.proveTransactTransferP256(assembled.proverInputs.inputs)
      : await client.proveTransactTransfer(assembled.proverInputs.inputs);
  return { ...assembled.ix, proof };
}

export interface TransactIxData {
  expiryUnixTs: bigint;
  relayerFee: number;
  privateTxHash: Uint8Array;
  p256SigningPkField?: Uint8Array;
  txViewingPk: Uint8Array;
  salt: Uint8Array;
  proof: TransactProof;
  inputs: Array<{
    nullifierHash: Uint8Array;
    nullifierTreeRootIndex: number;
    utxoTreeRootIndex: number;
    treeIndex: number;
    eddsaSignerIndex: number;
  }>;
  publicSolAmount?: bigint;
  publicSplAmount?: bigint;
  dataHash?: Uint8Array;
  zoneDataHash?: Uint8Array;
  outputUtxoHashes: Uint8Array[];
  outputCiphertexts: OutputCiphertext[];
}

export function serializeTransactIxData(ix: TransactIxData): Uint8Array {
  const out: number[] = [];
  writeU64Le(out, ix.expiryUnixTs);
  writeU16Le(out, ix.relayerFee);
  pushFixed(out, ix.privateTxHash, 32, "private tx hash");
  writeOptionFixed(out, ix.p256SigningPkField, 32, "p256 signing pk field");
  pushFixed(out, ix.txViewingPk, 33, "tx viewing pk");
  pushFixed(out, ix.salt, 16, "salt");
  writeTransactProof(out, ix.proof);
  writeVecU8(out, ix.inputs, (input) => {
    pushFixed(out, input.nullifierHash, 32, "nullifier hash");
    writeU16Le(out, input.nullifierTreeRootIndex);
    writeU16Le(out, input.utxoTreeRootIndex);
    out.push(input.treeIndex, input.eddsaSignerIndex);
  });
  writeOptionI64(out, ix.publicSolAmount);
  writeOptionI64(out, ix.publicSplAmount);
  writeOptionFixed(out, ix.dataHash, 32, "data hash");
  writeOptionFixed(out, ix.zoneDataHash, 32, "zone data hash");
  writeVecU8(out, ix.outputUtxoHashes, (hash) => pushFixed(out, hash, 32, "output utxo hash"));
  writeVecU8(out, ix.outputCiphertexts, (ciphertext) => {
    pushFixed(out, ciphertext.viewTag, 32, "output view tag");
    writeBytesU16(out, ciphertext.data);
  });
  return new Uint8Array(out);
}

export type TransactWithdrawal =
  | { kind: "sol"; recipient: Address }
  | {
      kind: "spl";
      cpiAuthority?: Address;
      splTokenInterface: Address;
      recipient: Address;
      userTokenAccount: Address;
      tokenProgram?: Address;
    };

export function transactInstruction(args: {
  payer: Address;
  tree: Address;
  withdrawal?: TransactWithdrawal;
  data: TransactIxData;
}): TransactionInstruction {
  const keys = [
    { pubkey: args.payer, isSigner: true, isWritable: true },
    { pubkey: args.tree, isSigner: false, isWritable: true },
  ];
  if (args.withdrawal?.kind === "sol") {
    keys.push(
      { pubkey: SOL_INTERFACE, isSigner: false, isWritable: true },
      { pubkey: args.withdrawal.recipient, isSigner: false, isWritable: true },
      { pubkey: SolanaPublicKey.default, isSigner: false, isWritable: false },
    );
  } else if (args.withdrawal?.kind === "spl") {
    if (args.withdrawal.cpiAuthority) {
      keys.push({ pubkey: args.withdrawal.cpiAuthority, isSigner: false, isWritable: false });
    }
    keys.push(
      { pubkey: args.withdrawal.splTokenInterface, isSigner: false, isWritable: true },
      { pubkey: args.withdrawal.recipient, isSigner: false, isWritable: true },
      { pubkey: args.withdrawal.userTokenAccount, isSigner: false, isWritable: true },
      { pubkey: args.withdrawal.tokenProgram ?? SPL_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    );
  }
  keys.push({ pubkey: SHIELDED_POOL_PROGRAM_ID, isSigner: false, isWritable: false });
  return new TransactionInstruction({
    programId: SHIELDED_POOL_PROGRAM_ID,
    keys,
    data: Buffer.from([InstructionTag.Transact, ...serializeTransactIxData(args.data)]),
  });
}

function encodeConfidentialRecipient(
  plaintext: TransferRecipientPlaintext,
  viewTag: Uint8Array,
  cx: { tx: ViewingKey; recipientPubkey: P256Pubkey; salt: Uint8Array; slotIndex: number },
): OutputCiphertext {
  const bytes = serializeTransferRecipientPlaintext(plaintext);
  const ciphertext = cx.tx.encryptSlot(cx.recipientPubkey, bytes, cx.salt, cx.slotIndex);
  return { viewTag, data: encodeOutputData("encrypted", new Uint8Array([3, ...ciphertext])) };
}

function encodeConfidentialSender(
  plaintext: TransferSenderPlaintext,
  viewTag: Uint8Array,
  cx: { tx: ViewingKey; selfPubkey: P256Pubkey; salt: Uint8Array; slotIndex: number },
): OutputCiphertext {
  const bytes = serializeTransferSenderPlaintext(plaintext);
  const ciphertext = cx.tx.encryptSlot(cx.selfPubkey, bytes, cx.salt, cx.slotIndex);
  return { viewTag, data: encodeOutputData("encrypted", new Uint8Array([4, ...ciphertext])) };
}

export function serializeTransferRecipientPlaintext(plaintext: TransferRecipientPlaintext): Uint8Array {
  assertLength(plaintext.blinding, BLINDING_LEN, "recipient blinding");
  const out: number[] = [];
  writeU64Le(out, plaintext.assetId);
  writeU64Le(out, plaintext.amount);
  out.push(...plaintext.blinding);
  writeOptionPubkey(out, plaintext.zoneProgramId);
  out.push(...(plaintext.data ?? Data.empty()).serialize());
  return new Uint8Array(out);
}

export function serializeTransferSenderPlaintext(plaintext: TransferSenderPlaintext): Uint8Array {
  assertLength(plaintext.blindingSeed, BLINDING_LEN, "blinding seed");
  const out: number[] = [];
  out.push(...plaintext.ownerPubkey.asBytes());
  writeU64Le(out, plaintext.splAssetId);
  writeU64Le(out, plaintext.splAmount);
  writeU64Le(out, plaintext.solAmount);
  out.push(...plaintext.blindingSeed);
  if (plaintext.recipientViewingPks.length > 0xff) throw new Error("too many recipient viewing keys");
  out.push(plaintext.recipientViewingPks.length);
  for (const pk of plaintext.recipientViewingPks) out.push(...pk.asBytes());
  out.push(...(plaintext.splData ?? Data.empty()).serialize());
  out.push(...(plaintext.solData ?? Data.empty()).serialize());
  return new Uint8Array(out);
}

function encodeOutputData(kind: "plaintext" | "encrypted" | "verifiable", blob: Uint8Array): Uint8Array {
  const out: number[] = [kind === "plaintext" ? 0 : kind === "encrypted" ? 1 : 2];
  writeU32Le(out, blob.length);
  out.push(...blob);
  return new Uint8Array(out);
}

function externalDataHash(data: ExternalData): Uint8Array {
  const preimage: number[] = [];
  preimage.push(data.instructionDiscriminator);
  preimage.push(...u64Be(data.expiryUnixTs));
  writeU16Be(preimage, data.relayerFee);
  preimage.push(...i64Be(data.publicSolAmount ?? 0n));
  preimage.push(...i64Be(data.publicSplAmount ?? 0n));
  preimage.push(...publicKeyBytes(data.userSolAccount));
  preimage.push(...publicKeyBytes(data.userSplToken));
  preimage.push(...publicKeyBytes(data.splTokenInterface));
  preimage.push(...(data.dataHash ?? new Uint8Array(32)));
  preimage.push(...(data.zoneDataHash ?? new Uint8Array(32)));
  writeU16Be(preimage, data.outputUtxoHashes.length);
  for (const hash of data.outputUtxoHashes) pushFixed(preimage, hash, 32, "output utxo hash");
  writeU16Be(preimage, data.outputCiphertexts.length);
  for (const ciphertext of data.outputCiphertexts) {
    pushFixed(preimage, ciphertext.viewTag, 32, "ciphertext view tag");
    writeU16Be(preimage, ciphertext.data.length);
    preimage.push(...ciphertext.data);
  }
  return sha256Be(new Uint8Array(preimage));
}

export function privateTxHash(
  inputHashes: Uint8Array[],
  outputHashes: Uint8Array[],
  addressHashes: Uint8Array[],
  externalHash: Uint8Array,
): Uint8Array {
  return poseidon([
    hashChain(inputHashes),
    hashChain(outputHashes),
    hashChain(addressHashes),
    externalHash,
  ]);
}

export function noAddressHashes(nInputs: number): Uint8Array[] {
  return Array.from({ length: nInputs }, () => new Uint8Array(32));
}

export function hashChain(items: Uint8Array[]): Uint8Array {
  if (items.length === 0) return new Uint8Array(32);
  let acc = items[0]!;
  for (const item of items.slice(1)) acc = poseidon([acc, item]);
  return acc;
}

function assembleInputs(
  inputs: Array<{ spend: SpendUtxo; proof?: SpendProof }>,
  rail: "p256" | "eddsa",
  tx: SignedTransaction,
) {
  const result = {
    inputs: [] as TransferInput[],
    inputHashes: [] as Uint8Array[],
    nullifiers: [] as Uint8Array[],
    utxoRoots: [] as Uint8Array[],
    nullifierTreeRoots: [] as Uint8Array[],
    inputOwnerPkHashes: [] as Uint8Array[],
    rootIndices: [] as Array<[number, number]>,
  };
  const p256SigningPkField = rail === "p256" ? p256OwnerPkField(tx) : new Uint8Array(32);
  for (const [index, { spend, proof }] of inputs.entries()) {
    if (!proof) {
      const utxoRoot = result.utxoRoots[0];
      const nfRoot = result.nullifierTreeRoots[0];
      const owner = result.inputOwnerPkHashes[0];
      const rootIndex = result.rootIndices[0];
      if (!utxoRoot || !nfRoot || !owner || !rootIndex) throw new Error("dummy input needs real root");
      const [dummy, nullifier] = transferInputDummy(spend.utxo.blinding, utxoRoot, nfRoot, owner);
      result.inputs.push(dummy);
      result.inputHashes.push(new Uint8Array(32));
      result.nullifiers.push(nullifier);
      result.utxoRoots.push(utxoRoot);
      result.nullifierTreeRoots.push(nfRoot);
      result.inputOwnerPkHashes.push(owner);
      result.rootIndices.push(rootIndex);
      continue;
    }
    checkPathLength(proof.state.path.length, STATE_TREE_HEIGHT);
    checkPathLength(proof.nullifier.path.length, NULLIFIER_TREE_HEIGHT);
    const dataHash = new Uint8Array(spend.dataHash ?? new Uint8Array(32));
    const zoneDataHash = new Uint8Array(spend.zoneDataHash ?? new Uint8Array(32));
    const nullifierPubkey = spend.nullifierKey.pubkey();
    const owner = spend.utxo.owner.ownerPkField();
    const ownerField = poseidon([owner, nullifierPubkey]);
    const utxoCommitment = spend.utxo.hash(new Uint8Array(nullifierPubkey), dataHash, zoneDataHash);
    const nullifier = spend.nullifierKey.nullifier(utxoCommitment, spend.utxo.blinding);
    const isP256 = spend.utxo.owner.signatureType() === "p256";
    if (rail === "eddsa" && isP256) throw new Error(`input ${index} is not Solana-owned`);
    const ownerPkHash = isP256 ? p256SigningPkField : spend.utxo.owner.ownerPkField();
    result.inputs.push({
      utxo: utxoInputsFromUtxo(spend.utxo, ownerField, dataHash, zoneDataHash),
      isDummy: 0n,
      statePathElements: proof.state.path.map(bytesToBigInt),
      statePathIndex: BigInt(proof.state.leafIndex),
      nullifierLowValue: bytesToBigInt(proof.nullifier.lowElement),
      nullifierNextValue: bytesToBigInt(proof.nullifier.highElement),
      nullifierLowPathElements: proof.nullifier.path.map(bytesToBigInt),
      nullifierLowPathIndex: BigInt(proof.nullifier.lowElementIndex),
      utxoTreeRoot: bytesToBigInt(proof.state.root),
      nullifierTreeRoot: bytesToBigInt(proof.nullifier.root),
      nullifier: bytesToBigInt(nullifier),
      ownerPkHash: bytesToBigInt(ownerPkHash),
      nullifierSecret: bytesToBigInt(rightAlign(spend.nullifierKey.secretBytes())),
    });
    result.inputHashes.push(utxoCommitment);
    result.nullifiers.push(nullifier);
    result.utxoRoots.push(proof.state.root);
    result.nullifierTreeRoots.push(proof.nullifier.root);
    result.inputOwnerPkHashes.push(ownerPkHash);
    result.rootIndices.push([proof.state.rootIndex, proof.nullifier.rootIndex]);
  }
  return result;
}

function assembleOutputs(outputs: OutputUtxo[]) {
  const result = {
    outputs: [] as TransferOutput[],
    outputHashes: [] as Uint8Array[],
    privateTxOutputHashes: [] as Uint8Array[],
    outputOwnerPkHashes: [] as Uint8Array[],
  };
  for (const output of outputs) {
    const hash = output.hash();
    const ownerPkField = output.ownerAddress
      ? output.ownerAddress.signingPubkey.ownerPkField()
      : hashField(output.ownerTag ?? new Uint8Array(32));
    result.outputs.push({
      utxo: utxoInputsFromOutput(output),
      isDummy: output.isDummy() ? 1n : 0n,
      hash: bytesToBigInt(hash),
      ownerPkHash: bytesToBigInt(ownerPkField),
      nullifierPk: bytesToBigInt(output.ownerAddress?.nullifierPubkey ?? new Uint8Array(32)),
    });
    result.outputHashes.push(hash);
    result.privateTxOutputHashes.push(output.isDummy() ? new Uint8Array(32) : hash);
    result.outputOwnerPkHashes.push(ownerPkField);
  }
  return result;
}

function publicInputsHash(args: {
  nullifiers: Uint8Array[];
  outputHashes: Uint8Array[];
  utxoRoots: Uint8Array[];
  nullifierTreeRoots: Uint8Array[];
  privateTx: Uint8Array;
  p256MessageHash: Uint8Array;
  externalDataHash: Uint8Array;
  publicAmounts: PublicAmounts;
  zoneProgramId: Uint8Array;
  payerPubkeyHash: Uint8Array;
  inputOwnerPkHashes: Uint8Array[];
  outputOwnerPkHashes: Uint8Array[];
  p256SigningPkField: Uint8Array;
}): Uint8Array {
  return hashChain([
    hashChain(args.nullifiers),
    hashChain(args.outputHashes),
    hashChain(args.utxoRoots),
    hashChain(args.nullifierTreeRoots),
    args.privateTx,
    hashField(args.p256MessageHash),
    args.externalDataHash,
    args.publicAmounts.sol,
    args.publicAmounts.spl,
    args.publicAmounts.asset,
    args.zoneProgramId,
    args.payerPubkeyHash,
    hashChain(args.inputOwnerPkHashes),
    hashChain(args.outputOwnerPkHashes),
    args.p256SigningPkField,
  ]);
}

function p256Witness(tx: SignedTransaction, privateTx: Uint8Array, p256SigningPkField: Uint8Array) {
  const ownerInput = tx.inputs.find((spend) => !isDummySpend(spend) && spend.utxo.owner.signatureType() === "p256");
  if (!ownerInput) throw new Error("missing P256 owner input");
  if (!tx.p256Owner) throw new Error("missing P256 signature");
  const compressed = ownerInput.utxo.owner.asP256().asBytes();
  const point = p256.Point.fromHex(Buffer.from(compressed).toString("hex")).toAffine();
  const pubX = bigIntToBytes(point.x, 32);
  const pubY = bigIntToBytes(point.y, 32);
  const msgHash = sha256(privateTx);
  const [low, high] = splitBe128Local(msgHash);
  return {
    p256PubX: bytesToBigInt(pubX),
    p256PubY: bytesToBigInt(pubY),
    p256SigR: bytesToBigInt(tx.p256Owner.slice(0, 32)),
    p256SigS: bytesToBigInt(tx.p256Owner.slice(32)),
    p256MessageHashLow: bytesToBigInt(low),
    p256MessageHashHigh: bytesToBigInt(high),
    p256SigningPkField: bytesToBigInt(p256SigningPkField),
  };
}

function p256OwnerPkField(tx: SignedTransaction): Uint8Array {
  const owner = tx.inputs.find((spend) => !isDummySpend(spend) && spend.utxo.owner.signatureType() === "p256")?.utxo.owner;
  if (!owner) throw new Error("missing P256 owner input");
  return owner.ownerPkField();
}

function utxoInputsFromUtxo(
  utxo: Utxo,
  owner: Uint8Array,
  dataHash: Uint8Array,
  zoneDataHash: Uint8Array,
): UtxoInputs {
  return {
    domain: 1n,
    owner: bytesToBigInt(owner),
    asset: bytesToBigInt(hashField(publicKeyBytes(utxo.asset))),
    amount: utxo.amount,
    blinding: bytesToBigInt(rightAlign(utxo.blinding)),
    dataHash: bytesToBigInt(dataHash),
    zoneDataHash: bytesToBigInt(zoneDataHash),
    zoneProgramId: bytesToBigInt(programIdField(utxo.zoneProgramId)),
  };
}

function utxoInputsFromOutput(output: OutputUtxo): UtxoInputs {
  return {
    domain: 1n,
    owner: bytesToBigInt(output.ownerHash()),
    asset: bytesToBigInt(hashField(publicKeyBytes(output.asset))),
    amount: output.amount,
    blinding: bytesToBigInt(rightAlign(output.blinding)),
    dataHash: bytesToBigInt(output.dataHash ?? new Uint8Array(32)),
    zoneDataHash: bytesToBigInt(output.zoneDataHash ?? new Uint8Array(32)),
    zoneProgramId: bytesToBigInt(programIdField(output.zoneProgramId)),
  };
}

function transferInputDummy(
  blinding: Uint8Array,
  utxoRoot: Uint8Array,
  nullifierRoot: Uint8Array,
  ownerPkHash: Uint8Array,
): [TransferInput, Uint8Array] {
  const nullifier = poseidon([new Uint8Array(32), rightAlign(blinding), new Uint8Array(32)]);
  return [
    {
      utxo: {
        domain: 0n,
        owner: 0n,
        asset: 0n,
        amount: 0n,
        blinding: bytesToBigInt(rightAlign(blinding)),
        dataHash: 0n,
        zoneDataHash: 0n,
        zoneProgramId: 0n,
      },
      isDummy: 1n,
      statePathElements: Array.from({ length: STATE_TREE_HEIGHT }, () => 0n),
      statePathIndex: 0n,
      nullifierLowValue: 0n,
      nullifierNextValue: 0n,
      nullifierLowPathElements: Array.from({ length: NULLIFIER_TREE_HEIGHT }, () => 0n),
      nullifierLowPathIndex: 0n,
      utxoTreeRoot: bytesToBigInt(utxoRoot),
      nullifierTreeRoot: bytesToBigInt(nullifierRoot),
      nullifier: bytesToBigInt(nullifier),
      ownerPkHash: bytesToBigInt(ownerPkHash),
      nullifierSecret: 0n,
    },
    nullifier,
  ];
}

function newDummySpend(): SpendUtxo {
  return {
    utxo: new Utxo({
      owner: PublicKey.zeroed(),
      asset: SOL_MINT,
      amount: 0n,
      blinding: randomBlinding(),
    }),
    nullifierKey: new NullifierKey(new Uint8Array(BLINDING_LEN)),
  };
}

function isDummySpend(spend: SpendUtxo): boolean {
  return spend.utxo.owner.isZero();
}

function inputsRequireP256(inputs: SpendUtxo[]): boolean {
  return inputs.some((spend) => !isDummySpend(spend) && spend.utxo.owner.signatureType() === "p256");
}

function resolveTransactionShape(
  declared: TransactionShape | undefined,
  nInputs: number,
  nOutputs: number,
): TransactionShape {
  const shape = declared ?? TRANSACTION_SUPPORTED_SHAPES.find((s) => nInputs <= s.nInputs && nOutputs <= s.nOutputs);
  if (!shape) throw new Error(`unsupported transaction shape ${nInputs}x${nOutputs}`);
  if (nInputs > shape.nInputs) throw new Error(`too many inputs: ${nInputs}`);
  if (nOutputs > shape.nOutputs) throw new Error(`too many outputs: ${nOutputs}`);
  return shape;
}

function assetIdFor(assets: AssetRegistry, asset: Address): number {
  return asset.equals(SOL_MINT) ? 1 : assets.assetId(asset);
}

function signedToField(value: bigint): Uint8Array {
  const reduced = ((value % BN254_MODULUS) + BN254_MODULUS) % BN254_MODULUS;
  return bigIntToBytes(reduced, 32);
}

function randomViewTag(): Uint8Array {
  const input = new Uint8Array(32);
  input.set(randomBlinding(), 1);
  return poseidon([input]);
}

function dummyCiphertextLen(tx: ViewingKey, recipientPubkey: P256Pubkey, salt: Uint8Array, assets: AssetRegistry): number {
  const dummy = new Utxo({
    owner: PublicKey.zeroed(),
    asset: SOL_MINT,
    amount: 0n,
    blinding: randomBlinding(),
  });
  return encodeConfidentialRecipient(
    {
      assetId: assets.assetId(dummy.asset),
      amount: dummy.amount,
      blinding: dummy.blinding,
      data: Data.empty(),
    },
    new Uint8Array(32),
    { tx, recipientPubkey, salt, slotIndex: 0 },
  ).data.length;
}

function checkPathLength(got: number, expected: number): void {
  if (got !== expected) throw new Error(`proof path has ${got} elements, expected ${expected}`);
}

function splitBe128Local(value: Uint8Array): [Uint8Array, Uint8Array] {
  assertLength(value, 32, "value");
  const low = new Uint8Array(32);
  const high = new Uint8Array(32);
  high.set(value.slice(0, 16), 16);
  low.set(value.slice(16), 16);
  return [low, high];
}

function pushFixed(out: number[], bytes: Uint8Array, len: number, name: string): void {
  assertLength(bytes, len, name);
  out.push(...bytes);
}

function writeVecU8<T>(out: number[], values: T[], write: (value: T) => void): void {
  if (values.length > 0xff) throw new Error("vector length exceeds u8");
  out.push(values.length);
  for (const value of values) write(value);
}

function writeBytesU16(out: number[], bytes: Uint8Array): void {
  writeU16Le(out, bytes.length);
  out.push(...bytes);
}

function writeOptionFixed(out: number[], bytes: Uint8Array | undefined, len: number, name: string): void {
  if (!bytes) {
    out.push(0);
    return;
  }
  out.push(1);
  pushFixed(out, bytes, len, name);
}

function writeOptionPubkey(out: number[], address?: Address | null): void {
  if (!address) {
    out.push(0);
    return;
  }
  out.push(1, ...publicKeyBytes(address));
}

function writeTransactProof(out: number[], proof: TransactProof): void {
  if (proof.kind === "eddsa") {
    out.push(0);
    pushFixed(out, proof.a, 32, "proof a");
    pushFixed(out, proof.b, 64, "proof b");
    pushFixed(out, proof.c, 32, "proof c");
  } else {
    out.push(1);
    pushFixed(out, proof.a, 32, "proof a");
    pushFixed(out, proof.b, 64, "proof b");
    pushFixed(out, proof.c, 32, "proof c");
    pushFixed(out, proof.commitment, 32, "proof commitment");
    pushFixed(out, proof.commitmentPok, 32, "proof commitment pok");
  }
}

function writeOptionI64(out: number[], value?: bigint): void {
  if (value === undefined) {
    out.push(0);
    return;
  }
  out.push(1, ...i64Le(value));
}

function i64Le(value: bigint): number[] {
  const normalized = value < 0n ? (1n << 64n) + value : value;
  const out: number[] = [];
  writeU64Le(out, normalized);
  return out;
}

function i64Be(value: bigint): Uint8Array {
  const normalized = value < 0n ? (1n << 64n) + value : value;
  return bigIntToBytes(normalized, 8);
}

function writeU16Be(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error("u16 out of range");
  out.push((value >>> 8) & 0xff, value & 0xff);
}

function writeU32Le(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new Error("u32 out of range");
  out.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}
