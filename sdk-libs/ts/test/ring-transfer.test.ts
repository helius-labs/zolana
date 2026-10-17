import { X25519Secret } from "../src/keypair/x25519.js";
import { ClientError } from "../src/client/error.js";
import {
  address,
  getAddressDecoder,
  getAddressEncoder,
  getProgramDerivedAddress,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { treeAddress } from "../src/interface/pda/index.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import { StateDiscriminator } from "../src/interface/state.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes128,
  Signature,
  TransactInstructionData,
} from "../src/interface/types.js";
import { solanaOwnerIdentity } from "../src/hasher/index.js";
import {
  auditPublicInputHash,
  auditorViewTag,
  encryptTransactionViewingSecret,
  parseAuditorMessage,
  symmetricAuditApply,
} from "../src/keypair/audit.js";
import { bytesToBigInt } from "../src/keypair/bytes.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import {
  auditRing,
  auditRingTransaction,
  auditorMessage,
  recoverTransactionViewingKey,
} from "../src/ring/audit.js";
import {
  assemble,
  ownerSignerAddresses,
  ringOpenings,
  signerIdentity,
} from "../src/client/prover/assembly.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingPolicyProofRequest,
} from "../src/client/prover/types.js";
import { ringAuditReader, ringTransferClient, transactionsPage } from "./helpers/clients.js";
import type { SpendProof } from "../src/client/rpc.js";
import { hashBytesBigInt } from "../src/client/internal.js";
import { hashBytes } from "../src/hasher/index.js";
import {
  checkRingMembership,
  frameDummyOutputs,
  proveCustomRingTransfer,
  proveCustomRingDelegateTransfer,
  type CustomRingDelegateTransferParams,
} from "../src/ring/transfer.js";
import {
  ListId,
  buildRuleTable,
  encodeRuleTable,
  memberOfTag,
  memberOfAsset,
  ringNamespaceOwnerHash,
  type Rule,
} from "../src/ring/policy.js";
import { ringPolicyNamespaceAddress } from "../src/ring/config.js";
import { ownSources, ownedAccount, ringPolicyConfigData } from "./helpers/ring-accounts.js";
import {
  memberRegistryRootData,
  oneMemberRegistry,
  registryFixture,
  emptyMemberRecord,
} from "./helpers/member-registry.js";
import { MEMBER_REGISTRY_EMPTY_ROOT } from "../src/ring/member-registry-tree.js";
import { ringMemberRegistryRootPda } from "../src/interface/pda/index.js";
import { entryProofReads } from "./helpers/ring-entries.js";
import { treeAccount } from "./helpers/tree-account.js";
import {
  RING_POLICY_SUPPORTED_SHAPES,
  RING_AUTHORITY_WIDTHS,
  ringAuthorityWidth,
} from "../src/interface/shape.js";
import {
  ConfidentialTransfer,
  SppProofInputs,
  privateTxAddressChain,
  prepareRingAuthorityTransfer,
  createExternalData,
  sppPrivateTxHashInput,
  type IndexedShieldedTransaction,
  type PreparedTransfer,
} from "../src/transaction/instructions/transact.js";
import { nonZeroHashChain, poseidon } from "../src/transaction/internal.js";
import {
  EncryptedScheme,
  encodeConfidential,
  readOutputData,
} from "../src/transaction/serialization/codecs.js";
import { Data } from "../src/transaction/data.js";
import { ProofInputUtxo, Utxo, createProofOutput } from "../src/transaction/utxo.js";
import { AssetRegistry, SOL_ASSET_ID, SOL_MINT } from "../src/transaction/asset.js";
import { LocalKeys } from "../src/client/keys.js";
import {
  encryptConfidentialTransfer,
  encryptCustomRingTransfer,
} from "../src/transaction/wallet/encrypt-rails.js";
import { LocalShieldedKeys } from "../src/transaction/wallet/keys.js";
import { withTransactionKey } from "../src/wallet/private-transaction.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
/** Every input proves from tree 0, the id the builders default to; the ring is not a tree. */
const TREE = treeAddress(0);
const ACTIVE_TREE = TREE;

function scalar(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(scalar(seed)));
  return {
    keypair,
    keys: LocalShieldedKeys.fromKeypair(keypair),
    address: keypair.shieldedAddress(),
  };
}

function ownedInput(
  owner: ReturnType<typeof actor>,
  utxo: ConstructorParameters<typeof Utxo>[0],
  hashes?: Parameters<typeof ProofInputUtxo.fromNullifierKey>[2],
): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(new Utxo(utxo), owner.keypair, hashes);
}

/** A 10 SOL ring UTXO of `sender` sending `amount` to `recipient` and `others`. */
function preparedTransfer(
  amount: bigint,
  others: readonly bigint[] = [],
  exits: readonly bigint[] = [],
  inputRing: typeof RING | null = RING,
  asset: Address = SOL_MINT,
  payer?: Address,
  shape?: Readonly<{ inputs: number; outputs: number }>,
): Readonly<{
  prepared: PreparedTransfer;
  sender: ReturnType<typeof actor>;
  recipient: ReturnType<typeof actor>;
}> {
  const sender = actor(3);
  const recipient = actor(4);
  const input = ownedInput(sender, {
    owner: sender.keypair.signingPublicKey(),
    asset,
    amount: 10n,
    blinding: scalar(6),
    ...(inputRing === null ? {} : { ringProgramId: inputRing }),
  });
  const transfer = new ConfidentialTransfer(
    sender.address,
    [input],
    payer ?? sender.address.solanaAddress(),
  ).withRingProgramId(RING);
  transfer.send(recipient.address, asset, amount);
  others.forEach((other, index) => transfer.send(actor(5 + index).address, asset, other));
  exits.forEach((exit, index) => transfer.sendDefaultRing(actor(20 + index).address, asset, exit));
  if (shape !== undefined) transfer.withShape(shape);
  return { prepared: transfer.prepare(), sender, recipient };
}

async function auditedProofInputs(
  amount: bigint,
  auditor: X25519Secret,
  others: readonly bigint[] = [],
  exits: readonly bigint[] = [],
  inputRing: typeof RING | null = RING,
  asset: Address = SOL_MINT,
  assets: AssetRegistry = new AssetRegistry(),
  payer?: Address,
): Promise<Readonly<{ proofInputs: SppProofInputs; recipient: ReturnType<typeof actor> }>> {
  const { prepared, sender, recipient } = preparedTransfer(
    amount,
    others,
    exits,
    inputRing,
    asset,
    payer,
  );
  return { proofInputs: await sealAudited(prepared, sender, auditor, assets), recipient };
}

async function sealAudited(
  ring: PreparedTransfer,
  sender: ReturnType<typeof actor>,
  auditor: X25519Secret,
  assets: AssetRegistry = new AssetRegistry(),
): Promise<SppProofInputs> {
  const encrypted = await withTransactionKey(sender.keys, ring.firstNullifier, (tx) =>
    encryptCustomRingTransfer(tx, {
      outputs: ring.proofOutputs(),
      assets,
      auditorPublicKey: auditor.publicKey(),
      outputTreeId: ring.outputTreeId,
    }),
  );
  return frameDummyOutputs(
    ring.finalize({
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      payload: encrypted.payload,
      messages: [encrypted.auditorMessage],
      instructionDiscriminator: InstructionTag.ringTransact,
    }),
  );
}

/** Builds a wide SPP fixture for framing tests; custom-ring proofs deliberately cap outputs at four. */
async function paddedProofInputs(
  amount: bigint,
  others: readonly bigint[] = [],
  exits: readonly bigint[] = [],
): Promise<Readonly<{ proofInputs: SppProofInputs; recipient: ReturnType<typeof actor> }>> {
  const { prepared, sender, recipient } = preparedTransfer(amount, others, exits);
  const encrypted = await withTransactionKey(sender.keys, prepared.firstNullifier, (tx) =>
    encryptConfidentialTransfer(tx, {
      outputs: prepared.outputs,
      assets: new AssetRegistry(),
    }),
  );
  return {
    recipient,
    proofInputs: frameDummyOutputs(
      prepared.finalize({
        txViewingPublicKey: encrypted.txViewingPublicKey,
        salt: encrypted.salt,
        payload: encrypted.payload,
        instructionDiscriminator: InstructionTag.ringTransact,
      }),
    ),
  };
}

function indexed(proofInputs: SppProofInputs): IndexedShieldedTransaction {
  const external = proofInputs.externalData;
  return {
    slot: 5n,
    txSignature: "1".repeat(87) as Signature,
    eventIndex: 0,
    ringProgramId: RING,
    txViewingPublicKey: external.txViewingPublicKey,
    salt: external.salt,
    outputSlots: external.outputs.map((output, index) => ({
      viewTag: external.resolvedOwnerTags[index] ?? scalar(0),
      outputContext: { hash: output.utxoHash, tree: TREE, leafIndex: BigInt(index) },
      payload: output.data ?? new Uint8Array(),
    })),
    messages: external.messages,
    nullifiers: proofInputs.inputUtxos.map((input) => input.nullifier()),
    proofless: false,
  };
}

const unusedProofService = {
  prove: () => Promise.reject(new Error("prove must not be called directly")),
  proveMerge: () => Promise.reject(new Error("proveMerge must not be called directly")),
};

function delegateSpender(keys: LocalKeys): CustomRingDelegateTransferParams["spender"] {
  return {
    proofs: keys,
    withTransactionKey: (firstNullifier, use, context) =>
      withTransactionKey(keys, firstNullifier, use, context),
  };
}

function walletKeys(owner: ReturnType<typeof actor>): LocalKeys {
  return LocalKeys.fromKeypair(owner.keypair, unusedProofService);
}

/** The ring's config and, for a policy ring, a policy config over `ACTIVE_TREE` pinning `rules` sourced from the ring's own namespace, a `registryRoot` turns key escrow on. */
async function ringAccounts(
  auditor: X25519Secret,
  hasPolicy: boolean,
  rules: readonly Rule[] = [],
  limited = false,
  registryRoot?: Bytes32,
) {
  const encoder = new TextEncoder();
  const pda = (seed: string) =>
    getProgramDerivedAddress({ programAddress: RING, seeds: [encoder.encode(seed)] });
  const [configAddress, configBump] = await pda("config");
  const [policyAddress, policyBump] = await pda("policy");
  const [registryAddress, registryBump] = await ringMemberRegistryRootPda(RING);
  const table = buildRuleTable({
    rules,
    ...(limited ? { limits: [{ asset: memberOfAsset(SOL_MINT), cap: 1n, cosignAbove: 1n }] } : {}),
  });
  const sources = ownSources(table, await ringPolicyNamespaceAddress(RING));
  const namespaceOwnerHash = ringNamespaceOwnerHash(await ringPolicyNamespaceAddress(RING));
  const read: Address[] = [];
  const getAccount = async (account: Address) => {
    read.push(account);
    if (account === ACTIVE_TREE) {
      return ownedAccount(
        SHIELDED_POOL_PROGRAM_ID,
        treeAccount({ stateCursor: 7, written: 8, nullifierCursor: 4n }),
      );
    }
    if (account === configAddress) {
      return {
        owner: RING,
        lamports: 1n,
        data: Uint8Array.from([
          1,
          ...new Uint8Array(32),
          ...auditor.publicKey().toBytes(),
          configBump,
          hasPolicy ? 1 : 0,
          registryRoot === undefined ? 0 : 1,
        ]),
      };
    }
    if (account === registryAddress) {
      return ownedAccount(
        RING,
        memberRegistryRootData({
          root: registryRoot ?? MEMBER_REGISTRY_EMPTY_ROOT,
          nextIndex: registryRoot === undefined ? 1n : 2n,
          bump: registryBump,
          cursor: 1,
          history: [MEMBER_REGISTRY_EMPTY_ROOT],
        }),
      );
    }
    if (hasPolicy && account === policyAddress) {
      return {
        owner: RING,
        lamports: 1n,
        data: ringPolicyConfigData({
          table,
          sources,
          addressTree: ACTIVE_TREE,
          bump: policyBump,
          generation: 0,
          namespaceOwnerHash,
        }),
      };
    }
    return undefined;
  };
  return { getAccount, read, policyAddress, policy: encodeRuleTable(table) };
}

describe("delegate policy rail", () => {
  it("keeps a gross mint sum above u64 when payment and change each fit u64", () => {
    const sender = actor(3),
      recipient = actor(4);
    const amount = (1n << 63n) + 1n;
    const inputs = [0, 1].map((offset) =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount,
          blinding: scalar(70 + offset),
          ringProgramId: RING,
        }),
        sender.keypair,
      ),
    );
    const prepared = prepareRingAuthorityTransfer({
      owner: sender.address,
      inputs,
      outputs: [{ recipient: recipient.address, asset: SOL_MINT, amount: (1n << 64n) - 1n }],
      payer: actor(8).address.solanaAddress(),
      ringProgramId: RING,
      outputTreeId: 0,
    });
    expect(prepared.outputs.map((output) => output.amount)).toEqual([3n, (1n << 64n) - 1n]);
  });
  it("names the input outside the ring and the foreign owner separately", () => {
    const sender = actor(3),
      other = actor(5);
    const spend = (owner: ReturnType<typeof actor>, ring: boolean) =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: owner.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 10n,
          blinding: scalar(90),
          ...(ring ? { ringProgramId: RING } : {}),
        }),
        owner.keypair,
      );
    const prepare = (input: ProofInputUtxo) =>
      prepareRingAuthorityTransfer({
        owner: sender.address,
        inputs: [input],
        outputs: [{ recipient: other.address, asset: SOL_MINT, amount: 5n }],
        payer: actor(8).address.solanaAddress(),
        ringProgramId: RING,
        outputTreeId: 0,
      });
    expect(() => prepare(spend(sender, false))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INPUT_OUTSIDE_RING" }),
    );
    expect(() => prepare(spend(other, true))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INPUT_OWNER_MISMATCH" }),
    );
  });
  it("keeps the table and audit but never bounds the move by the limits", async () => {
    const auditor = X25519Secret.fromBytes(scalar(9));
    const sender = actor(3);
    const { prepared: money } = preparedTransfer(5n);
    // A delegate move escrows every output key, the source's own key is registered.
    const prepared = prepareRingAuthorityTransfer({
      owner: sender.address,
      inputs: money.inputs,
      outputs: [{ recipient: sender.address, asset: SOL_MINT, amount: 5n }],
      payer: actor(8).address.solanaAddress(),
      ringProgramId: RING,
      outputTreeId: 0,
    });
    const registry = oneMemberRegistry({
      member: memberOfTag(sender.address.confidentialViewTag()),
      nullifierKey: sender.keypair.nullifierKey(),
      auditor: auditor.publicKey(),
    });
    const accounts = await ringAccounts(auditor, true, [], true, registry.root);
    let policy: CustomRingPolicyProofRequest | undefined;
    let finalized: SppProofInputs | undefined;
    const client = ringTransferClient({ tree: TREE, getAccount: accounts.getAccount });
    const proved = await proveCustomRingDelegateTransfer({
      client: {
        proofDataSource: client.proofDataSource,
        tree: client.tree,
        treeId: client.treeId,
        getAccount: client.getAccount,
        getRingMemberRecord: async () => registry.entry,
        proveRingAuthorityTransact: async (inputs) => {
          finalized = inputs;
          return {
            data: {
              ...ringInstructionData(scalar(8)),
              circuit: { kind: "ringAuthority", inputs: 2, outputs: 2, publicAssetSlots: 3 },
            },
            roots: SPP_ROOTS,
          };
        },
        proveCustomRingDelegatePolicy: async (input) => {
          policy = input;
          return new Uint8Array(192);
        },
        proveCustomRingBase: client.proveCustomRingBase,
      },
      ringProgramId: RING,
      prepared,
      spender: delegateSpender(walletKeys(sender)),
      assets: new AssetRegistry(),
      tree: TREE,
    });
    expect(policy?.limits).toMatchObject({
      approvalRequired: false,
      limits: [{ cap: 1n, cosignAbove: 1n }],
    });
    expect(finalized?.inputUtxos.filter((input) => !input.isDummy())).toHaveLength(1);
    expect(finalized?.outputs.filter((output) => !output.isDummy())).toHaveLength(2);
    expect(finalized?.externalData.messages).toHaveLength(1);
    if (finalized === undefined) throw new Error("authority proof inputs were not captured");
    const authorityRefusal = (inputs: SppProofInputs): unknown => {
      try {
        assemble(inputs, [], [], { kind: "ringAuthority", ring: RING });
      } catch (error) {
        return (error as { code?: unknown }).code;
      }
      return undefined;
    };
    expect(authorityRefusal(finalized)).not.toBe("CLIENT_INVALID_PROOF_INPUTS");
    expect(authorityRefusal(finalized.withReadCache(actor(40).address.solanaAddress()))).toBe(
      "CLIENT_INVALID_PROOF_INPUTS",
    );
    expect(proved.ownerSigners).toEqual([]);
    expect(proved.approvalRequired).toBe(false);
    expect(proved.policy?.memberRegistryRootIndex).toBe(1);
    expect(proved.policy?.memberRegistryRoot).toEqual(registry.root);
    expect(policy?.memberRegistryRoot).toEqual(registry.root);
    auditor.destroy();
  });

  it("plans two SPL mints with per-mint change and no source signer", () => {
    const sender = actor(3),
      recipient = actor(4);
    const mintA = actor(30).address.solanaAddress(),
      mintB = actor(31).address.solanaAddress();
    const inputs = [mintA, mintB].map((asset, index) =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset,
          amount: 10n,
          blinding: scalar(40 + index),
          ringProgramId: RING,
        }),
        sender.keypair,
        {},
        7,
      ),
    );
    const prepared = prepareRingAuthorityTransfer({
      owner: sender.address,
      inputs,
      outputs: [
        { recipient: recipient.address, asset: mintA, amount: 4n },
        { recipient: recipient.address, asset: mintB, amount: 6n },
      ],
      payer: actor(8).address.solanaAddress(),
      ringProgramId: RING,
      outputTreeId: 7,
    });
    expect(prepared.shape).toEqual({ inputs: 4, outputs: 4 });
    expect(prepared.senderOutputCount).toBe(2);
    expect(prepared.outputs.map(({ asset, amount }) => ({ asset, amount }))).toEqual([
      { asset: mintA, amount: 6n },
      { asset: mintB, amount: 4n },
      { asset: mintA, amount: 4n },
      { asset: mintB, amount: 6n },
    ]);
    expect(prepared.interfaceTransfers).toEqual([]);
    expect(prepared.ownerMode).toBe("opaque");
  });

  it("rounds an authority transfer up to the 2x2 or 4x4 key", () => {
    const sender = actor(3),
      recipient = actor(4);
    const inputs = [0, 1, 2].map((offset) =>
      ProofInputUtxo.fromKeypair(
        new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 10n,
          blinding: scalar(60 + offset),
          ringProgramId: RING,
        }),
        sender.keypair,
      ),
    );
    const prepare = (spent: readonly ProofInputUtxo[], amount: bigint) =>
      prepareRingAuthorityTransfer({
        owner: sender.address,
        inputs: spent,
        outputs: [{ recipient: recipient.address, asset: SOL_MINT, amount }],
        payer: actor(8).address.solanaAddress(),
        ringProgramId: RING,
        outputTreeId: 0,
      });
    expect(prepare(inputs.slice(0, 1), 10n).shape).toEqual({ inputs: 2, outputs: 2 });
    expect(prepare(inputs, 25n).shape).toEqual({ inputs: 4, outputs: 4 });
    expect(RING_AUTHORITY_WIDTHS).toEqual([2, 4]);
    expect([0, 1, 2, 3, 4, 5].map(ringAuthorityWidth)).toEqual([2, 2, 2, 4, 4, undefined]);
  });
});

const SPP_ROOTS = {
  stateRoot: scalar(92),
  stateRootIndex: 4,
  nullifierRoot: scalar(93),
  nullifierRootIndex: 3,
};

function ringInstructionData(txHash: Bytes32): TransactInstructionData {
  return {
    expiryUnixTs: 0n,
    privateTxHash: txHash,
    circuit: { kind: "ringEddsa", inputs: 2, outputs: 4, publicAssetSlots: 3 },
    txViewingPk: new Uint8Array(33) as Bytes33,
    salt: new Uint8Array(16) as Bytes16,
    proof: {
      a: new Uint8Array(32) as Bytes32,
      b: new Uint8Array(128) as Bytes128,
      c: new Uint8Array(32) as Bytes32,
    },
    inputs: [],
    treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    interfaceTransfers: [],
    outputs: [],
    messages: [],
  };
}

describe("change layout", () => {
  it("leads with the present change and follows it with the recipient", () => {
    const compact = preparedTransfer(4n).prepared;
    expect(compact.shape).toEqual({ inputs: 1, outputs: 2 });
    expect(compact.outputs.map((output) => output.amount)).toEqual([6n, 4n]);
    expect(compact.senderOutputCount).toBe(1);
  });

  it("keeps only the recipient after a full spend", () => {
    const compact = preparedTransfer(10n).prepared;
    expect(compact.shape).toEqual({ inputs: 1, outputs: 2 });
    expect(compact.outputs.map((output) => output.amount)).toEqual([10n]);
    expect(compact.senderOutputCount).toBe(0);
  });

  it("binds the change and the recipients to the ring the transfer runs in", () => {
    const ring = preparedTransfer(4n).prepared;
    expect(ring.outputs.every((output) => output.ringProgramId === RING)).toBe(true);
  });

  it("moves an exact amount into a ring and keeps default change", () => {
    const sender = actor(3);
    const input = ownedInput(sender, {
      owner: sender.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: scalar(6),
    });
    const transfer = new ConfidentialTransfer(
      sender.address,
      [input],
      sender.address.solanaAddress(),
    );
    transfer.sendToRing(sender.address, SOL_MINT, 4n, RING);

    const prepared = transfer.prepare();

    expect(prepared.senderOutputCount).toBe(1);
    expect(prepared.outputs.map((output) => [output.amount, output.ringProgramId])).toEqual([
      [6n, undefined],
      [4n, RING],
    ]);
  });

  it("keeps a default-ring recipient out of the ring and refuses a foreign one", () => {
    const sender = actor(3);
    const input = ownedInput(sender, {
      owner: sender.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: scalar(6),
      ringProgramId: RING,
    });
    const transfer = new ConfidentialTransfer(
      sender.address,
      [input],
      sender.address.solanaAddress(),
    ).withRingProgramId(RING);
    transfer.sendDefaultRing(actor(4).address, SOL_MINT, 4n);
    const prepared = transfer.prepare();
    expect(prepared.outputs.map((output) => output.ringProgramId)).toEqual([RING, undefined]);

    const foreign = prepared.outputs[1]?.withRingProgramId(actor(9).address.solanaAddress());
    expect(() =>
      checkRingMembership({ ...prepared, outputs: [prepared.outputs[0]!, foreign!] }, RING),
    ).toThrow("RING_FOREIGN_RING");
  });

  it("refuses ring data on a default UTXO like Rust `RingMembership`", () => {
    const sender = actor(3);
    // No nullifier derives from a commitment the hash refuses, so it is carried in.
    const tainted = new ProofInputUtxo({
      utxo: new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: scalar(6),
      }),
      nullifierPublicKey: sender.keypair.nullifierPublicKey(),
      nullifier: scalar(7),
      ringDataHash: scalar(9),
    });
    // The commitment refuses it wherever the input is hashed, and the ring
    // membership rule refuses it before the proof is assembled.
    expect(() => tainted.hash()).toThrow("TRANSACTION_MISSING_RING_PROGRAM_ID");

    const { prepared } = preparedTransfer(4n);
    expect(() => checkRingMembership({ ...prepared, inputs: [tainted] }, RING)).toThrow(
      "RING_DATA_OUTSIDE_RING",
    );
  });
});

describe("frameDummyOutputs", () => {
  for (const ringProgramId of [undefined, RING]) {
    it(`frames all-dummy outputs without a real template (${ringProgramId === undefined ? "default" : "ring"})`, async () => {
      const { proofInputs } = await auditedProofInputs(4n, X25519Secret.generate());
      const outputs = proofInputs.outputs.map((output) =>
        createProofOutput({
          asset: SOL_MINT,
          amount: 0n,
          blinding: output.blinding,
          ownerTag: scalar(3),
          ...(ringProgramId === undefined ? {} : { ringProgramId }),
        }),
      );
      const unframed = new SppProofInputs({
        payer: proofInputs.payer,
        inputUtxos: proofInputs.inputUtxos,
        outputs,
        blindingSeed: proofInputs.blindingSeed,
        outputTreeId: proofInputs.outputTreeId,
        externalData: createExternalData({
          ...proofInputs.externalData,
          outputs: proofInputs.externalData.outputs.map((output, index) => ({
            ownerTag: output.ownerTag,
            utxoHash: outputs[index]!.hash(proofInputs.outputTreeId),
          })),
        }),
      });
      const framed = frameDummyOutputs(unframed);
      const plaintext = encodeConfidential({
        assetId: SOL_ASSET_ID,
        amount: 0n,
        blinding: scalar(0),
        data: new Data(),
        ...(ringProgramId === undefined ? {} : { ringProgramId }),
      });
      for (const output of framed.externalData.outputs) {
        const body = readOutputData(output.data ?? new Uint8Array());
        expect(body).toMatchObject({
          encoding: "encrypted",
          scheme:
            ringProgramId === undefined
              ? EncryptedScheme.confidential
              : EncryptedScheme.ringConfidential,
        });
        expect(body.body).toHaveLength(33 + plaintext.length);
        expect(body.body[0]).toBe(4);
      }
      expect(framed.outputs).toEqual(unframed.outputs);
      expect(framed.externalData.messages).toEqual(unframed.externalData.messages);
    });
  }
  it("frames ring padding as ring-confidential bodies of the real length like Rust `frame_dummy_outputs`", async () => {
    // Five real outputs pad to the (1, 8) shape.
    const { proofInputs } = await paddedProofInputs(4n, [1n, 1n, 1n]);
    expect(proofInputs.outputs).toHaveLength(8);
    const external = proofInputs.externalData;
    const lengths = external.outputs.map((output) => output.data?.length);
    expect(new Set(lengths).size).toBe(1);
    const dummies = proofInputs.outputs.flatMap((output, index) =>
      output.isDummy() ? [index] : [],
    );
    expect(dummies.length).toBeGreaterThanOrEqual(1);
    const keys = dummies.map((index) => {
      const frame = readOutputData(external.outputs[index]?.data ?? new Uint8Array());
      expect(frame.encoding).toBe("encrypted");
      expect(frame.scheme).toBe(EncryptedScheme.ringConfidential);
      expect(frame.body[0]).toBe(4);
      return Buffer.from(frame.body.subarray(0, 33)).toString("hex");
    });
    expect(new Set(keys).size).toBe(keys.length);
    for (const [index, output] of proofInputs.outputs.entries()) {
      if (output.isDummy()) continue;
      const frame = readOutputData(external.outputs[index]?.data ?? new Uint8Array());
      expect(frame.scheme).toBe(EncryptedScheme.ringConfidential);
    }
    expect(external.instructionDiscriminator).toBe(InstructionTag.ringTransact);
    expect(external.messages).toHaveLength(0);
  });
});

describe("frameDummyOutputs with an exit", () => {
  it("frames ring padding after a default-ring slot at the ring slot length", async () => {
    const { proofInputs } = await paddedProofInputs(3n, [1n, 1n], [1n]);
    expect(proofInputs.outputs).toHaveLength(8);
    const external = proofInputs.externalData;
    const lengthOf = (index: number): number => external.outputs[index]?.data?.length ?? 0;
    const ringSlot = proofInputs.outputs.findIndex(
      (output) => !output.isDummy() && output.ringProgramId === RING,
    );
    const exitSlot = proofInputs.outputs.findIndex(
      (output) => !output.isDummy() && output.ringProgramId === undefined,
    );
    expect(lengthOf(ringSlot) - lengthOf(exitSlot)).toBe(32);
    for (const [index, output] of proofInputs.outputs.entries()) {
      if (!output.isDummy()) continue;
      expect(output.ringProgramId).toBe(RING);
      expect(lengthOf(index)).toBe(lengthOf(ringSlot));
      const frame = readOutputData(external.outputs[index]?.data ?? new Uint8Array());
      expect(frame.scheme).toBe(EncryptedScheme.ringConfidential);
    }
  });
});

function spendProofFor(input: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: Array.from({ length: 32 }, () => scalar(0)),
      leafIndex: 0n,
      root: scalar(3),
      rootSeq: 1n,
      rootIndex: 4,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 40 }, () => scalar(0)),
      lowElement: scalar(4),
      lowElementIndex: 0n,
      highElement: scalar(5),
      highElementIndex: 1n,
      root: scalar(6),
      rootSeq: 1n,
      rootIndex: 2,
    },
  };
}

describe("ring witness", () => {
  it("publishes owner hashes only for `Confidential` slots like Rust `confidential_marked_output_owner_pk_hashes`", async () => {
    const { proofInputs } = await paddedProofInputs(4n, [1n, 1n, 1n], [1n]);
    const input = proofInputs.inputUtxos[0];
    if (!input) throw new Error("input");
    const spendProof = spendProofFor(input);
    const assembled = assemble(proofInputs, [spendProof], [], { kind: "ring", ring: RING });
    const published = assembled.proverInputs.payload.publishedOutputOwnerPublicKeyHashes;
    const tags = proofInputs.externalData.resolvedOwnerTags;
    expect(published).toHaveLength(8);
    proofInputs.outputs.forEach((output, index) => {
      const tag = tags[index];
      if (!tag) throw new Error("owner tag");
      // A published tag is a Solana signer, so it enters as its tagged identity
      // (`0x53 || pk`), not the bare hash of the tag bytes.
      expect(published[index]).toBe(
        output.ringProgramId === undefined ? bytesToBigInt(solanaOwnerIdentity(tag)) : 0n,
      );
    });
    expect(assembled.proverInputs.circuit).toBe("transferRing");
    expect(assembled.proverInputs.payload.ringProgramId).toBe(
      hashBytesBigInt(new Uint8Array(getAddressEncoder().encode(RING))),
    );
    expect(assembled.instructionData.circuit.kind).toBe("ringEddsa");
    // The first input's roots and indices, the pair a ring statement binds.
    expect(assembled.roots).toEqual({
      stateRoot: scalar(3),
      stateRootIndex: 4,
      nullifierRoot: scalar(6),
      nullifierRootIndex: 2,
    });
  });
});

describe("ring openings", () => {
  const zeroOpening = (domain: number) => ({
    domain: scalar(domain),
    treeId: scalar(0),
    ownerPkHash: scalar(0),
    nullifierPk: scalar(0),
    asset: scalar(0),
    amount: scalar(0),
    blinding: scalar(0),
    dataHash: scalar(0),
    ringDataHash: scalar(0),
    ringProgramId: scalar(0),
  });

  it("opens every slot like Rust `CustomRingWitnessInput`", async () => {
    // Change 5, recipient 4, other 1 fill the (2, 4) shape with one dummy on each side.
    const { prepared, sender, recipient } = preparedTransfer(
      4n,
      [1n],
      [],
      RING,
      SOL_MINT,
      undefined,
      { inputs: 2, outputs: 4 },
    );
    const proofInputs = await sealAudited(prepared, sender, X25519Secret.generate());
    const openings = ringOpenings(proofInputs);
    expect(openings.nIn).toBe(2);
    expect(openings.nOut).toBe(4);

    const spend = proofInputs.inputUtxos[0];
    if (!spend) throw new Error("input");
    expect(openings.inputs[0]).toEqual({
      domain: scalar(3),
      treeId: scalar(0),
      ownerPkHash: spend.utxo.owner.ownerProofInputHash(),
      nullifierPk: spend.nullifierPublicKey,
      asset: hashBytes(new Uint8Array(getAddressEncoder().encode(SOL_MINT))),
      amount: scalar(10),
      blinding: scalar(6),
      dataHash: scalar(0),
      ringDataHash: scalar(0),
      ringProgramId: hashBytes(new Uint8Array(getAddressEncoder().encode(RING))),
    });
    // Dummy inputs do not enter the output disclosure.
    expect(openings.inputs[1]).toEqual(zeroOpening(1));
    expect(openings.inputs.slice(2)).toEqual([zeroOpening(0), zeroOpening(0), zeroOpening(0)]);

    const change = openings.outputs[0];
    const paid = openings.outputs[1];
    if (!change || !paid) throw new Error("outputs");
    expect(change.domain).toEqual(scalar(3));
    expect(change.amount).toEqual(scalar(5));
    expect(paid.amount).toEqual(scalar(4));
    expect(paid.ownerPkHash).toEqual(recipient.address.signingPublicKey.ownerProofInputHash());
    expect(paid.nullifierPk).toEqual(recipient.address.nullifierPublicKey);
    expect(openings.outputs[3]).toMatchObject({ domain: scalar(1), amount: scalar(0) });
  });

  it("opens an owner-tagged slot without an address as a dummy, like Rust", async () => {
    const { proofInputs } = await auditedProofInputs(4n, X25519Secret.generate(), [1n]);
    const outputs = [...proofInputs.outputs];
    outputs[2] = createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: scalar(9),
      ownerTag: scalar(7),
    });
    const swapped = new SppProofInputs({
      payer: proofInputs.payer,
      inputUtxos: proofInputs.inputUtxos,
      outputs,
      externalData: proofInputs.externalData,
      blindingSeed: proofInputs.blindingSeed,
      outputTreeId: proofInputs.outputTreeId,
    });
    // Never the `solanaOwnerIdentity(ownerTag)` fallback the SPP owner field publishes.
    expect(ringOpenings(swapped).outputs[2]).toEqual({
      ...zeroOpening(1),
      treeId: scalar(proofInputs.outputTreeId),
      blinding: scalar(9),
    });
  });

  it("refuses a transfer wider than the ring slots", async () => {
    const { proofInputs } = await paddedProofInputs(4n, [1n, 1n, 1n]);
    expect(proofInputs.outputs).toHaveLength(8);
    expect(() => ringOpenings(proofInputs)).toThrow("CLIENT_PROVER_INPUT");
  });

  it("derives the namespace owner hash the Go policy fixture pins", () => {
    const namespacePda = getAddressDecoder().decode(new Uint8Array(32).fill(0x11));
    expect(ringNamespaceOwnerHash(namespacePda)).toEqual(
      Uint8Array.from(
        Buffer.from("2cb09cab7a637278cc7157bb6780f81e5abdcc5e001eddad5279891f03f05196", "hex"),
      ),
    );
  });

  it("assembles a foreign fee payer with the owner as an appended signer", async () => {
    const payer = actor(8).address.solanaAddress();
    const owner = actor(3);
    const { proofInputs } = await auditedProofInputs(
      4n,
      X25519Secret.generate(),
      [],
      [],
      RING,
      SOL_MINT,
      new AssetRegistry(),
      payer,
    );
    const input = proofInputs.inputUtxos[0];
    if (!input) throw new Error("input");
    const assembled = assemble(proofInputs, [spendProofFor(input)], [], {
      kind: "ring",
      ring: RING,
    });
    const vector = assembled.proverInputs.payload.signerPublicKeyHashes;
    // Signers enter the chain as tagged Solana identities, `hash(0x53 || pk)`.
    const hashOf = (target: Address) =>
      bytesToBigInt(solanaOwnerIdentity(new Uint8Array(getAddressEncoder().encode(target))));
    expect(vector[0]).toBe(hashOf(payer));
    expect(vector[0]).toBe(signerIdentity(payer));
    expect(vector[1]).toBe(hashOf(owner.address.solanaAddress()));
    expect(vector.slice(2).every((entry) => entry === 0n)).toBe(true);
    expect(ownerSignerAddresses(proofInputs.inputUtxos, payer)).toEqual([
      owner.address.solanaAddress(),
    ]);
  });

  it("refuses a tree the client does not prove from, before any fetch", async () => {
    const client = ringTransferClient();
    await expect(
      proveCustomRingTransfer({
        client,
        ringProgramId: RING,
        prepared: {} as PreparedTransfer,
        keys: LocalKeys.fromKeypair(actor(3).keypair, {
          prove: () => Promise.reject(new Error("prove must not be called")),
          proveMerge: () => Promise.reject(new Error("proveMerge must not be called")),
        }),
        assets: new AssetRegistry(),
        tree: actor(8).address.solanaAddress(),
      }),
    ).rejects.toThrow("RING_TREE_MISMATCH");
  });

  it("derives from a caller-held nullifier key without taking it", () => {
    const owner = actor(3);
    const nullifierKey = owner.keypair.nullifierKey();
    const utxo = new Utxo({
      owner: owner.keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 5n,
      blinding: scalar(1),
    });
    const input = ProofInputUtxo.fromNullifierKey(utxo, nullifierKey);
    expect(input.nullifierPublicKey).toEqual(nullifierKey.publicKey());
    expect(input.nullifier()).toEqual(
      nullifierKey.nullifier(utxo.hash(nullifierKey.publicKey(), 0), utxo.blinding),
    );
    expect(Object.keys(input)).not.toContain("nullifierKey");
    // The key stays the caller's and keeps working.
    expect(nullifierKey.publicKey()).toEqual(owner.keypair.nullifierPublicKey());
  });

  it("derives non-payer owner signers like Rust `owner_signer_pubkeys`", () => {
    const owner = actor(3);
    const payer = actor(8).address.solanaAddress();
    const input = (blinding: number) =>
      ownedInput(owner, {
        owner: owner.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 5n,
        blinding: scalar(blinding),
      });
    const ownerAddress = owner.address.solanaAddress();
    expect(ownerSignerAddresses([input(1), input(2)], payer)).toEqual([ownerAddress]);
    expect(ownerSignerAddresses([input(1), input(2)], ownerAddress)).toEqual([]);
  });

  it("keeps a default UTXO's zero ring fields under the signing ring public input", async () => {
    const { proofInputs } = await auditedProofInputs(4n, X25519Secret.generate(), [], [], null);
    const input = proofInputs.inputUtxos[0];
    if (!input) throw new Error("input");
    const assembled = assemble(proofInputs, [spendProofFor(input)], [], {
      kind: "ring",
      ring: RING,
    });
    const slot = assembled.proverInputs.payload.inputs[0];
    if (!slot) throw new Error("input slot");
    expect(slot.circuit.ringProgramId).toBe(0n);
    expect(slot.circuit.ringDataHash).toBe(0n);
    const vector = assembled.proverInputs.payload.signerPublicKeyHashes;
    expect(vector.slice(1).every((entry) => entry === 0n)).toBe(true);
    expect(assembled.proverInputs.payload.ringProgramId).toBe(
      hashBytesBigInt(new Uint8Array(getAddressEncoder().encode(RING))),
    );
    proofInputs.outputs
      .filter((output) => !output.isDummy())
      .forEach((output) => expect(output.ringProgramId).toBe(RING));
  });
});

describe("ring audit", () => {
  it("matches the Go and Rust auditor stream vector", () => {
    const shared = new Uint8Array(32) as Bytes32;
    shared.set([1, 0x23, 0x45], 29);
    const ciphertext = symmetricAuditApply(shared, new Uint8Array(32));
    expect(Buffer.from(ciphertext).toString("hex")).toBe(
      "001d45a89ea12a64c7e6886ce543a66f77971b2c1052688ff668fe8c0c5d7c7b",
    );
    expect(symmetricAuditApply(shared, ciphertext)).toEqual(new Uint8Array(32));
  });
  it("opens every real slot with the recovered transaction key like Rust `TransactionAudit`", async () => {
    const auditor = X25519Secret.generate();
    const { proofInputs, recipient } = await auditedProofInputs(4n, auditor, [1n]);
    const transaction = indexed(proofInputs);
    const audited = auditRingTransaction({ auditor, transaction, assets: new AssetRegistry() });
    expect(audited.signature).toBe(transaction.txSignature);
    expect(audited.txViewingPublicKey.toBytes()).toEqual(
      proofInputs.externalData.txViewingPublicKey.toBytes(),
    );
    expect(audited.outputs.map((output) => [output.slotIndex, output.amount])).toEqual([
      [0, 5n],
      [1, 4n],
      [2, 1n],
    ]);
    expect(audited.outputs[1]?.recipientViewingPublicKey.toBytes()).toEqual(
      recipient.address.viewingPublicKey.toBytes(),
    );
    expect(audited.outputs.every((output) => output.ringProgramId === RING)).toBe(true);
    // Three real outputs fill the 1x4 shape; its padding slot carries random bytes.
    expect(audited.undecryptableSlots).toEqual([3]);
  });

  it("accepts the auditor message only as the unique last entry", async () => {
    const auditor = X25519Secret.generate();
    const { proofInputs } = await auditedProofInputs(4n, auditor);
    const transaction = indexed(proofInputs);
    const message = transaction.messages[0];
    if (!message) throw new Error("auditor message");
    const other = { viewTag: scalar(1), data: Uint8Array.of(9) };
    expect(() => auditorMessage({ ...transaction, messages: [] }, auditor.publicKey())).toThrow(
      "RING_AUDIT_MESSAGE",
    );
    expect(() =>
      auditorMessage({ ...transaction, messages: [message, message] }, auditor.publicKey()),
    ).toThrow("RING_AUDIT_MESSAGE");
    expect(() =>
      auditorMessage({ ...transaction, messages: [message, other] }, auditor.publicKey()),
    ).toThrow("RING_AUDIT_MESSAGE");
    expect(
      auditorMessage(
        { ...transaction, messages: [other, message] },
        auditor.publicKey(),
      ).ephemeralPublicKey.toBytes(),
    ).toEqual(parseAuditorMessage(message.data).ephemeralPublicKey.toBytes());
    expect(() =>
      auditRingTransaction({
        auditor,
        transaction: { ...transaction, txViewingPublicKey: ViewingKey.generate().publicKey() },
        assets: new AssetRegistry(),
      }),
    ).toThrow("RING_AUDIT_KEY_MISMATCH");
    expect(auditorViewTag(auditor.publicKey())).toEqual(message.viewTag);
  });

  it("resolves an SPL output through the registry and refuses an unknown id", async () => {
    const auditor = X25519Secret.generate();
    const mint = getAddressDecoder().decode(scalar(41));
    const registry = new AssetRegistry([[2n, mint]]);
    const { proofInputs } = await auditedProofInputs(4n, auditor, [], [], RING, mint, registry);
    const transaction = indexed(proofInputs);
    expect(() =>
      auditRingTransaction({ auditor, transaction, assets: new AssetRegistry() }),
    ).toThrow("TRANSACTION_UNKNOWN_ASSET");
    const audited = auditRingTransaction({ auditor, transaction, assets: registry });
    expect(audited.outputs.length).toBeGreaterThan(0);
    expect(audited.outputs.every((output) => output.asset === mint)).toBe(true);
  });

  it("refreshes the registry once from the chain on an unknown asset id", async () => {
    const auditor = X25519Secret.generate();
    const mint = getAddressDecoder().decode(scalar(41));
    const { proofInputs } = await auditedProofInputs(
      4n,
      auditor,
      [],
      [],
      RING,
      mint,
      new AssetRegistry([[2n, mint]]),
    );
    const transaction = indexed(proofInputs);
    const registryBytes = new Uint8Array(48);
    registryBytes[0] = StateDiscriminator.splAssetRegistry;
    registryBytes.set(new Uint8Array(getAddressEncoder().encode(mint)), 8);
    new DataView(registryBytes.buffer).setBigUint64(40, 2n, true);
    const getProgramAccounts = vi.fn(() => ({
      send: async () => [
        {
          account: {
            owner: SHIELDED_POOL_PROGRAM_ID,
            data: [Buffer.from(registryBytes).toString("base64"), "base64"],
          },
        },
      ],
    }));
    const client = ringAuditReader({
      getShieldedTransactionsByTags: async () =>
        transactionsPage({ transactions: [transaction, transaction] }),
      solanaRpc: { getProgramAccounts },
      commitment: "confirmed",
    });

    const assets = new AssetRegistry();
    const page = await auditRing({
      client,
      auditor,
      ringProgramId: RING,
      assets,
      origin: { ringInvoked: async () => true },
    });

    expect(page.transactions).toHaveLength(2);
    for (const audited of page.transactions) {
      expect(audited.outputs.length).toBeGreaterThan(0);
      expect(audited.outputs.every((output) => output.asset === mint)).toBe(true);
    }
    expect(getProgramAccounts).toHaveBeenCalledTimes(1);
    expect(assets.resolve(2n)).toBe(mint);
  });

  it("throws after one refresh when the chain does not know the id either", async () => {
    const auditor = X25519Secret.generate();
    const mint = getAddressDecoder().decode(scalar(41));
    const { proofInputs } = await auditedProofInputs(
      4n,
      auditor,
      [],
      [],
      RING,
      mint,
      new AssetRegistry([[2n, mint]]),
    );
    const transaction = indexed(proofInputs);
    const getProgramAccounts = vi.fn(() => ({ send: async () => [] }));
    const client = ringAuditReader({
      getShieldedTransactionsByTags: async () => transactionsPage({ transactions: [transaction] }),
      solanaRpc: { getProgramAccounts },
      commitment: "confirmed",
    });

    await expect(
      auditRing({
        client,
        auditor,
        ringProgramId: RING,
        assets: new AssetRegistry(),
        origin: { ringInvoked: async () => true },
      }),
    ).rejects.toThrow("TRANSACTION_UNKNOWN_ASSET");
    expect(getProgramAccounts).toHaveBeenCalledTimes(1);
  });

  it("opens only the clamped secret like Rust `an_unclamped_alias_of_the_published_key_is_refused`", () => {
    const auditor = X25519Secret.generate();
    const recover = (plaintext: Bytes32) => {
      const { ephemeralSecret, message } = encryptTransactionViewingSecret(
        plaintext,
        auditor.publicKey(),
      );
      try {
        return recoverTransactionViewingKey(auditor, message);
      } finally {
        ephemeralSecret.fill(0);
      }
    };
    const key = ViewingKey.fromBytes(new Uint8Array(32).fill(0x48) as Bytes32);
    const canonical = key.secretBytes();
    expect(recover(canonical).secretBytes()).toEqual(canonical);
    const lowBit = key.secretBytes();
    lowBit[0] = (lowBit[0] ?? 0) | 1;
    const highBit = key.secretBytes();
    highBit[31] = (highBit[31] ?? 0) | 0x80;
    for (const alias of [lowBit, highBit]) {
      expect(ViewingKey.fromBytes(alias).publicKey().toBytes()).toEqual(key.publicKey().toBytes());
      expect(() => recover(alias)).toThrow("RING_AUDIT_NONCANONICAL_KEY");
    }
    for (const unclamped of [
      new Uint8Array(32) as Bytes32,
      new Uint8Array(32).fill(0xff) as Bytes32,
    ]) {
      expect(() => recover(unclamped)).toThrow("RING_AUDIT_NONCANONICAL_KEY");
    }
  });
});

describe("ring proof folded fields", () => {
  it("folds the address chain and blinding of the SPP proof for any input count", async () => {
    const zero = new Uint8Array(32) as Bytes32;
    for (const inputs of [1, 2]) {
      const { prepared, sender } = preparedTransfer(4n, [], [], RING, SOL_MINT, undefined, {
        inputs,
        outputs: 2,
      });
      const proofInputs = await sealAudited(prepared, sender, X25519Secret.generate());
      expect(proofInputs.inputUtxos).toHaveLength(inputs);
      const addressChain = privateTxAddressChain(sppPrivateTxHashInput(proofInputs));
      expect(addressChain).toEqual(zero);
      expect(
        poseidon([
          nonZeroHashChain(
            proofInputs.inputUtxos.map((input) => (input.isDummy() ? zero : input.hash())),
          ),
          nonZeroHashChain(
            proofInputs.outputs.map((output) =>
              output.isDummy() ? zero : output.hash(proofInputs.outputTreeId),
            ),
          ),
          addressChain,
          proofInputs.privateTxBlinding(),
        ]),
      ).toEqual(proofInputs.privateTxHash());
    }
  });

  it("rejects excluded shapes and actual oversized transactions before either proof", async () => {
    const accounts = await ringAccounts(X25519Secret.generate(), true);
    const proveRingTransact = vi.fn(async () => ({
      data: ringInstructionData(scalar(91)),
      roots: SPP_ROOTS,
    }));
    const proveCustomRingPolicy = vi.fn(async () => new Uint8Array(192));
    const client = ringTransferClient({
      tree: ACTIVE_TREE,
      getAccount: accounts.getAccount,
      proveRingTransact,
      proveCustomRingPolicy,
    });
    const wide = preparedTransfer(4n, [], [], RING, SOL_MINT, undefined, { inputs: 1, outputs: 8 });
    await expect(
      proveCustomRingTransfer({
        client,
        ringProgramId: RING,
        prepared: wide.prepared,
        keys: walletKeys(wide.sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
      }),
    ).rejects.toMatchObject({ code: "RING_POLICY_SHAPE_UNSUPPORTED" });
    const normal = preparedTransfer(4n);
    await expect(
      proveCustomRingTransfer({
        client,
        ringProgramId: RING,
        prepared: normal.prepared,
        keys: walletKeys(normal.sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
        transaction: {
          setupInstructions: [
            { programAddress: actor(40).address.solanaAddress(), data: new Uint8Array(4000) },
          ],
        },
      }),
    ).rejects.toMatchObject({ code: "INTERFACE_TRANSACTION_TOO_LARGE" });
    const malformed = {
      client,
      ringProgramId: RING,
      prepared: normal.prepared,
      keys: walletKeys(normal.sender),
      assets: new AssetRegistry(),
      tree: ACTIVE_TREE,
    };
    Reflect.set(malformed, "transaction", null);
    await expect(proveCustomRingTransfer(malformed)).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
    });
    expect(proveRingTransact).not.toHaveBeenCalled();
    expect(proveCustomRingPolicy).not.toHaveBeenCalled();
  });

  it.each([1, 2])(
    "selects the legacy 2×3 key only for two published inputs, got %i",
    async (publishedInputs) => {
      const base = preparedTransfer(4n, [1n]);
      const spends = [...base.prepared.inputs];
      if (publishedInputs === 2)
        spends.push(
          ownedInput(base.sender, {
            owner: base.sender.keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 10n,
            blinding: scalar(77),
            ringProgramId: RING,
          }),
        );
      const transfer = ConfidentialTransfer.compact(
        base.sender.address,
        spends,
        base.prepared.payer,
      )
        .withRingProgramId(RING)
        .withShape({ inputs: 2, outputs: 4 });
      transfer.send(base.recipient.address, SOL_MINT, 4n);
      transfer.send(actor(5).address, SOL_MINT, 1n);
      const accounts = await ringAccounts(X25519Secret.generate(), true);
      let captured: CustomRingPolicyProofRequest | undefined;
      const client = ringTransferClient({
        tree: ACTIVE_TREE,
        getAccount: accounts.getAccount,
        proveRingTransact: async () => ({
          data: ringInstructionData(scalar(91)),
          roots: SPP_ROOTS,
        }),
        proveCustomRingPolicy: async (request) => {
          captured = request;
          return new Uint8Array(192);
        },
      });
      const proven = await proveCustomRingTransfer({
        client,
        ringProgramId: RING,
        prepared: transfer.prepare(),
        keys: walletKeys(base.sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
      });
      expect(captured?.nIn).toBe(2);
      expect(captured?.nOut).toBe(3);
      expect(captured?.twoByThree).toBe(publishedInputs === 2);
      expect(proven.twoByThree).toBe(publishedInputs === 2);
      expect(captured?.inputs).toHaveLength(publishedInputs === 2 ? 5 : 2);
      expect(captured?.subjects).toHaveLength(publishedInputs === 2 ? 13 : 10);
      expect(captured?.shape).toEqual(
        publishedInputs === 2 ? undefined : { inputs: 2, outputs: 4 },
      );
    },
  );

  it("builds capacity-sized witnesses for every supported ordinary shape", async () => {
    const accounts = await ringAccounts(X25519Secret.generate(), true);
    for (const shape of RING_POLICY_SUPPORTED_SHAPES) {
      const transfer = preparedTransfer(4n, [], [], RING, SOL_MINT, undefined, shape);
      let captured: CustomRingPolicyProofRequest | undefined;
      const client = ringTransferClient({
        tree: ACTIVE_TREE,
        getAccount: accounts.getAccount,
        proveRingTransact: async () => ({
          data: ringInstructionData(scalar(91)),
          roots: SPP_ROOTS,
        }),
        proveCustomRingPolicy: async (request) => {
          captured = request;
          return new Uint8Array(192);
        },
      });
      const proven = await proveCustomRingTransfer({
        client,
        ringProgramId: RING,
        prepared: transfer.prepared,
        keys: walletKeys(transfer.sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
      });
      expect(captured?.shape).toEqual(shape);
      expect(captured?.inputs).toHaveLength(shape.inputs);
      expect(captured?.outputs).toHaveLength(shape.outputs);
      expect(captured?.subjects).toHaveLength(shape.inputs + 2 * shape.outputs);
      expect(proven.policyShape).toBe("subtree");
    }
  });

  it("sends the zero address chain to the custom prover", async () => {
    const { prepared, sender } = preparedTransfer(4n, [1n]);
    const accounts = await ringAccounts(X25519Secret.generate(), true);
    const txHash = scalar(91);
    const data = ringInstructionData(txHash);
    let finalized: SppProofInputs | undefined;
    const proveRingTransact = vi.fn(async (proofInputs: SppProofInputs) => {
      finalized = proofInputs;
      return { data, roots: SPP_ROOTS };
    });
    let request: CustomRingPolicyProofRequest | undefined;
    const proveCustomRingPolicy = vi.fn(async (input: CustomRingPolicyProofRequest) => {
      request = input;
      return new Uint8Array(192);
    });
    const base = {
      client: ringTransferClient({
        tree: ACTIVE_TREE,
        getAccount: accounts.getAccount,
        proveRingTransact,
        proveCustomRingPolicy,
      }),
      ringProgramId: RING,
      prepared,
      keys: walletKeys(sender),
      assets: new AssetRegistry(),
      tree: ACTIVE_TREE,
      outputTree: ACTIVE_TREE,
    } as const;
    // An empty table reads both roots from the address tree head.
    const proven = await proveCustomRingTransfer(base);
    const entriesStateRoot = new Uint8Array(32).fill(0x17);
    const entriesNullifierRoot = new Uint8Array(32).fill(0x23);

    expect(finalized).toBeDefined();
    expect(request).toBeDefined();
    expect(request?.addressChain).toEqual(new Uint8Array(32));
    expect(request?.privateTxHash).toEqual(txHash);
    expect(request?.treeSlots).toEqual([
      { id: 0, utxoRoot: entriesStateRoot, nullifierRoot: entriesNullifierRoot },
    ]);
    expect(request?.addressTreeId).toBe(0);
    expect(request?.memberRegistryRoot).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
    expect(proven.policy).toMatchObject({
      trees: [ACTIVE_TREE],
      treeContexts: [{ utxoTreeRootIndex: 7, nullifierTreeRootIndex: 3 }],
    });
    expect(proven.policy?.memberRegistryRootIndex).toBe(1);
    expect(proven.policy?.memberRegistryRoot).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
    expect(proven.inputTrees).toEqual([ACTIVE_TREE]);
    expect(proven.outputTree).toBe(ACTIVE_TREE);
    expect(proven.ownerSigners).toEqual([]);
  });

  const requireAllow: Rule = {
    subject: "outputOwner",
    source: { kind: "lists", present: [ListId.allow], absent: [] },
    guard: { kind: "always" },
  };

  it.each([
    { proofDataSource: "client", lag: false },
    { proofDataSource: "prover", lag: false },
    { proofDataSource: "prover", lag: true },
  ] as const)(
    "resolves policy answers with $proofDataSource proof data and lag=$lag",
    async ({ proofDataSource, lag }) => {
      const { prepared, sender, recipient } = preparedTransfer(4n, [1n]);
      const registry = registryFixture(
        [sender, recipient, actor(5)].map((party) => ({
          member: memberOfTag(party.address.confidentialViewTag()),
          lists: 1n << BigInt(ListId.allow - 1),
        })),
      );
      const accounts = await ringAccounts(X25519Secret.generate(), true, [requireAllow]);
      const [rootAddress, rootBump] = await ringMemberRegistryRootPda(RING);
      const order: string[] = [];
      const getRingMemberRecord = vi.fn(async (input: { member: Bytes32 }) => {
        order.push("member");
        return registry.read(input.member);
      });
      const proveRingTransact = vi.fn(async () => {
        order.push("spp");
        return { data: ringInstructionData(scalar(91)), roots: SPP_ROOTS };
      });
      let request: CustomRingPolicyProofRequest | undefined;
      const proveCustomRingPolicy = vi.fn(async (input: CustomRingPolicyProofRequest) => {
        request = input;
        return new Uint8Array(192);
      });
      let policyCalls = 0;
      const proven = await proveCustomRingTransfer({
        client: ringTransferClient({
          tree: ACTIVE_TREE,
          getAccount: async (address) =>
            address === rootAddress
              ? ownedAccount(RING, memberRegistryRootData({ ...registry.tip, bump: rootBump }))
              : accounts.getAccount(address),
          getRingMemberRecord,
          proveRingTransact,
          proveCustomRingPolicy,
          proofDataSource,
          proveIndexedRingPolicy: async (indexed) => {
            policyCalls++;
            if (lag && policyCalls === 1)
              throw new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
            request = indexed.policy;
            expect(indexed.registry.root).toEqual(registry.root);
            return {
              proof: new Uint8Array(192),
              resolution: {
                trees: indexed.trees.map((tree) => ({
                  ...tree,
                  utxoRootIndex: 12,
                  nullifierRootIndex: 4,
                })),
                publicInputHash: scalar(91),
              },
            };
          },
        }),
        ringProgramId: RING,
        prepared,
        keys: walletKeys(sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
        outputTree: ACTIVE_TREE,
      });
      expect(order.at(-1)).toBe("spp");
      if (proofDataSource === "client")
        expect(request?.subjects?.filter((subject) => subject?.present)).toHaveLength(4);
      expect(request?.treeSlots).toEqual([
        {
          id: 0,
          utxoRoot: new Uint8Array(32).fill(0x17),
          nullifierRoot: new Uint8Array(32).fill(0x23),
        },
      ]);
      expect(proven.policy?.treeContexts).toEqual([
        {
          utxoTreeRootIndex: proofDataSource === "prover" ? 12 : 7,
          nullifierTreeRootIndex: proofDataSource === "prover" ? 4 : 3,
        },
      ]);
      expect(proven.policy?.memberRegistryRootIndex).toBe(0);
      expect(getRingMemberRecord).toHaveBeenCalledTimes(proofDataSource === "prover" ? 0 : 3);
      expect(proveCustomRingPolicy).toHaveBeenCalledTimes(proofDataSource === "prover" ? 0 : 1);
      expect(proveRingTransact).toHaveBeenCalledTimes(lag ? 2 : 1);
      // The account rows travel verbatim.
      const policy = accounts.policy;
      expect(request?.policyLen).toBe(1);
      expect(request?.rules.slice(0, 1)).toEqual(policy.rules);
      expect(request?.rules.slice(1).every((row) => row.every((byte) => byte === 0))).toBe(true);
      expect(request?.inlineCount).toBe(0);
      expect(request?.sources.map((slot) => slot.listId)).toEqual([
        ListId.allow,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
      ]);
    },
  );

  it("names only an output owner the prover finds no escrowed key for", async () => {
    const { prepared, sender, recipient } = preparedTransfer(4n, [1n]);
    const accounts = await ringAccounts(
      X25519Secret.generate(),
      true,
      [requireAllow],
      false,
      MEMBER_REGISTRY_EMPTY_ROOT,
    );
    const owner = Buffer.from(recipient.address.signingPublicKey.ownerProofInputHash()).toString(
      "hex",
    );
    for (const member of [owner, "2a".repeat(32)]) {
      const refused = new ClientError("CLIENT_MEMBER_REGISTRY_MEMBER_UNREGISTERED", {
        details: { method: "prove", member },
      });
      const proving = proveCustomRingTransfer({
        client: ringTransferClient({
          tree: ACTIVE_TREE,
          getAccount: accounts.getAccount,
          proveRingTransact: async () => ({
            data: ringInstructionData(scalar(91)),
            roots: SPP_ROOTS,
          }),
          proofDataSource: "prover",
          proveIndexedRingPolicy: async () => {
            throw refused;
          },
        }),
        ringProgramId: RING,
        prepared,
        keys: walletKeys(sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
        outputTree: ACTIVE_TREE,
      });
      if (member === owner)
        await expect(proving).rejects.toMatchObject({
          code: "RING_UNREGISTERED_OUTPUT_KEY",
          details: { owner },
        });
      else await expect(proving).rejects.toBe(refused);
    }
  });

  it("refuses a transfer no entry admits before any prover call", async () => {
    const { prepared, sender } = preparedTransfer(4n, [1n]);
    const accounts = await ringAccounts(X25519Secret.generate(), true, [requireAllow]);
    const reads = entryProofReads({ tree: ACTIVE_TREE });
    const proveRingTransact = vi.fn(async () => ({
      data: ringInstructionData(scalar(91)),
      roots: SPP_ROOTS,
    }));
    await expect(
      proveCustomRingTransfer({
        client: ringTransferClient({
          tree: ACTIVE_TREE,
          getAccount: accounts.getAccount,
          proveRingTransact,
          getRingMemberRecord: async () => ({ ...emptyMemberRecord(), rootIndex: 1 }),
        }),
        ringProgramId: RING,
        prepared,
        keys: walletKeys(sender),
        assets: new AssetRegistry(),
        tree: ACTIVE_TREE,
        outputTree: ACTIVE_TREE,
      }),
    ).rejects.toMatchObject({ code: "RING_POLICY_RULE_UNSATISFIED", details: { ruleIndex: 0 } });
    expect(proveRingTransact).not.toHaveBeenCalled();
    expect(reads.getMerkleProofs).not.toHaveBeenCalled();
    expect(reads.getNonInclusionProofs).not.toHaveBeenCalled();
  });

  it("proves the audit statement alone for a no-policy ring like Rust `finish_audit`", async () => {
    const { prepared, sender } = preparedTransfer(4n, [1n]);
    const auditor = X25519Secret.generate();
    const accounts = await ringAccounts(auditor, false);
    const txHash = scalar(91);
    const data = ringInstructionData(txHash);
    let finalized: SppProofInputs | undefined;
    let request: CustomRingBaseProofRequest | undefined;

    const proven = await proveCustomRingTransfer({
      client: ringTransferClient({
        tree: ACTIVE_TREE,
        getAccount: accounts.getAccount,
        proveRingTransact: async (proofInputs) => {
          finalized = proofInputs;
          return { data, roots: SPP_ROOTS };
        },
        proveCustomRingBase: async (input) => {
          request = input;
          return new Uint8Array(192);
        },
      }),
      ringProgramId: RING,
      prepared,
      keys: walletKeys(sender),
      assets: new AssetRegistry(),
      tree: ACTIVE_TREE,
      outputTree: ACTIVE_TREE,
    });

    if (finalized === undefined) throw new Error("finalized");
    const finalizedInputs = finalized;
    const message = finalizedInputs.externalData.messages[0];
    if (message === undefined) throw new Error("auditor message");
    // The policy config account is never read for an audit-only ring.
    expect(accounts.read).not.toContain(accounts.policyAddress);
    expect(request?.privateTxHash).toEqual(txHash);
    expect(request?.auditorPublicKey).toEqual(auditor.publicKey().u());
    expect(request?.publicInputHash).toEqual(
      auditPublicInputHash({
        privateTxHash: txHash,
        txViewingPublicKey: finalizedInputs.externalData.txViewingPublicKey,
        auditorPublicKey: auditor.publicKey(),
        message: parseAuditorMessage(message.data),
        outputHashes: finalizedInputs.outputs.map((output) =>
          output.hash(finalizedInputs.outputTreeId),
        ),
        salt: finalizedInputs.externalData.salt,
      }),
    );
    expect(proven).not.toHaveProperty("policy");
    expect(proven.inputTrees).toEqual([ACTIVE_TREE]);
    expect(proven.outputTree).toBe(ACTIVE_TREE);
  });
});
