import { bn254 } from "@noble/curves/bn254.js";
import {
  AccountRole,
  getAddressDecoder,
  signature,
  type Address,
  type Instruction,
} from "@solana/kit";
import { expect } from "vitest";

import type {
  AnonymousRingTransactProofInput,
  ChainReader,
  ProofAuthority,
  ProofService,
  ProvenRingTransact,
  RingMemberOpenings,
  RingRecordReader,
} from "../../src/client/ports.js";
import { prepareTransfer } from "../../src/client/prover/assembly.js";
import type { RingProofRequest } from "../../src/client/prover/ring.js";
import type {
  AnonymousEddsaAuthorization,
  TransferCircuit,
} from "../../src/client/prover/types.js";
import type {
  GetByTagsRequest,
  GetMerkleProofsResponse,
  RpcAccount,
} from "../../src/client/rpc.js";
import { LocalKeys } from "../../src/client/keys.js";
import { encodeTransactInstructionData } from "../../src/interface/codecs/index.js";
import { SYSTEM_PROGRAM } from "../../src/interface/instructions/index.js";
import { addressBytes, encodeBase58 } from "../../src/interface/internal.js";
import {
  nullifierPdaAddress,
  ringAuthAddress,
  ringConfigAddress,
  ringConfigPda,
  ringMemberRegistryPda,
  treeAddress,
} from "../../src/interface/pda/index.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../../src/interface/program.js";
import { UTXO_ROOT_HISTORY_OFFSET } from "../../src/interface/state.js";
import { DEFAULT_TREE_ID } from "../../src/interface/tree-slot.js";
import { TRANSACTION_SIZE_LIMIT } from "../../src/interface/transaction-size.js";
import type { Bytes16, Bytes32, Bytes128, TransactProof } from "../../src/interface/types.js";
import { openTransactionViewingSecret } from "../../src/keypair/audit.js";
import { checkedBytes, randomBlinding } from "../../src/keypair/bytes.js";
import { openRingDisclosure, type RingDisclosure } from "../../src/keypair/ring-disclosure.js";
import { ringIdField, ringTagField } from "../../src/keypair/ring-stream.js";
import type { ShieldedAddress, ShieldedKeypair } from "../../src/keypair/shielded.js";
import { ringOutputBlinding } from "../../src/keypair/transact/index.js";
import { ViewingKey } from "../../src/keypair/viewing-key.js";
import { X25519Keypair, X25519PublicKey } from "../../src/keypair/x25519.js";
import { checkTransactionFits } from "../../src/flows/compile.js";
import { RingInstructionTag, ringComputeUnitLimit } from "../../src/ring/admin.js";
import type { RingCoSigner, RingMode, RingSourceSlot } from "../../src/ring/codecs.js";
import type { ProvenRingTransfer, RingTransactionFrame } from "../../src/ring/pipeline.js";
import type { RingTransferApproval } from "../../src/ring/rails.js";
import {
  LIST_IDS,
  policySourceOwners,
  policyTableHash,
  referencedLists,
  type ListId,
  type RuleTable,
} from "../../src/ring/policy.js";
import { auditStatementHash, ringAuditStatement } from "../../src/ring/statement.js";
import { RingTransactData, type RingRail } from "../../src/ring/transact.js";
import { SOL_MINT } from "../../src/transaction/asset.js";
import {
  assetField,
  settlementAccounts,
  type SppProofInputs,
} from "../../src/transaction/instructions/transact.js";
import { decodeRingPacked, readOutputData } from "../../src/transaction/serialization/codecs.js";
import { openRingDelivery } from "../../src/transaction/serialization/ring-delivered.js";
import { ProofInputUtxo, Utxo } from "../../src/transaction/utxo.js";
import type { RingKeys, RingRecipientKey } from "../../src/transaction/wallet/keys.js";

import { matchesPage, transactionsPage } from "./clients.js";
import { stateTreeAt, type StateTree } from "./state-tree.js";
import { recordTree, type FixtureRecord } from "./member-registry.js";
import { treeAccount } from "./tree-account.js";
import {
  memberRegistryData,
  ownedAccount,
  ringProgramConfigData,
  sppRingRegistration,
} from "./ring-accounts.js";

export const TREE_ID = DEFAULT_TREE_ID;
export const TREE = treeAddress(TREE_ID);
const addressDecoder = getAddressDecoder();

export function randomAddress(): Address {
  return addressDecoder.decode(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

export function filled(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

/** A field element below every modulus, `value` in the last byte. */
export function small(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

export function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function itemAt<T>(values: readonly T[], index: number): T {
  const value = values[index];
  if (value === undefined) throw new Error(`no item at ${String(index)}`);
  return value;
}

/** Matches a `RingError` or `WalletError` by code and, when given, by details. */
export function ringError(code: string, details?: Readonly<Record<string, unknown>>): unknown {
  return expect.objectContaining(
    details === undefined ? { code } : { code, details: expect.objectContaining(details) },
  );
}

/** A ring and the curator ring a source of it may name, as the chain and Photon hold them. */
export interface RingFixtureOptions {
  readonly mode?: RingMode;
  readonly table?: RuleTable;
  readonly records?: readonly FixtureRecord[];
  readonly coSigner?: RingCoSigner;
  readonly delegate?: Address;
  /** The lists a second ring's registry serves. */
  readonly curator?: Readonly<{ lists: readonly ListId[]; records: readonly FixtureRecord[] }>;
  readonly slot?: bigint;
  readonly registration?: Readonly<{ activated: boolean; paused: boolean }>;
}

export interface SppCall {
  readonly proofInputs: SppProofInputs;
  readonly circuit: TransferCircuit;
  readonly authority: ProofAuthority;
  readonly payload: ReturnType<typeof prepareTransfer>["inputs"]["payload"];
  /** Present exactly on the anonymous rail. */
  readonly authorization?: AnonymousEddsaAuthorization;
  readonly data: ProvenRingTransact["data"];
}

/** The root history slot every anchor tree holds its root in. */
export const ANCHOR_ROOT_INDEX = 3;

/** An SPP tree whose UTXO root history holds `root` at `ANCHOR_ROOT_INDEX`. */
export function anchorTreeAccount(root: Bytes32): RpcAccount {
  const data = treeAccount({
    stateCursor: ANCHOR_ROOT_INDEX,
    written: ANCHOR_ROOT_INDEX + 1,
    nullifierCursor: 0n,
  });
  data.set(root, UTXO_ROOT_HISTORY_OFFSET + ANCHOR_ROOT_INDEX * 32);
  return ownedAccount(SHIELDED_POOL_PROGRAM_ID, data);
}

/** A ring the chain, Photon and the prover serve from memory, every proof request recorded. */
export async function ringFixture(options: RingFixtureOptions = {}) {
  const ringProgramId = randomAddress();
  const auditor = X25519Keypair.generate();
  const authority = randomAddress();
  const accounts = new Map<Address, RpcAccount>();
  const trees = new Map<Address, ReturnType<typeof recordTree>>();
  const ownTree = recordTree(options.records ?? []);
  trees.set(ringProgramId, ownTree);
  const hasPolicy = options.table !== undefined;
  const [configAddress, configBump] = await ringConfigPda(ringProgramId);
  accounts.set(
    configAddress,
    ownedAccount(
      ringProgramId,
      ringProgramConfigData({
        authority,
        auditorPublicKey: auditor.publicKey().toBytes(),
        bump: configBump,
        hasPolicy,
        mode: options.mode ?? "off",
        ...(options.coSigner === undefined ? {} : { coSigner: options.coSigner }),
        ...(options.delegate === undefined ? {} : { delegate: options.delegate }),
      }),
    ),
  );
  const [ringAuth, registration] = await sppRingRegistration({
    authority,
    ringProgramId,
    ...options.registration,
  });
  accounts.set(ringAuth, registration);
  let curatorRing: Address | undefined;
  let curatorRegistry: Address | undefined;
  let curatorTree: ReturnType<typeof recordTree> | undefined;
  if (options.curator !== undefined) {
    curatorRing = randomAddress();
    const tree = recordTree(options.curator.records);
    curatorTree = tree;
    trees.set(curatorRing, tree);
    const [address, bump] = await ringMemberRegistryPda(curatorRing);
    curatorRegistry = address;
    accounts.set(
      address,
      ownedAccount(
        curatorRing,
        memberRegistryData({
          bump,
          history: [{ root: tree.root, applied: 0n, slot: 0n }],
          nextIndex: tree.nextIndex,
        }),
      ),
    );
  }
  if (options.table !== undefined) {
    const referenced = referencedLists(options.table.rules);
    const shared = options.curator?.lists ?? [];
    const sources: RingSourceSlot[] = LIST_IDS.map((listId) =>
      referenced.includes(listId)
        ? {
            listId,
            registry:
              shared.includes(listId) && curatorRegistry !== undefined
                ? curatorRegistry
                : ZERO_ADDRESS,
          }
        : { listId: 0, registry: ZERO_ADDRESS },
    );
    const [address, bump] = await ringMemberRegistryPda(ringProgramId);
    accounts.set(
      address,
      ownedAccount(
        ringProgramId,
        memberRegistryData({
          bump,
          history: [{ root: ownTree.root, applied: 0n, slot: 0n }],
          nextIndex: ownTree.nextIndex,
          policyHash: policyTableHash(options.table, policySourceOwners(sources)),
          sources,
          table: options.table,
          generation: 1,
        }),
      ),
    );
  }
  const slot = options.slot ?? 1n;
  const context = Object.freeze({ slot, blockTime: 0n });
  const ringRequests: RingProofRequest[] = [];
  const sppCalls: SppCall[] = [];
  // Hex of every view tag an earlier transaction published.
  const publishedTags = new Set<string>();
  const leaves = new Map<string, bigint>();
  const placed = new Map<Address, Map<number, Uint8Array>>();
  const anchorAccounts = new Map<Address, RpcAccount>();
  const anchorTree = (tree: Address): StateTree => stateTreeAt(placed.get(tree) ?? new Map());
  const merkleRequests: Readonly<{ tree: Address; leaves: readonly Bytes32[] }>[] = [];
  let proofs = 0;
  const reader: Pick<ChainReader, "getAccount"> & Pick<RingRecordReader, "getRingMemberOpenings"> =
    {
      getAccount: async (address) => accounts.get(address),
      getRingMemberOpenings: async (request): Promise<RingMemberOpenings> => {
        const tree = trees.get(request.ringProgramId);
        if (tree === undefined || hex(tree.root) !== hex(request.expectedRoot))
          throw new Error("openings under an unknown root");
        return {
          context,
          root: { root: tree.root, rootIndex: 0, applied: 0n, nextIndex: tree.nextIndex },
          openings: request.members.map((member) => tree.opening(member)),
        };
      },
    };
  const spp = (
    proofInputs: SppProofInputs,
    circuit: TransferCircuit,
    authority: ProofAuthority,
  ): ProvenRingTransact => {
    const prepared = prepareTransfer(proofInputs, circuit);
    const complete = prepared.finish(
      proofInputs.inputTreeIds().map((treeId, index) => ({
        treeId,
        slot: { id: treeId, utxoRoot: small(0x31 + index), nullifierRoot: small(0x41 + index) },
        utxoRootIndex: 7 + index,
        nullifierRootIndex: 9 + index,
      })),
    );
    const data = complete.withProof(
      SPP_PROOF,
      circuit.kind === "ringAnonymous"
        ? { commitment: filled(0x51), commitmentPok: filled(0x52) }
        : undefined,
    );
    sppCalls.push({
      proofInputs,
      circuit,
      authority,
      payload: prepared.inputs.payload,
      ...(prepared.inputs.circuit === "transferEddsaRing"
        ? { authorization: prepared.inputs.authorization }
        : {}),
      data,
    });
    return { data, roots: complete.roots };
  };
  const client = {
    tree: TREE,
    treeId: TREE_ID,
    ...reader,
    getSlot: async () => slot,
    proveRing: async (request: RingProofRequest): Promise<Uint8Array> => {
      ringRequests.push(structuredClone(request));
      proofs += 1;
      return new Uint8Array(192).fill(proofs);
    },
    proveRingTransact: async (proofInputs: SppProofInputs, ring: Address, keys: ProofAuthority) =>
      spp(proofInputs, { kind: "ring", ring }, keys),
    proveRingAuthorityTransact: async (
      proofInputs: SppProofInputs,
      ring: Address,
      keys: ProofAuthority,
    ) => spp(proofInputs, { kind: "ringAuthority", ring }, keys),
    proveAnonymousRingTransact: async (input: AnonymousRingTransactProofInput) =>
      spp(
        input.proofInputs,
        {
          kind: "ringAnonymous",
          ring: input.ringProgramId,
          owner: input.owner,
          ...(input.cosigner === undefined ? {} : { cosigner: input.cosigner }),
          ...(input.exitTokenOwner === undefined ? {} : { exitTokenOwner: input.exitTokenOwner }),
        },
        input.keys,
      ),
    getShieldedTransactionsByTags: async (request: GetByTagsRequest) => {
      const outputSlots = request.tags
        .filter((tag) => publishedTags.has(hex(tag)))
        .map((tag, leafIndex) => ({
          viewTag: tag,
          outputContext: { hash: tag, tree: TREE, treeId: TREE_ID, leafIndex: BigInt(leafIndex) },
          payload: new Uint8Array(),
        }));
      return transactionsPage(
        outputSlots.length === 0
          ? {}
          : {
              transactions: [
                {
                  slot,
                  txSignature: PUBLISHED_SIGNATURE,
                  outputSlots,
                  messages: [],
                  nullifiers: [],
                  proofless: false,
                },
              ],
            },
      );
    },
    getShieldedTransactionsByNullifiers: async () => transactionsPage(),
    getEncryptedUtxosByTags: async () => matchesPage(),
    getMerkleProofs: async (
      tree: Address,
      requested: readonly Bytes32[],
    ): Promise<GetMerkleProofsResponse> => {
      merkleRequests.push({ tree, leaves: [...requested] });
      const state = anchorTree(tree);
      return {
        context,
        proofs: requested.map((leaf) => {
          const leafIndex = leaves.get(`${tree}:${hex(leaf)}`);
          if (leafIndex === undefined) throw new Error("no path for a leaf the tree never held");
          return {
            leaf,
            merkleContext: { treeType: 3, tree },
            path: state.path(Number(leafIndex)),
            leafIndex,
            root: state.root,
            rootSeq: slot,
            rootIndex: ANCHOR_ROOT_INDEX,
          };
        }),
      };
    },
  };
  return {
    ringProgramId,
    auditor,
    authority,
    /** Registry mode escrows every output nullifier key. */
    keyEscrow: options.mode === "registry",
    accounts,
    client,
    ringRequests,
    sppCalls,
    merkleRequests,
    ownTree,
    /** The tag streams find these anonymous tags used. */
    publishTags(tags: readonly Bytes16[]): void {
      for (const tag of tags) publishedTags.add(hex(ringTagField(tag)));
    },
    /** Photon serves a path for `hash` at `leafIndex` of `tree`, the tree holds its root unless a test replaced it. */
    placeLeaf(tree: Address, hash: Bytes32, leafIndex: bigint): void {
      leaves.set(`${tree}:${hex(hash)}`, leafIndex);
      const held = placed.get(tree) ?? new Map<number, Uint8Array>();
      placed.set(tree, held.set(Number(leafIndex), hash));
      if (accounts.has(tree) && accounts.get(tree) !== anchorAccounts.get(tree)) return;
      const account = anchorTreeAccount(anchorTree(tree).root);
      accounts.set(tree, account);
      anchorAccounts.set(tree, account);
    },
    anchorTree,
    ...(curatorRing === undefined ? {} : { curatorRing }),
    ...(curatorRegistry === undefined ? {} : { curatorRegistry }),
    ...(curatorTree === undefined ? {} : { curatorTree }),
  };
}

export type Fixture = Awaited<ReturnType<typeof ringFixture>>;

const PUBLISHED_SIGNATURE = signature("1".repeat(64));

/** Never consulted, every proof here is a stub. */
export const PROOF_SERVICE: ProofService = {
  prove: async () => {
    throw new Error("unused proof service");
  },
  proveMerge: async () => {
    throw new Error("unused proof service");
  },
  proveRing: async () => {
    throw new Error("unused proof service");
  },
};

export function walletKeys(keypair: ShieldedKeypair): LocalKeys {
  return LocalKeys.fromKeypair(keypair, PROOF_SERVICE);
}

/** A spendable note of `keypair` in `ring`, or in the default ring without one. */
export function noteInput(
  keypair: ShieldedKeypair,
  amount: bigint,
  ring?: Address,
  asset: Address = SOL_MINT,
): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset,
      amount,
      blinding: randomBlinding(),
      ...(ring === undefined ? {} : { ringProgramId: ring }),
    }),
    keypair,
    {},
    TREE_ID,
  );
}

/** The BN254 G2 generator, the SPP proof `b` the stub proves with must lie on the curve. */
const G2 = bn254.G2.Point.BASE.toAffine();
export const SPP_PROOF: TransactProof = Object.freeze({
  a: filled(0x0a),
  b: checkedBytes<Bytes128>(
    Uint8Array.from(
      [G2.x.c1, G2.x.c0, G2.y.c1, G2.y.c0].flatMap((value) =>
        Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex")),
      ),
    ),
    128,
    "b",
  ),
  c: filled(0x0c),
});

export const ZERO_ADDRESS = encodeBase58(new Uint8Array(32));

/** The instruction parses back to its data, and the program's expansion reproduces what SPP proved. */
export async function expanded(
  fixture: Fixture,
  proven: ProvenRingTransfer,
  rail: RingRail,
  coSigner?: Address,
) {
  const instruction = await proven.instruction();
  expect(instruction.data?.[0]).toBe(
    rail === "delegate" ? RingInstructionTag.delegateTransact : RingInstructionTag.transact,
  );
  const bytes = instruction.data?.subarray(1) ?? new Uint8Array();
  const data = RingTransactData.parse(bytes, rail);
  expect(hex(RingTransactData.encode(data))).toBe(hex(bytes));
  const call = fixture.sppCalls.at(-1);
  if (call === undefined) throw new Error("no SPP proof");
  const config = {
    auditorPubkey: fixture.auditor.publicKey().toBytes(),
    coSigner: checkedBytes<Bytes32>(
      coSigner === undefined ? new Uint8Array(32) : addressBytes(coSigner),
      32,
      "coSigner",
    ),
  };
  expect(hex(encodeTransactInstructionData(RingTransactData.expand(data, config)))).toBe(
    hex(encodeTransactInstructionData(call.data)),
  );
  expect(
    RingTransactData.externalDataHash(
      data,
      config,
      call.proofInputs.externalData.interfaceTransfers.map(settlementAccounts),
    ),
  ).toEqual(call.proofInputs.externalData.hash());
  return { instruction, data, call };
}

type AccountEntry = Readonly<{ address: Address; role: AccountRole }>;

/**
 * Rust `TransactAccounts::instruction`, the ring prefix then SPP's own list, every transfer here
 * spending from and landing in `TREE`.
 */
export async function checkAccounts(
  instruction: Instruction,
  expected: Readonly<{
    fixture: Fixture;
    data: RingTransactData;
    /** After the config, the registry, curator, co-signer, delegate and anchor tree in order. */
    prefix: readonly AccountEntry[];
    payer: Address;
    ownerSigners?: readonly Address[];
    settlement?: readonly AccountEntry[];
  }>,
): Promise<void> {
  const { fixture } = expected;
  const readonly = (address: Address): AccountEntry => ({ address, role: AccountRole.READONLY });
  const writable = (address: Address): AccountEntry => ({ address, role: AccountRole.WRITABLE });
  const nullifiers = await Promise.all(
    expected.data.nullifiers.map((nullifier) => nullifierPdaAddress(TREE, nullifier)),
  );
  expect(
    instruction.accounts?.map((account) => ({ address: account.address, role: account.role })),
  ).toEqual([
    readonly(await ringConfigAddress(fixture.ringProgramId)),
    ...expected.prefix,
    { address: expected.payer, role: AccountRole.WRITABLE_SIGNER },
    writable(TREE),
    readonly(SHIELDED_POOL_PROGRAM_ID),
    readonly(SYSTEM_PROGRAM),
    readonly(await ringAuthAddress(fixture.ringProgramId)),
    writable(TREE),
    ...nullifiers.map(writable),
    ...(expected.ownerSigners ?? []).map((address) => ({
      address,
      role: AccountRole.READONLY_SIGNER,
    })),
    ...(expected.settlement ?? []),
  ]);
}

/** Every ring output's blinding is the TXRB of the ring secret SPP proves it under, every other slot has none. */
export function checkRingSecrets(call: SppCall, data: RingTransactData): void {
  const firstNullifier = RingTransactData.firstNullifier(data);
  call.proofInputs.outputs.forEach((output, slotIndex) => {
    const proven = call.payload.ringSecrets[slotIndex];
    expect(output.ringSecret !== undefined).toBe(
      !output.isDummy() && output.ringProgramId !== undefined,
    );
    if (output.ringSecret === undefined) {
      expect(proven).toBe(0n);
      return;
    }
    expect(proven).toBe(BigInt(`0x${hex(output.ringSecret)}`));
    expect(output.blinding).toEqual(
      ringOutputBlinding({ firstNullifier, ringSecret: output.ringSecret, outputIndex: slotIndex }),
    );
  });
}

/** The audit request proves the statement the program rebuilds from the parsed data. */
export function checkAudit(
  fixture: Fixture,
  data: RingTransactData,
  binding: Readonly<{ kind: RingProofRequest["kind"]; epoch?: bigint; firstContactRoot?: Bytes32 }>,
): void {
  const audit = fixture.ringRequests.find((request) => request.kind.endsWith("Audit"));
  expect(audit?.kind).toBe(binding.kind);
  expect(audit?.publicInputHash).toEqual(
    auditStatementHash(
      ringAuditStatement(data, {
        ringId: ringIdField(fixture.ringProgramId),
        auditorPubkey: fixture.auditor.publicKey().toBytes(),
        epoch: binding.epoch ?? 0n,
        firstContactRoot: binding.firstContactRoot ?? (new Uint8Array(32) as Bytes32),
        keyEscrow: fixture.keyEscrow,
      }),
    ),
  );
  expect(audit === undefined ? undefined : "layout" in audit ? audit.layout : undefined).toEqual(
    RingTransactData.auditLayout(data),
  );
}

/**
 * The auditor recovers the transaction key from the envelope and opens every published slot to the
 * output SPP proves. A change slot's key is the sender's ring change key, the caller checks it.
 */
export function checkDisclosure(
  fixture: Fixture,
  call: SppCall,
  data: RingTransactData,
  sender: ShieldedAddress,
): RingDisclosure {
  const txViewingSecret = openTransactionViewingSecret(fixture.auditor, {
    ephemeralPublicKey: X25519PublicKey.fromU(data.ephU),
    sealed: data.sealed,
  });
  const txKey = ViewingKey.fromBytes(txViewingSecret);
  expect(txKey.publicKey().u()).toEqual(data.txViewingU);
  txKey.destroy();
  const exits = data.outputs.map((output) => output.kind === "exit");
  const disclosure = openRingDisclosure(
    { txViewingSecret, salt: data.salt },
    { layout: RingTransactData.disclosureLayout(data), fields: data.disclosure, exits },
  );
  txViewingSecret.fill(0);
  // SeedOut opens the disclosure exactly beside an exit.
  expect(disclosure.seedOut).toEqual(
    exits.includes(true) ? call.proofInputs.outputBlindingSeed() : undefined,
  );
  const escrowed = disclosure.kind !== "anonymous" && disclosure.layout.keyEscrow;
  const published = call.proofInputs.outputs.filter((output) => !output.isCompact());
  expect(disclosure.outputs).toHaveLength(published.length);
  disclosure.outputs.forEach((opened, index) => {
    const output = itemAt(published, index);
    const owner = output.ownerAddress;
    if (owner === undefined) {
      expect(opened).toEqual(disclosure.kind === "packed" ? undefined : { kind: "dummy" });
      return;
    }
    const exit = exits[index] === true;
    const nullifierPk = escrowed ? undefined : owner.nullifierPublicKey;
    const ownerKey = owner.signingPublicKey.confidentialViewTag();
    const asset = assetField(output.asset);
    if (disclosure.kind === "packed")
      expect(opened).toEqual({
        ownerKey,
        nullifierPk,
        asset,
        amount: output.amount,
        dataHash: output.dataHash ?? new Uint8Array(32),
        ringDataHash: output.ringDataHash ?? new Uint8Array(32),
      });
    else if (exit)
      expect(opened).toEqual({ kind: "exit", nullifierPk, asset, amount: output.amount });
    else if (disclosure.kind === "delivered")
      expect(opened).toEqual({ kind: "ring", nullifierPk, ownerKey });
    else if (hex(owner.toBytes()) === hex(sender.toBytes()))
      expect(opened).toMatchObject({ kind: "ring", nullifierPk, ownerKey });
    else
      expect(opened).toEqual({
        kind: "ring",
        nullifierPk,
        ownerKey,
        recipientU: owner.viewingPublicKey.u(),
      });
  });
  if (disclosure.kind === "anonymous") {
    const spent = call.proofInputs.inputUtxos.filter((input) => !input.isCompact());
    expect(disclosure.inputs).toEqual(
      disclosure.layout.key.kind === "entry"
        ? {
            kind: "openings",
            senderKey: sender.signingPublicKey.confidentialViewTag(),
            senderNullifierPk: sender.nullifierPublicKey,
            inputs: spent.map((input) =>
              input.isDummy()
                ? undefined
                : {
                    asset: assetField(input.utxo.asset),
                    amount: input.utxo.amount,
                    blinding: input.utxo.blinding,
                  },
            ),
          }
        : {
            kind: "commitments",
            first: spent[0]?.hash(),
            prefixes: spent
              .slice(1)
              .map((input) =>
                input.isDummy()
                  ? undefined
                  : BigInt(`0x${Buffer.from(input.hash().subarray(0, 16)).toString("hex")}`),
              ),
          },
    );
  }
  return disclosure;
}

/** A packed slot opens under the recipient's viewing key as scheme 11. */
export function openPacked(
  recipient: ShieldedKeypair,
  call: SppCall,
  data: RingTransactData,
  slotIndex: number,
) {
  const slot = call.proofInputs.externalData.outputs[slotIndex];
  const frame = readOutputData(slot?.data ?? new Uint8Array());
  expect(frame.scheme).toBe(11);
  const viewing = recipient.viewingKey();
  try {
    return decodeRingPacked(
      viewing.decryptUtxo(
        frame.body.subarray(33),
        X25519PublicKey.fromBytes(call.data.txViewingPk),
        data.salt,
        slotIndex,
      ),
    );
  } finally {
    viewing.destroy();
  }
}

/**
 * A delivered or anonymous slot opens to the committed note under the slot secret the recipient's
 * keys answer, `undefined` for another recipient's slot.
 */
export async function openDelivered(
  input: Readonly<{
    fixture: Fixture;
    keys: RingKeys;
    recipient: RingRecipientKey;
    call: SppCall;
    data: RingTransactData;
    slotIndex: number;
  }>,
) {
  const { call, data, slotIndex } = input;
  const firstNullifier = RingTransactData.firstNullifier(data);
  const [slotSecret] = await input.keys.ringDeliverySecrets([
    {
      recipient: input.recipient,
      txViewingPublicKey: X25519PublicKey.fromBytes(call.data.txViewingPk),
      salt: data.salt,
      outputIndex: slotIndex,
      firstNullifier,
    },
  ]);
  const wire = data.outputs[slotIndex];
  if (slotSecret === undefined || (wire?.kind !== "delivered" && wire?.kind !== "anonymous"))
    throw new Error("no delivered slot");
  const owner = input.keys.address();
  return openRingDelivery(
    {
      ring: input.fixture.ringProgramId,
      firstNullifier,
      outputIndex: slotIndex,
      ...(wire.kind === "anonymous" ? { tag: wire.tag } : {}),
    },
    {
      body: wire.body,
      slotSecret,
      owner: {
        signingPublicKey: owner.signingPublicKey,
        nullifierPublicKey: owner.nullifierPublicKey,
      },
      commitment: wire.hash,
      treeId: call.proofInputs.outputTreeId,
    },
  );
}

/** A setup instruction of `length` data bytes ahead of the ring instruction. */
function padding(length: number): Instruction {
  return { programAddress: PADDING_PROGRAM, data: new Uint8Array(length) };
}

const PADDING_PROGRAM = randomAddress();

/**
 * The transfer `prove` builds fits beside the setup instruction that fills its transaction, and one
 * more setup byte or a priority fee refuses it before approval and any proof.
 */
export async function checkFrameCounted(
  fixture: Fixture,
  input: Readonly<{
    payer: Address;
    prove: (approval: RingTransferApproval) => Promise<ProvenRingTransfer>;
  }>,
): Promise<void> {
  const proofs = () => fixture.ringRequests.length + fixture.sppCalls.length;
  const approvals: number[] = [];
  const approval = (transaction: RingTransactionFrame): RingTransferApproval => ({
    transaction,
    approve: async () => {
      approvals.push(proofs());
    },
  });
  const instruction = await (await input.prove(approval({}))).instruction();
  const fits = (length: number): boolean => {
    try {
      checkTransactionFits({
        feePayer: input.payer,
        setupInstructions: [padding(length)],
        instructions: [instruction],
        computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.transact),
      });
      return true;
    } catch {
      return false;
    }
  };
  let [filling, overflow] = [0, TRANSACTION_SIZE_LIMIT];
  while (overflow - filling > 1) {
    const middle = Math.floor((filling + overflow) / 2);
    if (fits(middle)) filling = middle;
    else overflow = middle;
  }
  const before = proofs();
  for (const transaction of [
    { setupInstructions: [padding(overflow)] },
    { setupInstructions: [padding(filling)], priorityFeeLamports: 1n },
  ])
    await expect(input.prove(approval(transaction))).rejects.toMatchObject({
      code: "INTERFACE_TRANSACTION_TOO_LARGE",
    });
  expect(proofs()).toBe(before);
  await input.prove(approval({ setupInstructions: [padding(filling)] }));
  expect(approvals).toEqual([0, before]);
}
