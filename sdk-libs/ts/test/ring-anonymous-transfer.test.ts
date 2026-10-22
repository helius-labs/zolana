import { AccountState, getTokenEncoder } from "@solana-program/token";
import {
  AccountRole,
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  none,
  some,
  type Address,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { WalletKeys } from "../src/client/ports.js";
import { ringProofCircuit } from "../src/client/prover/ring.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { publicAmountFields, publicSlots } from "../src/client/prover/assembly.js";
import { initializePoseidon, solanaOwnerIdentity } from "../src/hasher/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes } from "../src/interface/internal.js";
import {
  associatedTokenAddress,
  ringMemberRegistryAddress,
  splInterfaceWithBump,
  treeAddress,
} from "../src/interface/pda/index.js";
import {
  SOL_INTERFACE,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
} from "../src/interface/program.js";
import { ringCircuitType } from "../src/interface/proving-keys.js";
import { TREE_STATE_PAUSED } from "../src/interface/state.js";
import { treeIdField } from "../src/interface/tree-slot.js";
import { TRANSACTION_SIZE_LIMIT, transactionSize } from "../src/interface/transaction-size.js";
import { TransactWithdrawal, type Bytes32 } from "../src/interface/types.js";
import { randomBlinding } from "../src/keypair/bytes.js";
import { Pairing, type RingAddress } from "../src/keypair/ring-address.js";
import {
  EPOCH_SLOTS,
  J_INBOX,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringIdField,
  senderCommitment,
  tagEpoch,
  tagIndex,
} from "../src/keypair/ring-stream.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { X25519PublicKey } from "../src/keypair/x25519.js";
import {
  anonymousExitTokenOwner,
  signingKeySpendSigner,
  type AnonymousSpendSigner,
} from "../src/ring/anonymous.js";
import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  decodeRingMemberRegistry,
} from "../src/ring/codecs.js";
import { ListId, buildRuleTable, memberOfIdentity } from "../src/ring/policy.js";
import { policyStatementHash } from "../src/ring/statement.js";
import type { ProvenRingTransfer } from "../src/ring/pipeline.js";
import { CustomRingTransfer, type AnonymousTransfer } from "../src/ring/rails.js";
import {
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
} from "../src/ring/transfer.js";
import { RingTransactData } from "../src/ring/transact.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import {
  ConfidentialTransfer,
  WithdrawalTarget,
  assetField,
  type SettlementTransfer,
} from "../src/transaction/instructions/transact.js";
import { decodeConfidential } from "../src/transaction/serialization/codecs.js";
import { ProofInputUtxo, Utxo } from "../src/transaction/utxo.js";
import {
  AnonymousRingState,
  type SentFirstContact,
} from "../src/transaction/wallet/anonymous-state.js";
import type { RingKeys } from "../src/transaction/wallet/keys.js";
import { approveIntent, type ApprovalRequest } from "../src/transaction/wallet/intent.js";
import { Wallet } from "../src/transaction/wallet/state.js";
import { ringAddressOf } from "../src/wallet/anonymous-sync.js";

import { BLOCKHASH } from "./helpers/clients.js";

import {
  ANCHOR_ROOT_INDEX,
  TREE,
  anchorTreeAccount,
  TREE_ID,
  checkAccounts,
  checkAudit,
  checkDisclosure,
  checkFrameCounted,
  checkRingSecrets,
  expanded,
  itemAt,
  noteInput,
  openDelivered,
  randomAddress,
  ringError,
  ringFixture,
  small,
  walletKeys,
  type Fixture,
  type RingFixtureOptions,
} from "./helpers/ring-pipeline.js";

await initializePoseidon();

const assets = new AssetRegistry();
/** The fixture lands every transfer at slot 1. */
const EPOCH = tagEpoch(1n);

interface Sender {
  readonly signing: SigningKey;
  readonly keypair: ShieldedKeypair;
}

function anonymousSender(): Sender {
  const signing = SigningKey.generate();
  return { signing, keypair: ShieldedKeypair.fromKeypair(signing) };
}

function anonymousRing(options: RingFixtureOptions = {}): Promise<Fixture> {
  return ringFixture({ mode: "anonymous", ...options });
}

/** One note of the sender, of the ring unless `ring` is `"default"`. */
function spend(
  fixture: Fixture,
  sender: Sender,
  options: Readonly<{ ring?: Address | "default"; payer?: Address; asset?: Address }> = {},
): ConfidentialTransfer {
  const ring = options.ring === "default" ? undefined : (options.ring ?? fixture.ringProgramId);
  return new ConfidentialTransfer(
    sender.keypair.shieldedAddress(),
    [noteInput(sender.keypair, 10_000n, ring, options.asset)],
    options.payer ?? fixture.authority,
  );
}

/** The hidden owner's rail over `transfer`. */
function rail(
  input: Readonly<{
    fixture: Fixture;
    sender: Sender;
    transfer: ConfidentialTransfer;
    state?: AnonymousRingState;
    keys?: WalletKeys;
    signer?: AnonymousSpendSigner;
    withdrawal?: TransactWithdrawal;
  }>,
): AnonymousTransfer {
  const { fixture, sender } = input;
  const owner = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: input.keys ?? walletKeys(sender.keypair),
    transfer: input.transfer,
    assets,
  });
  return (input.withdrawal === undefined ? owner : owner.withWithdrawalAccounts(input.withdrawal))
    .withAnonymousSigner(
      input.signer ?? signingKeySpendSigner(sender.signing),
      input.state ?? AnonymousRingState.create(fixture.ringProgramId, 0n),
    )
    .withTagRandom(firstFreeIndex);
}

/** The first free index of every draw, each test pins its tags on it. */
function firstFreeIndex(length: number): Uint8Array {
  return new Uint8Array(length);
}

function addressOf(
  fixture: Fixture,
  owner: ShieldedKeypair,
  pairing: Pairing = Pairing.any(),
): Promise<RingAddress> {
  return ringAddressOf({ keys: walletKeys(owner), ring: fixture.ringProgramId, index: 0, pairing });
}

function inboxOf(fixture: Fixture, to: RingAddress): Bytes32 {
  return inboxKey(ringIdField(fixture.ringProgramId), to.recipient.viewingPublicKey);
}

/** The anonymous audit request, its circuit the key the program verifies under. */
function anonymousAudit(fixture: Fixture) {
  const audit = fixture.ringRequests.find((request) => request.kind === "anonymousAudit");
  if (audit?.kind !== "anonymousAudit") throw new Error("no anonymous audit request");
  return { audit, circuit: ringCircuitType(ringProofCircuit(audit)) };
}

/** A sender whose earlier inbox payment to `to` landed at leaf 40 of `treeId` among nine decoys. */
function pairedSender(
  fixture: Fixture,
  to: RingAddress,
  treeId: number,
): Readonly<{ state: AnonymousRingState; contact: SentFirstContact }> {
  const contact: SentFirstContact = {
    recipient: to.recipient.viewingPublicKey,
    treeId,
    leafIndex: 40n,
    utxoHash: small(0x90),
    slotSecret: small(0x91),
    firstNullifier: small(0x92),
    slotIndex: 1,
    epoch: EPOCH,
    index: tagIndex(0),
    asset: SOL_MINT,
    amount: 500n,
  };
  const decoys = Array.from({ length: 9 }, (_, leaf) => ({
    treeId,
    leafIndex: BigInt(leaf),
    hash: small(0xa0 + leaf),
  }));
  for (const decoy of decoys) fixture.placeLeaf(treeAddress(treeId), decoy.hash, decoy.leafIndex);
  fixture.placeLeaf(treeAddress(treeId), contact.utxoHash, contact.leafIndex);
  const state = AnonymousRingState.create(fixture.ringProgramId, 0n)
    .recordFirstContact(contact)
    .rememberDecoys(decoys);
  return { state, contact };
}

function noProofs(fixture: Fixture): void {
  expect(fixture.ringRequests).toHaveLength(0);
  expect(fixture.sppCalls).toHaveLength(0);
}

describe("anonymous ring payment", () => {
  it("tags a payment from its address's inbox stream, the recipient opens it and the auditor every hash", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    expect(call.circuit.kind).toBe("ringAnonymous");
    expect(data.outputs.map((output) => output.kind)).toEqual(["anonymous", "anonymous"]);
    expect([data.fullOpenings, data.keyEscrow, data.anchor]).toEqual([false, false, undefined]);
    const payment = data.outputs[1];
    if (payment?.kind !== "anonymous") throw new Error("no payment slot");
    expect(payment.tag).toEqual(inboxTag(inboxOf(fixture, to), EPOCH, tagIndex(0)));
    await checkAccounts(instruction, { fixture, data, prefix: [], payer: fixture.authority });
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    checkRingSecrets(call, data);
    const { audit, circuit } = anonymousAudit(fixture);
    expect(circuit).toBe("custom-ring-audit-anonymous-4-2");
    expect([audit.inputCount, audit.inputs.length]).toEqual([1, 4]);
    expect(audit.outputs.map((slot) => [slot.stream.inbox, slot.stream.self])).toEqual([
      [false, true],
      [true, false],
    ]);
    const note = await openDelivered({
      fixture,
      keys: walletKeys(bob),
      recipient: { kind: "address", ring: fixture.ringProgramId, index: 0 },
      call,
      data,
      slotIndex: 1,
    });
    expect(note?.utxo.amount).toBe(400n);
    expect(note?.utxoHash).toEqual(payment.hash);
    expect(proven.epoch).toBe(EPOCH);
    expect(proven.firstContacts).toHaveLength(1);
    const contact = itemAt(proven.firstContacts, 0);
    expect(contact).toMatchObject({ slotIndex: 1, index: 0, amount: 400n, utxoHash: payment.hash });
    expect(contact.recipient.equals(to.recipient.viewingPublicKey)).toBe(true);
  });

  it.each([
    ["the output tree", TREE_ID, 2],
    ["a tree outside the transfer", 5, 1],
  ] as const)(
    "pairs on a first contact in %s, its path fetched among seven decoys",
    async (_, treeId, anchorSlot) => {
      const fixture = await anonymousRing();
      const sender = anonymousSender();
      const bob = ShieldedKeypair.generate();
      const to = await addressOf(fixture, bob);
      const { state, contact } = pairedSender(fixture, to, treeId);
      const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client);
      const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

      const payment = data.outputs[1];
      if (payment?.kind !== "anonymous") throw new Error("no payment slot");
      expect(payment.tag).toEqual(pairTag(pairKey(contact.slotSecret), EPOCH, tagIndex(0)));
      expect(data.anchor).toEqual({ tree: anchorSlot, rootIndex: ANCHOR_ROOT_INDEX });
      const tree = treeAddress(treeId);
      const anchored = fixture.anchorTree(tree);
      expect(proven.anchor).toEqual({ tree, rootIndex: ANCHOR_ROOT_INDEX, root: anchored.root });
      await checkAccounts(instruction, {
        fixture,
        data,
        prefix: tree === TREE ? [] : [{ address: tree, role: AccountRole.READONLY }],
        payer: fixture.authority,
      });
      expect(fixture.merkleRequests).toHaveLength(1);
      const request = itemAt(fixture.merkleRequests, 0);
      expect(request.tree).toBe(tree);
      expect(request.leaves).toHaveLength(8);
      expect(request.leaves).toContainEqual(contact.utxoHash);
      checkAudit(fixture, data, {
        kind: "anonymousAudit",
        epoch: EPOCH,
        firstContactRoot: anchored.root,
      });
      checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
      const { audit } = anonymousAudit(fixture);
      expect(audit.anchor).toMatchObject({
        treeId: treeIdField(treeId),
        slotSecret: contact.slotSecret,
        pathIndex: 40n,
        path: anchored.path(40),
      });
      expect(audit.outputs[1]?.stream).toMatchObject({ pair: true, inbox: false, index: 0 });
      // A pair payment opens no new first contact.
      expect(proven.firstContacts).toEqual([]);
    },
  );

  it("refuses a first contact path its tree's root history does not hold before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    fixture.accounts.set(treeAddress(5), anchorTreeAccount(small(0x72)));
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client),
    ).rejects.toThrow(
      ringError("RING_ANCHOR_INVALID", { reason: "root", rootIndex: ANCHOR_ROOT_INDEX }),
    );
    noProofs(fixture);
  });

  it("refuses a first contact path that does not reach its root before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state, contact } = pairedSender(fixture, to, 5);
    const served = fixture.client.getMerkleProofs;
    fixture.client.getMerkleProofs = async (tree, leaves) => {
      const response = await served(tree, leaves);
      return {
        ...response,
        proofs: response.proofs.map((proof) =>
          Buffer.from(proof.leaf).equals(Buffer.from(contact.utxoHash))
            ? { ...proof, path: proof.path.map((node, at) => (at === 3 ? small(0x7f) : node)) }
            : proof,
        ),
      };
    };
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_ANCHOR_INVALID", { reason: "path" }));
    noProofs(fixture);
  });

  it("refuses a first contact on a paused tree before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    const paused = anchorTreeAccount(fixture.anchorTree(treeAddress(5)).root);
    paused.data[1] = TREE_STATE_PAUSED;
    fixture.accounts.set(treeAddress(5), paused);
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_ANCHOR_INVALID", { reason: "paused", tree: treeAddress(5) }));
    noProofs(fixture);
  });

  it("names one leaf list on every anchor read of a contact, so no intersection isolates it", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, TREE_ID);
    const prove = () =>
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client);
    await prove();
    await prove();

    expect(fixture.merkleRequests).toHaveLength(2);
    expect(itemAt(fixture.merkleRequests, 1).leaves).toEqual(
      itemAt(fixture.merkleRequests, 0).leaves,
    );
  });

  it("takes the inbox stream when the address's rows refuse the first contact", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob, Pairing.of([{ mint: SOL_MINT, minAmount: 1_000n }]));
    const { state } = pairedSender(fixture, to, TREE_ID);
    const inbox = inboxOf(fixture, to);
    fixture.publishTags([inboxTag(inbox, EPOCH, tagIndex(0))]);
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), state })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data } = await expanded(fixture, proven, "anonymous");

    const payment = data.outputs[1];
    if (payment?.kind !== "anonymous") throw new Error("no payment slot");
    expect(payment.tag).toEqual(inboxTag(inbox, EPOCH, tagIndex(0)));
    expect(data.anchor).toBeUndefined();
    expect(fixture.merkleRequests).toEqual([]);
    expect(proven.firstContacts.map((contact) => contact.index)).toEqual([0]);
  });

  it("pays an address whose every inbox index outsiders already used in the epoch", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const inbox = inboxOf(fixture, to);
    fixture.publishTags(
      Array.from({ length: J_INBOX }, (_, index) => inboxTag(inbox, EPOCH, tagIndex(index))),
    );
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data } = await expanded(fixture, proven, "anonymous");

    const payment = data.outputs[1];
    if (payment?.kind !== "anonymous") throw new Error("no payment slot");
    expect(payment.tag).toEqual(inboxTag(inbox, EPOCH, tagIndex(0)));
  });

  it("keeps a payment on its own slot when a later send on the shared transfer follows it", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const transfer = spend(fixture, sender);
    const paying = rail({ fixture, sender, transfer }).withPayment({
      to,
      asset: SOL_MINT,
      amount: 400n,
    });
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const proven = await paying.prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.outputs.map((output) => output.kind)).toEqual([
      "anonymous",
      "anonymous",
      "exit",
      "anonymous",
    ]);
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    const note = await openDelivered({
      fixture,
      keys: walletKeys(bob),
      recipient: { kind: "address", ring: fixture.ringProgramId, index: 0 },
      call,
      data,
      slotIndex: 1,
    });
    expect(note?.utxo.amount).toBe(400n);
  });

  it("completes through a remote holder that forwards only port methods", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const local = walletKeys(sender.keypair);
    const called = new Set<string>();
    const track = <T>(name: string, value: T): T => {
      called.add(name);
      return value;
    };
    const remote: WalletKeys & RingKeys = {
      address: () => track("address", local.address()),
      viewingPublicKeys: () => track("viewingPublicKeys", local.viewingPublicKeys()),
      decrypt: (requests) => track("decrypt", local.decrypt(requests)),
      derive: (requests) => track("derive", local.derive(requests)),
      transactionKeys: (requests) => track("transactionKeys", local.transactionKeys(requests)),
      ringAddressKeys: (ring, indexes) =>
        track("ringAddressKeys", local.ringAddressKeys(ring, indexes)),
      ringDeliverySecrets: (requests) =>
        track("ringDeliverySecrets", local.ringDeliverySecrets(requests)),
      ringChangeKey: (ring) => track("ringChangeKey", local.ringChangeKey(ring)),
      senderViewTags: (counters) => track("senderViewTags", local.senderViewTags(counters)),
      prove: (inputs, context) => track("prove", local.prove(inputs, context)),
      proveMerge: (inputs, context) => track("proveMerge", local.proveMerge(inputs, context)),
      proveRingWithSecret: (request, context) =>
        track("proveRingWithSecret", local.proveRingWithSecret(request, context)),
    };
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), keys: remote })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(call.authority).toBe(remote);
    expect([...called].sort()).toEqual([
      "address",
      "ringAddressKeys",
      "ringChangeKey",
      "transactionKeys",
    ]);
  });
});

describe("anonymous ring exits and entries", () => {
  it("exits a note to the default ring under scheme 3 with SeedOut in the disclosure", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const outside = ShieldedKeypair.generate();
    const transfer = spend(fixture, sender);
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const proven = await rail({ fixture, sender, transfer }).prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.outputs.map((output) => output.kind)).toEqual(["anonymous", "exit"]);
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    const disclosure = checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(disclosure.seedOut).toEqual(call.proofInputs.outputBlindingSeed());
    const exit = data.outputs[1];
    if (exit?.kind !== "exit") throw new Error("no exit slot");
    const viewing = outside.viewingKey();
    const opened = decodeConfidential(
      viewing.decryptUtxo(
        exit.payload.subarray(33),
        X25519PublicKey.fromBytes(call.data.txViewingPk),
        data.salt,
        1,
      ),
    );
    viewing.destroy();
    expect(opened.amount).toBe(300n);
    expect(proven.firstContacts).toEqual([]);
  });

  it("spends a default-ring note under the entry key, every input opened in full", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const proven = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender, { ring: "default" }),
    })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.fullOpenings).toBe(true);
    // Input byte bit 7 names the entry key.
    expect((RingTransactData.encode(data)[2] ?? 0) & 0x80).toBe(0x80);
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    const disclosure = checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(disclosure.kind === "anonymous" && disclosure.inputs.kind).toBe("openings");
    const { audit, circuit } = anonymousAudit(fixture);
    expect(circuit).toBe("custom-ring-audit-anonymous-entry-8-2");
    expect([audit.layout.fullOpenings, audit.inputs.length]).toEqual([true, 8]);
  });

  it("counts an entry's default owner tag, its setup instructions and fee before approval and any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        rail({ fixture, sender, transfer: spend(fixture, sender, { ring: "default" }) })
          .withPayment({ to, asset: SOL_MINT, amount: 400n })
          .proveApproved(fixture.client, approval),
    });
  });

  it("refuses an entry input that carries data before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const input = ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10_000n,
        blinding: randomBlinding(),
      }),
      sender.keypair,
      { dataHash: small(0x55) },
      TREE_ID,
    );
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      [input],
      fixture.authority,
    );
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_ENTRY_INPUT_DATA", { index: 0 }),
    );
    noProofs(fixture);
  });

  it("refuses an exit to the sender's own ring address key and to a payee's", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const own = await addressOf(fixture, sender.keypair);
    const issued = AnonymousRingState.create(fixture.ringProgramId, 0n).issue(0, Pairing.any());
    const toOwn = spend(fixture, sender);
    toOwn.sendDefaultRing(own.recipient, SOL_MINT, 100n);
    await expect(
      rail({ fixture, sender, transfer: toOwn, state: issued }).prove(fixture.client),
    ).rejects.toThrow(ringError("RING_ADDRESS_EXIT"));
    const bob = await addressOf(fixture, ShieldedKeypair.generate());
    const toPayee = spend(fixture, sender);
    const paying = rail({ fixture, sender, transfer: toPayee }).withPayment({
      to: bob,
      asset: SOL_MINT,
      amount: 100n,
    });
    toPayee.sendDefaultRing(bob.recipient, SOL_MINT, 100n);
    await expect(paying.prove(fixture.client)).rejects.toThrow(ringError("RING_ADDRESS_EXIT"));
    noProofs(fixture);
  });

  it("refuses a ring output no payment planned", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 100n);
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_UNPLANNED_OUTPUT", { slotIndex: 1 }),
    );
    noProofs(fixture);
  });
});

describe("anonymous ring signer and epoch", () => {
  it("refuses another signer, a hidden owner that signs in public, a partial key holder and another ring", async () => {
    const sender = anonymousSender();
    const hidden = sender.keypair.shieldedAddress().solanaAddress();
    const refused = async (
      fixture: Fixture,
      transfer: Promise<ProvenRingTransfer>,
      code: string,
    ): Promise<void> => {
      await expect(transfer).rejects.toThrow(ringError(code));
      noProofs(fixture);
    };
    const ring = await anonymousRing();
    await refused(
      ring,
      rail({
        fixture: ring,
        sender,
        transfer: spend(ring, sender),
        signer: signingKeySpendSigner(SigningKey.generate()),
      }).prove(ring.client),
      "RING_ANONYMOUS_SIGNER_MISMATCH",
    );
    await refused(
      ring,
      rail({ fixture: ring, sender, transfer: spend(ring, sender, { payer: hidden }) }).prove(
        ring.client,
      ),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const coSigned = await anonymousRing({
      coSigner: { signer: hidden, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
    });
    await refused(
      coSigned,
      rail({ fixture: coSigned, sender, transfer: spend(coSigned, sender) }).prove(coSigned.client),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const local = walletKeys(sender.keypair);
    const partial: WalletKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: (requests) => local.derive(requests),
      transactionKeys: (requests) => local.transactionKeys(requests),
      prove: (inputs, context) => local.prove(inputs, context),
      proveMerge: (inputs, context) => local.proveMerge(inputs, context),
      proveRingWithSecret: (request, context) => local.proveRingWithSecret(request, context),
    };
    await refused(
      ring,
      rail({ fixture: ring, sender, transfer: spend(ring, sender), keys: partial }).prove(
        ring.client,
      ),
      "RING_KEYS_REQUIRED",
    );
    const confidential = await ringFixture();
    await refused(
      confidential,
      rail({ fixture: confidential, sender, transfer: spend(confidential, sender) }).prove(
        confidential.client,
      ),
      "RING_NOT_ANONYMOUS",
    );
    const other = await anonymousRing();
    const foreign = await addressOf(other, ShieldedKeypair.generate());
    expect(() =>
      rail({ fixture: ring, sender, transfer: spend(ring, sender) }).withPayment({
        to: foreign,
        asset: SOL_MINT,
        amount: 1n,
      }),
    ).toThrow(ringError("RING_FOREIGN_RING", { address: other.ringProgramId }));
  });

  it("names the epoch before the landing slot's one epoch late and refuses a later slot", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) }).prove(
      fixture.client,
    );
    const previousEpoch = async (slot: bigint): Promise<boolean> => {
      const data = (await proven.instructionAt(slot)).data;
      if (data === undefined) throw new Error("no instruction data");
      return RingTransactData.parse(data.subarray(1), "anonymous").previousEpoch;
    };
    expect(await previousEpoch(1n)).toBe(false);
    expect(await previousEpoch(EPOCH_SLOTS)).toBe(true);
    await expect(
      Promise.resolve().then(() => proven.instructionAt(2n * EPOCH_SLOTS)),
    ).rejects.toThrow(ringError("RING_EPOCH_PASSED", { proofEpoch: "0", currentEpoch: "2" }));
  });
});

describe("anonymous ring transfer builder", () => {
  /** A spend of `notes` notes of 10, of the ring or the default ring, on a ring a co-signer guards when `policy`. */
  async function anonymousSpend(
    input: Readonly<{
      notes: number;
      amount: bigint;
      ring?: "default";
      /** Default-ring notes beside the ring notes, a transfer may spend them. */
      defaultNotes?: readonly bigint[];
      policy?: boolean;
      withdraw?: boolean;
    }>,
  ) {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await anonymousRing(
      input.policy === true
        ? {
            table: buildRuleTable({
              rules: [
                {
                  subject: "sender",
                  source: { kind: "lists", present: [ListId.allow], absent: [] },
                  guard: { kind: "always" },
                },
              ],
              limits: [{ asset: assetField(SOL_MINT), cap: 0n, cosignAbove: 1n }],
            }),
            records: [
              {
                member: memberOfIdentity(
                  sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
                ),
                lists: 1n,
              },
            ],
            coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
          }
        : {},
    );
    const notes = [
      ...Array.from({ length: input.notes }, () => ({
        amount: 10n,
        ring: input.ring === "default" ? undefined : fixture.ringProgramId,
      })),
      ...(input.defaultNotes ?? []).map((amount) => ({ amount, ring: undefined })),
    ];
    const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
    wallet._replace({
      utxos: notes.map((note, index) => ({
        utxo: new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: note.amount,
          blinding: randomBlinding(),
          ...(note.ring === undefined ? {} : { ringProgramId: note.ring }),
        }),
        outputContext: { hash: small(index + 1), tree: TREE, leafIndex: BigInt(index) },
        nullifier: small(index + 100),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: ApprovalRequest[] = [];
    const params = {
      client: { ...fixture.client, getLatestBlockhash: async () => BLOCKHASH },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender.keypair),
      feePayer: fixture.authority,
      amount: input.amount,
      priorityFeeLamports: 5_000n,
      ...(input.policy === true ? { cosigner: coSigner } : {}),
      approve: async (request: ApprovalRequest) => {
        requests.push(request);
        return approveIntent(request.intent);
      },
      anonymous: {
        signer: signingKeySpendSigner(sender.signing),
        state: AnonymousRingState.create(fixture.ringProgramId, 0n),
      },
    };
    const build =
      input.withdraw === true
        ? buildRingWithdrawalTransaction({ ...params, recipient: randomAddress() })
        : buildRingTransferTransaction({
            ...params,
            recipient: await addressOf(fixture, ShieldedKeypair.generate()),
            ...(input.ring === "default"
              ? { inputs: "default" as const }
              : input.defaultNotes === undefined
                ? {}
                : { inputs: "ring-or-default" as const }),
          });
    return { fixture, requests, build };
  }

  it("spends the widest commitment class and refuses a payment past it before approval", async () => {
    const widest = await anonymousSpend({ notes: 24, amount: 235n, policy: true });
    expect(transactionSize(await widest.build)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(widest.requests).toHaveLength(1);
    expect(widest.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 24,
      outputs: 2,
    });
    const wider = await anonymousSpend({ notes: 25, amount: 245n });
    await expect(wider.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 24 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("refuses a withdrawal of the widest class past one transaction before approval as too many notes", async () => {
    const wide = await anonymousSpend({ notes: 24, amount: 235n, policy: true, withdraw: true });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_WITHDRAWAL",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { selected: 24, limit: TRANSACTION_SIZE_LIMIT } },
    });
    expect(wide.requests).toEqual([]);
    noProofs(wide.fixture);
  });

  it("spends the entry key's input class of default-ring notes and refuses one more", async () => {
    const entry = await anonymousSpend({ notes: 8, amount: 75n, ring: "default", policy: true });
    expect(transactionSize(await entry.build)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(entry.requests).toHaveLength(1);
    const wider = await anonymousSpend({ notes: 9, amount: 85n, ring: "default" });
    await expect(wider.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 8 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("funds a ring-or-default payment from ring notes alone, else default-ring notes alone, never both", async () => {
    const ringAlone = await anonymousSpend({ notes: 3, amount: 25n, defaultNotes: [100n] });
    await ringAlone.build;
    expect(ringAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 0n });
    const defaultAlone = await anonymousSpend({ notes: 3, amount: 40n, defaultNotes: [100n] });
    await defaultAlone.build;
    expect(defaultAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 100n });
    const both = await anonymousSpend({ notes: 3, amount: 50n, defaultNotes: [25n] });
    await expect(both.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_INSUFFICIENT_BALANCE",
    });
    expect(both.requests).toEqual([]);
    noProofs(both.fixture);
  });

  it("compiles a payment proven in the epoch before the slot it compiles at under the previous epoch", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: sender.keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 10_000n,
            blinding: randomBlinding(),
            ringProgramId: fixture.ringProgramId,
          }),
          outputContext: { hash: small(1), tree: TREE, leafIndex: 0n },
          nullifier: small(100),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    let proved = false;
    const transaction = await buildRingTransferTransaction({
      client: {
        ...fixture.client,
        getSlot: async () => (proved ? EPOCH_SLOTS : 1n),
        proveAnonymousRingTransact: async (input) => {
          proved = true;
          return fixture.client.proveAnonymousRingTransact(input);
        },
        getLatestBlockhash: async () => BLOCKHASH,
      },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender.keypair),
      feePayer: fixture.authority,
      recipient: to,
      amount: 400n,
      anonymous: {
        signer: signingKeySpendSigner(sender.signing),
        state: AnonymousRingState.create(fixture.ringProgramId, 0n),
      },
    });
    const data = decompileTransactionMessage(
      getCompiledTransactionMessageDecoder().decode(transaction.messageBytes),
    ).instructions.find(
      (instruction) => instruction.programAddress === fixture.ringProgramId,
    )?.data;
    if (data === undefined) throw new Error("no ring instruction");
    expect(RingTransactData.parse(data.subarray(1), "anonymous").previousEpoch).toBe(true);
  });
});

const MINT = address("So11111111111111111111111111111111111111112");
const STRANGER = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
/** A keypair address, on the ed25519 curve. */
const DESTINATION = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
const TOKEN_ACCOUNT = await associatedTokenAddress(STRANGER, MINT, SPL_TOKEN_PROGRAM_ID);

function tokenAccount(
  owner: Address,
  others: Readonly<{ mint?: Address; delegate?: Address; closeAuthority?: Address }> = {},
): RpcAccount {
  const key = (value: Address | undefined) => (value === undefined ? none<Address>() : some(value));
  return {
    owner: SPL_TOKEN_PROGRAM_ID,
    lamports: 1n,
    data: new Uint8Array(
      getTokenEncoder().encode({
        mint: others.mint ?? MINT,
        owner,
        amount: 0n,
        delegate: key(others.delegate),
        state: AccountState.Initialized,
        isNative: none(),
        delegatedAmount: 0n,
        closeAuthority: key(others.closeAuthority),
      }),
    ),
  };
}

/** An SPL or SOL withdrawal of 4 out of a ring note, the destination's account as the chain holds it. */
async function anonymousWithdrawal(
  input: Readonly<{
    sender: Sender;
    destination: Address;
    spl: boolean;
    accounts?: ReadonlyMap<Address, RpcAccount>;
    exitTokenOwner?: Address;
  }>,
): Promise<Readonly<{ fixture: Fixture; proven: Promise<ProvenRingTransfer> }>> {
  const fixture = await anonymousRing();
  for (const [key, account] of input.accounts ?? []) fixture.accounts.set(key, account);
  const { sender, destination } = input;
  const transfer = spend(fixture, sender, input.spl ? { asset: MINT } : {});
  let withdrawal: TransactWithdrawal;
  if (input.spl) {
    const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(MINT);
    transfer.withdraw(
      MINT,
      4n,
      WithdrawalTarget.spl({
        recipientTokenAccount: destination,
        splTokenInterface,
        splInterfaceBump,
      }),
    );
    withdrawal = TransactWithdrawal.spl({
      mint: MINT,
      splTokenInterface,
      recipientTokenAccount: destination,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    });
  } else {
    transfer.withdraw(SOL_MINT, 4n, WithdrawalTarget.sol({ recipient: destination }));
    withdrawal = TransactWithdrawal.sol({ recipient: destination });
  }
  const anonymous = rail({ fixture, sender, transfer, withdrawal });
  return {
    fixture,
    proven: (input.exitTokenOwner === undefined
      ? anonymous
      : anonymous.withExitTokenOwner(input.exitTokenOwner)
    ).prove(fixture.client),
  };
}

function exitTokenOwnerOf(fixture: Fixture): Address | undefined {
  const call = itemAt(fixture.sppCalls, 0);
  return call.circuit.kind === "ringAnonymous" ? call.circuit.exitTokenOwner : undefined;
}

describe("anonymous ring withdrawal destination", () => {
  const sender = anonymousSender();
  const hidden = sender.keypair.shieldedAddress().solanaAddress();

  it("refuses an SPL destination naming the hidden owner or a second key before proving", async () => {
    const associated = await associatedTokenAddress(hidden, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Address, RpcAccount | undefined, string])[] = [
      [TOKEN_ACCOUNT, tokenAccount(hidden), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [hidden, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [associated, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_ON_CURVE"],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { delegate: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
      ],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { closeAuthority: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
      ],
      [TOKEN_ACCOUNT, undefined, "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID"],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { mint: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
    ];
    for (const [destination, account, code] of refusals) {
      const { fixture, proven } = await anonymousWithdrawal({
        sender,
        destination,
        spl: true,
        accounts: new Map(account === undefined ? [] : [[destination, account] as const]),
      });
      await expect(proven).rejects.toThrow(ringError(code, { destination }));
      noProofs(fixture);
    }
  });

  it("refuses a SOL recipient that is the hidden owner or holds data before proving", async () => {
    for (const [recipient, account, code] of [
      [hidden, undefined, "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA"],
      [
        DESTINATION,
        { owner: SYSTEM_PROGRAM, lamports: 1n, data: new Uint8Array(80) },
        "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA",
      ],
    ] as const) {
      const { fixture, proven } = await anonymousWithdrawal({
        sender,
        destination: recipient,
        spl: false,
        accounts: new Map(account === undefined ? [] : [[recipient, account] as const]),
      });
      await expect(proven).rejects.toThrow(ringError(code, { destination: recipient }));
      noProofs(fixture);
    }
  });

  it("binds the SPL token account owner or no owner for a SOL recipient", async () => {
    const spl = await anonymousWithdrawal({
      sender,
      destination: TOKEN_ACCOUNT,
      spl: true,
      accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
    });
    await expanded(spl.fixture, await spl.proven, "anonymous");
    expect(exitTokenOwnerOf(spl.fixture)).toBe(STRANGER);
    const sol = await anonymousWithdrawal({ sender, destination: DESTINATION, spl: false });
    const { instruction, data } = await expanded(sol.fixture, await sol.proven, "anonymous");
    expect(exitTokenOwnerOf(sol.fixture)).toBeUndefined();
    await checkAccounts(instruction, {
      fixture: sol.fixture,
      data,
      prefix: [],
      payer: sol.fixture.authority,
      settlement: [
        { address: SOL_INTERFACE, role: AccountRole.WRITABLE },
        { address: DESTINATION, role: AccountRole.WRITABLE },
      ],
    });
  });

  const minted = new Map([
    [MINT, { owner: SPL_TOKEN_PROGRAM_ID, lamports: 1n, data: new Uint8Array(82) }],
  ]);

  it("takes a destination the transaction creates as the named owner's associated token account", async () => {
    const { fixture, proven } = await anonymousWithdrawal({
      sender,
      destination: TOKEN_ACCOUNT,
      spl: true,
      accounts: minted,
      exitTokenOwner: STRANGER,
    });
    await expanded(fixture, await proven, "anonymous");
    expect(exitTokenOwnerOf(fixture)).toBe(STRANGER);
  });

  const splLeg = (destination: Address): SettlementTransfer => ({
    kind: "spl",
    mint: MINT,
    isDeposit: false,
    amount: 4n,
    tokenAccount: destination,
    splInterfaceBump: 255,
  });

  const exitOwner = (
    input: Readonly<{
      transfers: readonly SettlementTransfer[];
      accounts: ReadonlyMap<Address, RpcAccount>;
      tokenOwner?: Address;
    }>,
  ) =>
    anonymousExitTokenOwner({
      client: { getAccount: async (key) => input.accounts.get(key) },
      transfers: input.transfers,
      hiddenOwner: addressBytes(hidden) as Bytes32,
      ...(input.tokenOwner === undefined ? {} : { tokenOwner: input.tokenOwner }),
    });

  const tokenOwnerOf = (account: RpcAccount) =>
    exitOwner({
      transfers: [splLeg(TOKEN_ACCOUNT)],
      accounts: new Map([[TOKEN_ACCOUNT, account]]),
    });

  it("refuses a named owner the destination or the withdrawals contradict", async () => {
    const associated = await associatedTokenAddress(hidden, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Parameters<typeof exitOwner>[0], string])[] = [
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: minted },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: minted, tokenOwner: DESTINATION },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: new Map(), tokenOwner: STRANGER },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(associated)], accounts: minted, tokenOwner: hidden },
        "RING_ANONYMOUS_EXIT_LINKS_OWNER",
      ],
      [
        {
          transfers: [splLeg(TOKEN_ACCOUNT)],
          accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
          tokenOwner: DESTINATION,
        },
        "RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH",
      ],
      [
        {
          transfers: [{ kind: "sol", isDeposit: false, amount: 4n, userSolAccount: DESTINATION }],
          accounts: new Map(),
          tokenOwner: STRANGER,
        },
        "CLIENT_ANONYMOUS_EXIT_TOKEN_OWNER_MISMATCH",
      ],
    ];
    for (const [input, code] of refusals)
      await expect(exitOwner(input)).rejects.toMatchObject({ code });
  });

  it("names the destination, the named owner and the token owner of a mismatch", async () => {
    await expect(
      exitOwner({
        transfers: [splLeg(TOKEN_ACCOUNT)],
        accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
        tokenOwner: DESTINATION,
      }),
    ).rejects.toThrow(
      ringError("RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH", {
        destination: TOKEN_ACCOUNT,
        named: DESTINATION,
        owner: STRANGER,
      }),
    );
  });

  it("refuses two SPL exits to different owners", async () => {
    const other = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
    const second = await associatedTokenAddress(other, MINT, SPL_TOKEN_PROGRAM_ID);
    await expect(
      exitOwner({
        transfers: [splLeg(TOKEN_ACCOUNT), splLeg(second)],
        accounts: new Map([
          [TOKEN_ACCOUNT, tokenAccount(STRANGER)],
          [second, tokenAccount(other)],
        ]),
      }),
    ).rejects.toMatchObject({ code: "CLIENT_ANONYMOUS_EXIT_DESTINATIONS_DIFFER" });
  });

  const token2022 = (
    tail: readonly number[],
    edit: (data: Uint8Array) => void = () => undefined,
  ): RpcAccount => {
    const base = tokenAccount(STRANGER);
    const data = Uint8Array.from([...base.data, ...tail]);
    edit(data);
    return { ...base, owner: SPL_TOKEN_2022_PROGRAM_ID, data };
  };

  it("reads a Token-2022 account with extensions as SPP unpacks it", async () => {
    // Account type `Account`, then an ImmutableOwner entry of type 7 and length 0.
    await expect(tokenOwnerOf(token2022([2, 7, 0, 0, 0]))).resolves.toBe(STRANGER);
  });

  it.each<readonly [string, RpcAccount, string]>([
    [
      "an extension tail that is not an account",
      token2022([1, 7, 0, 0, 0]),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "the multisig length",
      token2022([2, ...new Uint8Array(189)]),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "a frozen state",
      token2022([], (data) => (data[108] = AccountState.Frozen)),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "a delegate tag above one",
      token2022([], (data) => (data[72] = 2)),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
    ],
  ])("refuses a token account with %s", async (_, account, code) => {
    await expect(tokenOwnerOf(account)).rejects.toThrow(
      ringError(code, { destination: TOKEN_ACCOUNT }),
    );
  });

  it("refuses a destination of another program than the token programs", async () => {
    await expect(
      tokenOwnerOf({ ...tokenAccount(STRANGER), owner: randomAddress() }),
    ).rejects.toThrow(
      ringError("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID", { destination: TOKEN_ACCOUNT }),
    );
  });
});

describe("anonymous rail on a policy ring", () => {
  const ZERO = new Uint8Array(32) as Bytes32;

  /** One rule over the sender's allow list and one SOL limit, the sender's record on the list. */
  function policyRing(
    sender: Sender,
    limit: Readonly<{ cap: bigint; cosignAbove: bigint }>,
    coSigner?: Address,
  ): Promise<Fixture> {
    return anonymousRing({
      table: buildRuleTable({
        rules: [
          {
            subject: "sender",
            source: { kind: "lists", present: [ListId.allow], absent: [] },
            guard: { kind: "always" },
          },
        ],
        limits: [{ asset: assetField(SOL_MINT), ...limit }],
      }),
      records: [
        {
          member: memberOfIdentity(
            sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
          ),
          lists: 1n,
        },
      ],
      ...(coSigner === undefined
        ? {}
        : { coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] } }),
    });
  }

  async function pay(fixture: Fixture, sender: Sender): Promise<ProvenRingTransfer> {
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
  }

  function memberPolicy(fixture: Fixture) {
    const policy = fixture.ringRequests.find((request) => request.kind === "memberPolicy");
    if (policy?.kind !== "memberPolicy") throw new Error("no member policy request");
    return policy;
  }

  it("proves the policy over the hidden sender's commitment the frame and both statements bind", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 1_000n, cosignAbove: 0n });
    const proven = await pay(fixture, sender);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    const senderPkHash = sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash();
    const commitment = senderCommitment({
      senderPkHash,
      privateTxBlinding: call.proofInputs.privateTxBlinding(),
    });
    expect(data.policy?.senderCommitment).toEqual(commitment);
    expect(data.approvalRequired).toBe(false);
    const policy = memberPolicy(fixture);
    expect(policy).toMatchObject({ anonymous: true, sender: commitment, senderPkHash });
    expect(policy.senderEntry.own?.kind).toBe("present");
    const registryAccount = fixture.accounts.get(
      await ringMemberRegistryAddress(fixture.ringProgramId),
    );
    if (registryAccount === undefined) throw new Error("no registry");
    const slots = publicSlots(call.proofInputs.externalData.interfaceTransfers);
    expect(policy.publicInputHash).toEqual(
      policyStatementHash({
        key: { kind: "member", anonymous: true },
        privateTxHash: data.privateTxHash,
        policyHash: decodeRingMemberRegistry(registryAccount.data).policyHash,
        ringId: ringIdField(fixture.ringProgramId),
        approvalRequired: false,
        keyEscrow: false,
        ownRoot: fixture.ownTree.root,
        curatorRoot: ZERO,
        sender: commitment,
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
      }),
    );
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    expect(anonymousAudit(fixture).audit.senderCommitment).toEqual(commitment);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [
        {
          address: await ringMemberRegistryAddress(fixture.ringProgramId),
          role: AccountRole.READONLY,
        },
      ],
      payer: fixture.authority,
    });
  });

  it("refuses a hidden sender off the required list before any proof", async () => {
    const fixture = await policyRing(anonymousSender(), { cap: 1_000n, cosignAbove: 0n });
    await expect(pay(fixture, anonymousSender())).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", {
        reason: "lists",
        ruleIndex: 0,
        subject: "sender",
      }),
    );
    noProofs(fixture);
  });

  it("refuses an outflow past the cap before any proof", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 399n, cosignAbove: 0n });
    await expect(pay(fixture, sender)).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "399", outflow: "400" }),
    );
    noProofs(fixture);
  });

  it("names and signs with the co-signer when the outflow passes the co-sign bound", async () => {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n }, coSigner);
    const proven = await pay(fixture, sender);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous", coSigner);

    expect(proven.approvalRequired).toBe(true);
    expect(proven.coSigner).toBe(coSigner);
    expect(data.approvalRequired).toBe(true);
    expect(memberPolicy(fixture).approvalRequired).toBe(true);
    expect(call.authorization?.parties[1]).toEqual(solanaOwnerIdentity(addressBytes(coSigner)));
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [
        {
          address: await ringMemberRegistryAddress(fixture.ringProgramId),
          role: AccountRole.READONLY,
        },
        { address: coSigner, role: AccountRole.READONLY_SIGNER },
      ],
      payer: fixture.authority,
    });
  });

  it("refuses an outflow past the co-sign bound on a ring without a co-signer", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n });
    await expect(pay(fixture, sender)).rejects.toThrow(ringError("RING_COSIGNER_REQUIRED"));
    noProofs(fixture);
  });
});

describe("anonymous entry key bound", () => {
  /** A payment out of `count` default-ring notes of the sender. */
  async function entry(
    fixture: Fixture,
    sender: Sender,
    count: number,
  ): Promise<ProvenRingTransfer> {
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      Array.from({ length: count }, () => noteInput(sender.keypair, 1_000n)),
      fixture.authority,
    );
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
  }

  it("spends eight default-ring notes under the entry key", async () => {
    const fixture = await anonymousRing();
    const proven = await entry(fixture, anonymousSender(), 8);
    const { data } = await expanded(fixture, proven, "anonymous");
    expect(data.fullOpenings).toBe(true);
    expect(data.nullifiers).toHaveLength(8);
    expect(anonymousAudit(fixture).circuit).toBe("custom-ring-audit-anonymous-entry-8-2");
  });

  it("refuses a ninth default-ring note before any proof", async () => {
    const fixture = await anonymousRing();
    await expect(entry(fixture, anonymousSender(), 9)).rejects.toThrow(
      ringError("RING_TRANSACT_DATA_INVALID", { reason: "RingShapeUnkeyed" }),
    );
    noProofs(fixture);
  });
});

describe("anonymous party identities", () => {
  const ZERO = new Uint8Array(32) as Bytes32;
  const identity = (key: Address): Uint8Array => solanaOwnerIdentity(addressBytes(key));

  /** The payer, co-signer and exit identities the SPP proof of one payment binds. */
  async function parties(options: RingFixtureOptions, exit?: Address) {
    const fixture = await anonymousRing(options);
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    if (exit !== undefined)
      transfer.withdraw(SOL_MINT, 4n, WithdrawalTarget.sol({ recipient: exit }));
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await rail({
      fixture,
      sender,
      transfer,
      ...(exit === undefined ? {} : { withdrawal: TransactWithdrawal.sol({ recipient: exit }) }),
    })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    return {
      payer: fixture.authority,
      bound: itemAt(fixture.sppCalls, 0).authorization?.parties,
    };
  }

  it("binds the payer and zero for an absent co-signer and an absent exit", async () => {
    const { payer, bound } = await parties({});
    expect(bound).toEqual([identity(payer), ZERO, ZERO]);
  });

  it("binds a configured co-signer the transfer does not demand", async () => {
    const coSigner = randomAddress();
    const { payer, bound } = await parties({
      coSigner: { signer: coSigner, scope: RING_COSIGN_DEPOSITS, thresholds: [] },
    });
    expect(bound).toEqual([identity(payer), identity(coSigner), ZERO]);
  });

  it("binds the destination of a withdrawal", async () => {
    const { payer, bound } = await parties({}, DESTINATION);
    expect(bound).toEqual([identity(payer), ZERO, identity(DESTINATION)]);
  });
});
