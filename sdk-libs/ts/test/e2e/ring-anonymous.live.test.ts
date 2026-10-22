// Fresh anonymous rings keyed by the harness ring rpc in derived mode, one admitting listed senders only.
import { generateKeyPairSigner, type Address, type KeyPairSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { ZolanaClient } from "../../src/client/client.js";
import { syncWallet } from "../../src/index.js";
import {
  ListId,
  buildRuleTable,
  memberOfIdentity,
  recordBit,
  type RuleTable,
} from "../../src/ring/advanced.js";
import { customRingDepositPayload } from "../../src/ring/deposit-payload.js";
import {
  AuthorityListWrite,
  RingInstructionTag,
  RingRpc,
  buildRingDepositTransaction,
  buildRingTransferTransaction,
  checkedReaderKey,
  fetchRingProgramConfig,
  grantReadAccessInstruction,
  listWrite,
  messageSignerSpendSigner,
  ringComputeUnitLimit,
  type RingReadTarget,
} from "../../src/ring/index.js";
import { AnonymousRingState, issueRingAddress } from "../../src/wallet/index.js";
import { currentSlot, liveHarness, signSendAndConfirm, type Actor } from "./live-helpers.js";
import {
  airdrop,
  createRing,
  freshActor,
  indexedKeys,
  indexedRecord,
  requiredEnv,
  ringReadTarget,
  sendInstruction,
  waitForAudited,
} from "./ring-live-helpers.js";

const DEPOSIT = 1_000_000_000n;
const PAYMENT = 250_000_000n;

interface AnonymousRing {
  readonly client: ZolanaClient;
  readonly ringProgramId: Address;
  readonly authority: KeyPairSigner;
  readonly creationEpoch: bigint;
  /** Pays every fee, an anonymous ring refuses a signer holding the hidden owner's key. */
  readonly funder: KeyPairSigner;
  readonly ringRpc: RingRpc;
  readonly target: RingReadTarget;
}

async function anonymousRing(
  kind: Readonly<{ kind: "anonymous" }> | Readonly<{ kind: "anonymousPolicy"; table: RuleTable }>,
): Promise<AnonymousRing> {
  const { client } = await liveHarness("client");
  const ringRpc = new RingRpc(requiredEnv("RING_RPC_URL"), { allowInsecureHttp: true });
  if ((await ringRpc.health()).mode !== "derived")
    throw new Error(
      "the anonymous ring suites need a ring rpc that derives each ring's auditor key",
    );
  const authority = (await freshActor(client)).signer;
  const funder = await generateKeyPairSigner();
  const program = await generateKeyPairSigner();
  const ringProgramId = program.address;
  for (let i = 0; i < 6; i++) await airdrop(client, authority.address);
  await airdrop(client, funder.address);
  await createRing(client, {
    program,
    authority,
    auditor: { releasedBy: ringRpc },
    authorityTransact: false,
    ...kind,
  });
  // Reads are grant only, the ring authority included.
  await sendInstruction(
    client,
    await grantReadAccessInstruction({
      ringProgramId,
      payer: authority,
      authority,
      reader: checkedReaderKey(authority.address),
    }),
    authority,
  );
  const { creationEpoch } = await fetchRingProgramConfig(client, ringProgramId);
  const target = await ringReadTarget(ringRpc, ringProgramId);
  return { client, ringProgramId, authority, creationEpoch, funder, ringRpc, target };
}

/** The ring rpc names the hidden sender and opens the payment and its change. */
async function expectAudited(ring: AnonymousRing, sender: Actor, signature: string): Promise<void> {
  const item = await waitForAudited(ring.ringRpc, ring.target, ring.authority, signature);
  expect(item.sender?.ownerKey).toEqual(sender.keypair.signingPublicKey().ed25519());
  expect(item.payloadErrors).toEqual([]);
  expect(
    item.outputs
      .flatMap(({ opening }) => (opening.kind === "ring" ? [opening.utxo.amount] : []))
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)),
  ).toEqual([PAYMENT, DEPOSIT - PAYMENT]);
}

/** Reads every stream of the ring through the current slot. */
async function syncRing(ring: AnonymousRing, actor: Actor): Promise<void> {
  const slot = await currentSlot(ring.client);
  await syncWallet({
    client: ring.client,
    wallet: actor.wallet,
    keys: actor.keys,
    anonymousRings: {
      slot,
      start: [{ ring: ring.ringProgramId, creationEpoch: ring.creationEpoch }],
    },
    config: { depositPayloadDecoder: customRingDepositPayload, requireSlot: slot },
  });
}

/** Unspent value the wallet holds inside the ring. */
function ringHoldings(actor: Actor, ring: AnonymousRing): bigint {
  return actor.wallet
    .utxos()
    .filter((entry) => !entry.spent && entry.utxo.ringProgramId === ring.ringProgramId)
    .reduce((total, entry) => total + entry.utxo.amount, 0n);
}

/** A member whose own deposit funds its hidden identity on the ring. */
async function depositor(ring: AnonymousRing): Promise<Actor> {
  const sender = await freshActor(ring.client);
  const deposit = await buildRingDepositTransaction({
    client: ring.client,
    ringProgramId: ring.ringProgramId,
    feePayer: ring.funder.address,
    recipient: {
      kind: "anonymous",
      keys: sender.keys,
      state: AnonymousRingState.create(ring.ringProgramId, ring.creationEpoch),
    },
    amount: DEPOSIT,
  });
  await signSendAndConfirm(ring.client, deposit, [ring.funder]);
  await syncRing(ring, sender);
  expect(ringHoldings(sender, ring)).toBe(DEPOSIT);
  return sender;
}

/** The hidden owner signs inside the proof, the funder pays and signs the transaction. */
async function payment(ring: AnonymousRing, sender: Actor, recipient: Actor) {
  const to = await issueRingAddress({
    wallet: recipient.wallet,
    keys: recipient.keys,
    ring: ring.ringProgramId,
    creationEpoch: ring.creationEpoch,
  });
  return async () => {
    const state = sender.wallet.anonymousRing(ring.ringProgramId);
    if (state === undefined) throw new Error("the sync tracks the ring");
    return buildRingTransferTransaction({
      client: ring.client,
      ringProgramId: ring.ringProgramId,
      wallet: sender.wallet,
      keys: sender.keys,
      feePayer: ring.funder.address,
      recipient: to,
      amount: PAYMENT,
      anonymous: { signer: messageSignerSpendSigner(sender.signer), state },
    });
  };
}

describe("anonymous ring", () => {
  it("pays a ring address end to end, the recipient and the sender's change found by sync", async () => {
    const ring = await anonymousRing({ kind: "anonymous" });
    const sender = await depositor(ring);
    const recipient = await freshActor(ring.client);
    const pay = await payment(ring, sender, recipient);
    const signature = await signSendAndConfirm(ring.client, await pay(), [ring.funder]);
    await expectAudited(ring, sender, signature);
    await syncRing(ring, recipient);
    expect(ringHoldings(recipient, ring)).toBe(PAYMENT);
    await syncRing(ring, sender);
    expect(ringHoldings(sender, ring)).toBe(DEPOSIT - PAYMENT);
  }, 900_000);

  it("refuses an unlisted hidden sender before any proof and pays once the authority lists it", async () => {
    const ring = await anonymousRing({
      kind: "anonymousPolicy",
      table: buildRuleTable({
        rules: [
          {
            subject: "sender",
            source: { kind: "lists", present: [ListId.allow], absent: [] },
            guard: { kind: "always" },
          },
        ],
      }),
    });
    const sender = await depositor(ring);
    const recipient = await freshActor(ring.client);
    const pay = await payment(ring, sender, recipient);
    await expect(pay()).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_POLICY_RULE_UNSATISFIED",
    });

    const member = memberOfIdentity(
      sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
    );
    const listed = await new AuthorityListWrite({
      ringProgramId: ring.ringProgramId,
      authority: ring.authority.address,
    })
      .withWrite(member, listWrite({ set: [ListId.allow] }))
      .prove(ring.client);
    await sendInstruction(
      ring.client,
      listed.instruction,
      ring.authority,
      ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
    );
    // The policy reads the record Photon serves, the indexer lags the chain.
    for (let attempt = 0; ; attempt++) {
      const read = await indexedKeys(() => indexedRecord(ring.client, ring.ringProgramId, member));
      if (((read.record?.lists ?? 0n) & recordBit(ListId.allow)) !== 0n) break;
      if (attempt === 240) throw new Error("the allow list write was not indexed");
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    const signature = await signSendAndConfirm(ring.client, await pay(), [ring.funder]);
    await expectAudited(ring, sender, signature);
    await syncRing(ring, recipient);
    expect(ringHoldings(recipient, ring)).toBe(PAYMENT);
  }, 900_000);
});
