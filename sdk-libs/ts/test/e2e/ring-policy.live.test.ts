// Runs against the harness ring of `just test-ts-e2e`, its table pins the
// released rows, allow required for every party, block and frozen forbidden.
import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { createZolanaClient } from "../../src/index.js";
import { ListId, memberOfTag } from "../../src/ring/advanced.js";
import {
  buildRingDepositTransaction,
  buildRingTransferTransaction,
  fetchRingPolicyConfig,
  fetchRingMemberRegistryRoot,
} from "../../src/ring/index.js";
import { signSendAndConfirm } from "./live-helpers.js";
import {
  airdrop,
  enrolInAllow,
  freshActor,
  keypairSignerFromFile,
  requiredEnv,
  sync,
  writeList,
} from "./ring-live-helpers.js";

describe("ring policy", () => {
  it("frozen senders and blocked recipients are refused until cleared", async () => {
    const ringProgramId = address(requiredEnv("RING_PROGRAM_ID"));
    const client = await createZolanaClient({
      solanaRpcUrl: requiredEnv("ZOLANA_LOCALNET_URL"),
      indexerUrl: requiredEnv("ZOLANA_INDEXER_URL"),
      proverUrl: requiredEnv("ZOLANA_PROVER_URL"),
      tree: address(requiredEnv("ZOLANA_TREE")),
      proofDataSource: "client",
    });
    const authority = await keypairSignerFromFile(requiredEnv("RING_AUTHORITY_KEYPAIR"));
    const policy = await fetchRingPolicyConfig(client, ringProgramId);
    expect(policy.ruleCount).toBe(4);
    expect(policy.addressTree).toBe(client.tree);

    const sender = await freshActor(client);
    const recipient = await freshActor(client);
    await airdrop(client, sender.signer.address);
    const amount = 500_000_000n;
    for (const deposited of [amount * 4n, amount]) {
      const deposit = await buildRingDepositTransaction({
        client,
        ringProgramId,
        depositor: sender.signer.address,
        feePayer: sender.signer.address,
        recipient: sender.keypair.shieldedAddress(),
        amount: deposited,
      });
      await signSendAndConfirm(client, deposit, [sender.signer]);
    }
    const transfer = async () => {
      await sync(client, sender);
      return buildRingTransferTransaction({
        client,
        ringProgramId,
        wallet: sender.wallet,
        keys: sender.keys,
        feePayer: sender.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount,
      });
    };
    const refused = async () =>
      expect(transfer()).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_POLICY_RULE_UNSATISFIED",
      });
    const senderTag = sender.keypair.shieldedAddress().confidentialViewTag();
    const recipientTag = recipient.keypair.shieldedAddress().confidentialViewTag();

    // Neither party is allowed yet.
    await refused();
    await enrolInAllow(client, ringProgramId, authority, [sender, recipient]);
    await signSendAndConfirm(client, await transfer(), [sender.signer]);

    // A frozen sender is refused until its frozen-list bit is cleared.
    const frozen = await writeList(client, ringProgramId, authority, {
      listId: ListId.frozen,
      tag: senderTag,
      state: "active",
    });
    expect(frozen).toMatchObject({
      kind: "transaction",
      items: [{ member: memberOfTag(senderTag) }],
    });
    await refused();
    const unfrozen = await writeList(client, ringProgramId, authority, {
      listId: ListId.frozen,
      tag: senderTag,
      state: "cleared",
    });
    expect(unfrozen).toMatchObject({
      kind: "transaction",
      items: [{ member: memberOfTag(senderTag) }],
    });
    await signSendAndConfirm(client, await transfer(), [sender.signer]);

    // A blocked recipient is refused even while allowed.
    await writeList(client, ringProgramId, authority, {
      listId: ListId.block,
      tag: recipientTag,
      state: "active",
    });
    await refused();
    await writeList(client, ringProgramId, authority, {
      listId: ListId.block,
      tag: recipientTag,
      state: "cleared",
    });
    await signSendAndConfirm(client, await transfer(), [sender.signer]);

    // Setting an existing membership bit makes no transaction.
    const again = await writeList(client, ringProgramId, authority, {
      listId: ListId.allow,
      tag: recipientTag,
      state: "active",
    });
    expect(again.kind).toBe("unchanged");

    // The member proof authenticates the same root the ring account currently stores.
    const root = await fetchRingMemberRegistryRoot(client, ringProgramId);
    if (again.kind !== "unchanged") throw new Error("unreachable");
    expect(again.records[0]?.opening.present).toBe(true);
    expect(again.records[0]?.registry.root).toEqual(root.root);
    expect(again.records[0]?.registry.nextIndex).toBe(root.nextIndex);
  }, 900_000);
});
