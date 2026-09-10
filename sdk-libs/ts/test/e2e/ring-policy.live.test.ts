// Runs against the harness ring of `just test-ts-e2e`, its table pins the
// released rows, allow required for every party, block and frozen forbidden.
import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { createZolanaClient } from "../../src/index.js";
import { decodeTreeHeadRoots } from "../../src/interface/index.js";
import {
  ListId,
  buildRingDepositTransaction,
  buildRingLookupTableTransaction,
  buildRingTransferTransaction,
  fetchRingPolicyConfig,
} from "../../src/ring/index.js";
import { currentSlot, signSendAndConfirm } from "./live-helpers.js";
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
    });
    const authority = await keypairSignerFromFile(requiredEnv("RING_AUTHORITY_KEYPAIR"));
    const policy = await fetchRingPolicyConfig(client, ringProgramId);
    expect(policy.ruleCount).toBe(4);
    expect(policy.entriesTree).toBe(client.tree);

    const sender = await freshActor();
    const recipient = await freshActor();
    await airdrop(client, sender.signer.address);
    const amount = 500_000_000n;
    for (const deposited of [amount * 4n, amount]) {
      const deposit = await buildRingDepositTransaction({
        client,
        ringProgramId,
        feePayer: sender.signer.address,
        recipient: sender.keypair.shieldedAddress(),
        amount: deposited,
      });
      await signSendAndConfirm(client, deposit, [sender.signer]);
    }
    const table = await buildRingLookupTableTransaction({
      client,
      ringProgramId,
      feePayer: sender.signer.address,
    });
    await signSendAndConfirm(client, table.transaction, [sender.signer]);
    const writtenAt = await currentSlot(client);
    while ((await currentSlot(client)) <= writtenAt) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    const transfer = async () => {
      await sync(client, sender);
      return buildRingTransferTransaction({
        client,
        ringProgramId,
        wallet: sender.wallet,
        authority: sender.authority,
        feePayer: sender.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount,
        lookupTable: table.address,
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

    // A frozen sender is refused, the cleared entry admits again through the cleared branch.
    const frozen = await writeList(client, ringProgramId, authority, {
      listId: ListId.frozen,
      tag: senderTag,
      state: "active",
    });
    expect(frozen).toMatchObject({ kind: "transaction", change: "claimed" });
    await refused();
    const unfrozen = await writeList(client, ringProgramId, authority, {
      listId: ListId.frozen,
      tag: senderTag,
      state: "cleared",
    });
    expect(unfrozen).toMatchObject({
      kind: "transaction",
      change: "moved",
      entry: { version: 1n },
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

    // A write the entry already carries makes no transaction.
    const again = await writeList(client, ringProgramId, authority, {
      listId: ListId.allow,
      tag: recipientTag,
      state: "active",
    });
    expect(again.kind).toBe("unchanged");

    // The head the SDK reads off the account is the root the indexer proves the latest entry against.
    const account = await client.getAccount(client.tree);
    if (account === undefined) throw new Error("entries tree missing");
    const heads = decodeTreeHeadRoots(account.data);
    if (again.kind !== "unchanged") throw new Error("unreachable");
    const { proofs } = await client.getMerkleProofs(client.tree, [again.entry.utxoHash]);
    expect(proofs[0]?.rootIndex).toBeLessThanOrEqual(heads.stateRootIndex);
  }, 900_000);
});
