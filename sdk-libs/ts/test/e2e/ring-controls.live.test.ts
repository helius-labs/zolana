import { readFile } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createKeyPairSignerFromBytes,
  generateKeyPairSigner,
  type KeyPairSigner,
} from "@solana/kit";
import { describe, expect, it } from "vitest";
import { ClientError } from "../../src/client/error.js";
import { setRingActivationInstruction } from "../../src/interface/instructions/index.js";
import { SOL_MINT } from "../../src/transaction/asset.js";
import { SPL_TOKEN_2022_PROGRAM_ID } from "../../src/interface/program.js";
import { ViewingKey } from "../../src/keypair/viewing-key.js";
import {
  RingProgramBinary,
  RingError,
  deployRingProgram,
  createRingConfigInstruction,
  buildRingCreatePolicyTransaction,
  initSppRingConfigInstruction,
  createRingHeadMapRootInstruction,
  setRingCoSignerInstruction,
  setRingSpendWindowInstruction,
  setRingDelegateInstruction,
  fetchRingHeadMapRoot,
  fetchRingSpendWindow,
  fetchRingCoSigner,
  clearRingCoSignerInstruction,
  clearRingSpendWindowInstruction,
  RING_COSIGN_TRANSFERS,
  ListId,
  memberOfAsset,
  spendCountersSpent,
  ringAuthAddress,
  buildRuleTable,
  prepareRingSpendRegistration,
  createKitRingSubmissionTransport,
  createRingTransferSubmission,
  createRingWithdrawalSubmission,
  createRingDelegateSubmission,
  buildRingTransferTransaction,
  buildRingDelegateTransferTransaction,
  buildRingDepositTransaction,
  readRingVelocityState,
  auditRingTransaction,
  type RingTransactionSubmission,
} from "../../src/ring/index.js";
import { liveHarness, signSendAndConfirm } from "./live-helpers.js";
import {
  airdrop,
  enrolInAllow,
  freshActor,
  requiredEnv,
  sendInstruction,
  sync,
  writeList,
} from "./ring-live-helpers.js";

async function settle(
  submission: RingTransactionSubmission,
  client: Awaited<ReturnType<typeof liveHarness>>["client"],
  signers: readonly KeyPairSigner[],
) {
  const transport = createKitRingSubmissionTransport(client, signers);
  const deadline = Date.now() + 180_000;
  for (;;) {
    const result = await submission.send(transport);
    if (result.kind === "confirmed") return result;
    if (result.kind === "failed")
      throw new Error(`controls transaction failed (${result.signature})`);
    if (Date.now() > deadline)
      throw new Error(`controls transaction unresolved (${result.signature})`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

async function indexedHead<T>(read: () => Promise<T>): Promise<T> {
  const deadline = Date.now() + 120_000;
  for (;;) {
    try {
      return await read();
    } catch (cause) {
      const code =
        cause instanceof ClientError
          ? cause.code
          : cause instanceof RingError
            ? cause.causeCode
            : undefined;
      if (
        code === undefined ||
        !["CLIENT_HEAD_MAP_OUT_OF_SYNC", "CLIENT_HEAD_ROOT_CHANGED"].includes(code) ||
        Date.now() > deadline
      )
        throw cause;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

describe("fresh ring controls", () => {
  it("registers compressed state, co-signs and audits outflow, and delegates SOL plus both token programs without charging velocity", async () => {
    const harness = await liveHarness();
    if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(harness.rpcUrl).hostname))
      throw new Error("controls fixture runs on a local validator only");
    const { client } = harness;
    await airdrop(client, harness.testAuthority.address);
    const authority = (await freshActor()).signer;
    const delegate = (await freshActor()).signer;
    const cosigner = (await freshActor()).signer;
    const program = await generateKeyPairSigner();
    const ringProgramId = program.address;
    const auditor = ViewingKey.generate();
    try {
      for (let i = 0; i < 6; i++) await airdrop(client, authority.address);
      await airdrop(client, delegate.address);
      await deployRingProgram({
        client,
        ringProgramId,
        program,
        payer: authority,
        authority,
        binary: RingProgramBinary.parse(
          new Uint8Array(await readFile(requiredEnv("RING_PROGRAM_SO"))),
        ),
      });
      await sendInstruction(
        client,
        await createRingConfigInstruction({
          ringProgramId,
          payer: authority,
          authority,
          auditorPublicKey: auditor.publicKey(),
          hasPolicy: true,
        }),
        authority,
      );
      await signSendAndConfirm(
        client,
        await buildRingCreatePolicyTransaction({
          client,
          ringProgramId,
          payer: authority.address,
          authority: authority.address,
          entriesTree: client.tree,
          table: buildRuleTable({
            rules: [
              {
                subject: "outputOwner",
                source: { kind: "lists", present: [ListId.allow], absent: [] },
                guard: { kind: "always" },
              },
              {
                subject: "sender",
                source: { kind: "lists", present: [], absent: [ListId.frozen] },
                guard: { kind: "always" },
              },
              {
                subject: "outputOwner",
                source: { kind: "lists", present: [], absent: [ListId.block] },
                guard: { kind: "always" },
              },
            ],
            windowSlots: 100_000n,
            velocity: [
              { asset: memberOfAsset(SOL_MINT), cap: 1_000_000_000n, cosignAbove: 300_000_000n },
              { asset: memberOfAsset(harness.mint), cap: 500n, cosignAbove: 90n },
              { asset: memberOfAsset(harness.token2022Mint), cap: 800n, cosignAbove: 190n },
            ],
          }),
        }),
        [authority],
      );
      await sendInstruction(
        client,
        await createRingHeadMapRootInstruction({ ringProgramId, payer: authority, authority }),
        authority,
      );
      await sendInstruction(
        client,
        await initSppRingConfigInstruction({
          ringProgramId,
          payer: authority,
          authority,
          hasPolicy: true,
        }),
        authority,
      );
      // Localnet snapshots require the fixed public governance seed.
      const governanceSeed = new TextEncoder().encode("zolana localnet snapshot authori");
      const governance = await createKeyPairSignerFromBytes(
        Uint8Array.of(...governanceSeed, ...ed25519.getPublicKey(governanceSeed)),
      );
      await airdrop(client, governance.address);
      await sendInstruction(
        client,
        await setRingActivationInstruction({
          authority: governance,
          ringConfig: await ringAuthAddress(ringProgramId),
          activated: true,
          ringAuthorityTransactIsEnabled: true,
        }),
        governance,
      );
      await sendInstruction(
        client,
        await setRingDelegateInstruction({
          ringProgramId,
          payer: authority,
          authority,
          delegate: delegate.address,
        }),
        authority,
      );
      await sendInstruction(
        client,
        await setRingCoSignerInstruction({
          ringProgramId,
          payer: authority,
          authority,
          signer: cosigner.address,
          scope: RING_COSIGN_TRANSFERS,
        }),
        authority,
      );
      await sendInstruction(
        client,
        await setRingSpendWindowInstruction({
          ringProgramId,
          payer: authority,
          authority,
          mint: SOL_MINT,
          windowSlots: 100_000n,
          depositCap: 3_000_000_000n,
          withdrawalCap: 100_000_000n,
        }),
        authority,
      );
      const sender = await freshActor(),
        recipient = await freshActor();
      await airdrop(client, sender.signer.address);
      await enrolInAllow(client, ringProgramId, authority, [sender, recipient]);
      const registration = await indexedHead(() =>
        prepareRingSpendRegistration({ client, ringProgramId, payer: sender.signer }),
      );
      if (registration.kind !== "pending") throw new Error("fresh sender already registered");
      await settle(registration.submission, client, [sender.signer]);
      const firstRoot = await fetchRingHeadMapRoot(client, ringProgramId);
      expect(firstRoot.nextIndex).toBe(2n);
      expect(
        (
          await indexedHead(() =>
            prepareRingSpendRegistration({ client, ringProgramId, payer: sender.signer }),
          )
        ).kind,
      ).toBe("registered");
      await signSendAndConfirm(
        client,
        await buildRingDepositTransaction({
          client,
          ringProgramId,
          feePayer: sender.signer.address,
          recipient: sender.keypair.shieldedAddress(),
          amount: 2_000_000_000n,
        }),
        [sender.signer],
      );
      for (const [asset, splTokenAccount, splTokenProgram] of [
        [harness.mint, harness.testTokenAccount, undefined],
        [harness.token2022Mint, harness.testToken2022Account, SPL_TOKEN_2022_PROGRAM_ID],
      ] as const) {
        await signSendAndConfirm(
          client,
          await buildRingDepositTransaction({
            client,
            ringProgramId,
            feePayer: harness.testAuthority.address,
            recipient: sender.keypair.shieldedAddress(),
            asset,
            amount: 1000n,
            splTokenAccount,
            ...(splTokenProgram === undefined ? {} : { splTokenProgram }),
          }),
          [harness.testAuthority],
        );
      }
      await sync(client, sender);
      const transfer = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        authority: sender.authority,
        feePayer: sender.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount: 400_000_000n,
      };
      await expect(indexedHead(() => buildRingTransferTransaction(transfer))).rejects.toMatchObject(
        { code: "RING_BUILD_TRANSFER", causeCode: "RING_COSIGNER_REQUIRED" },
      );
      await settle(
        await indexedHead(() => createRingTransferSubmission({ ...transfer, cosigner })),
        client,
        [sender.signer, cosigner],
      );
      await sync(client, sender);
      const state = () =>
        sender.authority.withSpendSession((session) =>
          readRingVelocityState({
            client,
            ringProgramId,
            member: sender.keypair.shieldedAddress(),
            session,
          }),
        );
      const afterTransfer = await indexedHead(state);
      expect(afterTransfer.counters?.spent[0]).toBe(400_000_000n);
      if (afterTransfer.head === undefined) throw new Error("head witness missing");
      const audited = auditRingTransaction({
        auditor,
        transaction: afterTransfer.head.record.transaction,
        assets: sender.wallet.registry,
      });
      expect(audited.spendRecords[0]?.counters?.spent[0]).toBe(400_000_000n);
      await settle(
        await indexedHead(() =>
          createRingWithdrawalSubmission({
            client,
            ringProgramId,
            wallet: sender.wallet,
            authority: sender.authority,
            feePayer: sender.signer.address,
            recipient: sender.signer.address,
            amount: 100_000_000n,
            cosigner,
          }),
        ),
        client,
        [sender.signer, cosigner],
      );
      expect((await fetchRingSpendWindow(client, ringProgramId, SOL_MINT))?.withdrawn).toBe(
        100_000_000n,
      );
      await sync(client, sender);
      await expect(
        indexedHead(() =>
          buildRingTransferTransaction({ ...transfer, amount: 600_000_000n, cosigner }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_VELOCITY_CAP_EXCEEDED",
      });
      for (const [asset, amount, rejected] of [
        [harness.mint, 100n, 401n],
        [harness.token2022Mint, 200n, 601n],
      ] as const) {
        await settle(
          await indexedHead(() =>
            createRingTransferSubmission({ ...transfer, asset, amount, cosigner }),
          ),
          client,
          [sender.signer, cosigner],
        );
        await sync(client, sender);
        const charged = await indexedHead(state);
        if (charged.counters === undefined || charged.head === undefined)
          throw new Error("charged record missing");
        expect(spendCountersSpent(charged.counters, memberOfAsset(asset))).toBe(amount);
        expect(spendCountersSpent(charged.counters, memberOfAsset(SOL_MINT))).toBe(500_000_000n);
        expect(spendCountersSpent(charged.counters, memberOfAsset(harness.mint))).toBe(100n);
        const audit = auditRingTransaction({
          auditor,
          transaction: charged.head.record.transaction,
          assets: sender.wallet.registry,
        });
        expect(audit.spendRecords[0]?.counters).toEqual(charged.counters);
        await expect(
          indexedHead(() =>
            buildRingTransferTransaction({ ...transfer, asset, amount: rejected, cosigner }),
          ),
        ).rejects.toMatchObject({
          code: "RING_BUILD_TRANSFER",
          causeCode: "RING_VELOCITY_CAP_EXCEEDED",
        });
      }
      const beforeDelegate = await indexedHead(state);
      const move = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        source: sender.authority,
        delegate,
        feePayer: delegate.address,
        outputs: [
          { recipient: recipient.keypair.shieldedAddress(), asset: SOL_MINT, amount: 700_000_000n },
        ],
      };
      await expect(buildRingDelegateTransferTransaction(move)).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_COSIGNER_REQUIRED",
      });
      await settle(await createRingDelegateSubmission({ ...move, cosigner }), client, [
        delegate,
        cosigner,
      ]);
      await sync(client, sender);
      await settle(
        await createRingDelegateSubmission({
          ...move,
          cosigner,
          outputs: [
            { recipient: recipient.keypair.shieldedAddress(), asset: harness.mint, amount: 400n },
            {
              recipient: recipient.keypair.shieldedAddress(),
              asset: harness.token2022Mint,
              amount: 600n,
            },
          ],
        }),
        client,
        [delegate, cosigner],
      );
      const afterDelegate = await indexedHead(state);
      expect(afterDelegate.live.nullifier).toEqual(beforeDelegate.live.nullifier);
      expect(afterDelegate.counters).toEqual(beforeDelegate.counters);
      await sync(client, sender);
      await sync(client, recipient);
      for (const [asset, sourceAmount, recipientAmount] of [
        [SOL_MINT, 800_000_000n, 1_100_000_000n],
        [harness.mint, 500n, 500n],
        [harness.token2022Mint, 200n, 800n],
      ] as const) {
        expect(
          sender.wallet
            .ringBalances()
            .find((ring) => ring.ringProgramId === ringProgramId)
            ?.assets.find((balance) => balance.mint === asset)?.amount,
        ).toBe(sourceAmount);
        expect(
          recipient.wallet
            .ringBalances()
            .find((ring) => ring.ringProgramId === ringProgramId)
            ?.assets.find((balance) => balance.mint === asset)?.amount,
        ).toBe(recipientAmount);
      }
      await settle(
        await indexedHead(() =>
          createRingWithdrawalSubmission({
            client,
            ringProgramId,
            wallet: sender.wallet,
            authority: sender.authority,
            feePayer: authority.address,
            recipient: authority.address,
            asset: harness.token2022Mint,
            splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
            amount: 200n,
            cosigner,
          }),
        ),
        client,
        [sender.signer, authority, cosigner],
      );
      await sync(client, sender);
      const drained = await indexedHead(state);
      if (drained.counters === undefined) throw new Error("drained counters missing");
      expect(spendCountersSpent(drained.counters, memberOfAsset(harness.token2022Mint))).toBe(400n);
      expect(
        sender.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === harness.token2022Mint)?.amount ?? 0n,
      ).toBe(0n);
      await writeList(client, ringProgramId, authority, {
        listId: ListId.block,
        tag: recipient.keypair.shieldedAddress().confidentialViewTag(),
        state: "active",
      });
      await expect(
        buildRingDelegateTransferTransaction({
          ...move,
          cosigner,
          outputs: [{ ...move.outputs[0]!, amount: 1n }],
        }),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_POLICY_RULE_UNSATISFIED",
      });
      await sendInstruction(
        client,
        await clearRingCoSignerInstruction({
          ringProgramId,
          authority,
          rentRecipient: authority.address,
        }),
        authority,
      );
      await sendInstruction(
        client,
        await clearRingSpendWindowInstruction({
          ringProgramId,
          authority,
          mint: SOL_MINT,
          rentRecipient: authority.address,
        }),
        authority,
      );
      expect(await fetchRingCoSigner(client, ringProgramId)).toBeUndefined();
      expect(await fetchRingSpendWindow(client, ringProgramId, SOL_MINT)).toBeUndefined();
    } finally {
      auditor.destroy();
    }
  }, 1_800_000);
});
