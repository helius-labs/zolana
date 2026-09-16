import { readFile, stat } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createKeyPairSignerFromBytes,
  generateKeyPairSigner,
  type KeyPairSigner,
} from "@solana/kit";
import { describe, expect, it } from "vitest";
import { ClientError } from "../../src/client/error.js";
import type {
  RingSubmissionStatus,
  RingSubmissionTransport,
  SlotReader,
} from "../../src/client/ports.js";
import { wireDecoder } from "../../src/interface/decode.js";
import { postJsonRpc } from "../../src/services/jsonrpc.js";
import { setRingActivationInstruction } from "../../src/interface/instructions/index.js";
import { SOL_MINT } from "../../src/transaction/asset.js";
import { SPL_TOKEN_2022_PROGRAM_ID } from "../../src/interface/program.js";
import { ViewingKey } from "../../src/keypair/viewing-key.js";
import {
  RingProgramBinary,
  RingError,
  RingProgramError,
  deployRingProgram,
  initializeRingConfigInstructions,
  buildRingCreatePolicyTransaction,
  initSppRingConfigInstruction,
  createRingHeadMapRootInstruction,
  createRingKeyRegistryRootInstruction,
  fetchRingKeyRegistryRoot,
  fetchRingSealedKey,
  openRingSealedKey,
  prepareRingKeyRegistration,
  recoverRingMemberNotes,
  createRingDelegateRecoveredSubmission,
  memberOfTag,
  setRingCoSignerInstruction,
  setRingSpendWindowInstruction,
  setRingDelegateInstruction,
  fetchRingHeadMapRoot,
  fetchRingSpendWindow,
  fetchRingCoSigner,
  fetchRingDepositAudit,
  clearRingCoSignerInstruction,
  clearRingSpendWindowInstruction,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
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
import { liveHarness, signSendAndConfirm, type Actor } from "./live-helpers.js";
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
  return settleWithTransport(submission, createKitRingSubmissionTransport(client, signers));
}

async function settleWithTransport(
  submission: RingTransactionSubmission,
  transport: RingSubmissionTransport,
) {
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

async function advanceScopedClock(
  input: Readonly<{
    client: SlotReader;
    rpcUrl: string;
    slot: bigint;
  }>,
): Promise<void> {
  const scope = requiredEnv("ZOLANA_PROCESS_SCOPE_DIR");
  if (!(await stat(scope)).isDirectory()) throw new Error("process scope is absent");
  const port = process.env["ZOLANA_LOCALNET_RPC_PORT"] ?? "8899";
  if (
    !/^[1-9]\d{0,4}$/u.test(port) ||
    Number(port) > 65_535 ||
    input.rpcUrl !== `http://127.0.0.1:${port}`
  )
    throw new Error("RPC must match the scoped runtime port");
  if (input.slot > BigInt(Number.MAX_SAFE_INTEGER) || input.slot <= (await input.client.getSlot()))
    throw new Error("target slot must be a safe integer after the current slot");
  const decoder = wireDecoder((path) => new Error(`invalid local clock response at ${path}`));
  const result = decoder.record(
    await postJsonRpc(
      {
        fetch: globalThis.fetch,
        url: new URL(input.rpcUrl),
        rpcMethod: "surfnet_timeTravel",
        params: [{ absoluteSlot: Number(input.slot) }],
        id: "ring-controls-window",
        maxRequestBytes: 1024,
        maxResponseBytes: 4096,
      },
      { timeoutMs: 10_000 },
    ),
    "result",
  );
  if (decoder.integer(result["absoluteSlot"], "absoluteSlot") !== input.slot)
    throw new Error("local clock returned a different slot");
  const deadline = Date.now() + 10_000;
  while ((await input.client.getSlot({ timeoutMs: 1000 })) < input.slot) {
    if (Date.now() > deadline) throw new Error("local clock did not advance");
    await new Promise((resolve) => setTimeout(resolve, 100));
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
        ![
          "CLIENT_HEAD_MAP_OUT_OF_SYNC",
          "CLIENT_HEAD_ROOT_CHANGED",
          "CLIENT_KEY_REGISTRY_OUT_OF_SYNC",
          "CLIENT_KEY_REGISTRY_ROOT_CHANGED",
        ].includes(code) ||
        Date.now() > deadline
      )
        throw cause;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

describe("fresh ring controls", () => {
  it("registers compressed state, co-signs and audits outflow, and delegates existing and recovered notes without charging velocity", async () => {
    const harness = await liveHarness();
    if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(harness.rpcUrl).hostname))
      throw new Error("controls fixture runs on a local validator only");
    const { client } = harness;
    // Photon replays every surfpool slot after a clock jump, so the window stays short.
    const windowSlots = 1_000n;
    await airdrop(client, harness.testAuthority.address);
    const authority = (await freshActor(client)).signer;
    const delegate = (await freshActor(client)).signer;
    const cosigner = (await freshActor(client)).signer;
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
      for (const instruction of await initializeRingConfigInstructions({
        ringProgramId,
        payer: authority,
        authority,
        auditorPublicKey: auditor.publicKey(),
        hasPolicy: true,
        depositAudit: true,
      }))
        await sendInstruction(client, instruction, authority);
      expect(await fetchRingDepositAudit(client, ringProgramId)).toBe(true);
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
            windowSlots,
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
        await createRingKeyRegistryRootInstruction({ ringProgramId, payer: authority, authority }),
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
          scope: RING_COSIGN_WITHDRAWALS,
          thresholds: [{ mint: SOL_MINT, above: 100_000_000n }],
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
          windowSlots,
          depositCap: 3_000_000_000n,
          withdrawalCap: 100_000_000n,
        }),
        authority,
      );
      const sender = await freshActor(client),
        recipient = await freshActor(client);
      await airdrop(client, sender.signer.address);
      await enrolInAllow(client, ringProgramId, authority, [sender, recipient]);
      // A fresh window from here, so the counters below never straddle a natural rollover.
      await advanceScopedClock({
        client,
        rpcUrl: harness.rpcUrl,
        slot: ((await client.getSlot()) / windowSlots + 1n) * windowSlots,
      });
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
      const depositKey = sender.keypair.nullifierKey();
      try {
        const recoveredDeposits = await recoverRingMemberNotes({
          client,
          ringProgramId,
          auditor,
          source: sender.keypair.shieldedAddress(),
          nullifierKey: depositKey,
          assets: sender.wallet.registry,
          resolveTreeId: (tree) => {
            if (tree !== client.tree) throw new Error(`unknown tree ${tree}`);
            return client.treeId;
          },
        });
        expect(recoveredDeposits.unopened).toEqual([]);
        expect(recoveredDeposits.unsupportedDeposits).toEqual([]);
        const deposits = sender.wallet
          .utxos()
          .filter((note) => !note.spent && note.utxo.ringProgramId === ringProgramId);
        expect(recoveredDeposits.notes.map((note) => note.outputContext.hash)).toEqual(
          expect.arrayContaining(deposits.map((note) => note.outputContext.hash)),
        );
        expect(recoveredDeposits.notes).toHaveLength(3);
        for (const [asset, amount] of [
          [SOL_MINT, 2_000_000_000n],
          [harness.mint, 1000n],
          [harness.token2022Mint, 1000n],
        ] as const) {
          expect(
            deposits.filter((note) => note.utxo.asset === asset).map((note) => note.utxo.amount),
          ).toEqual([amount]);
          expect(
            recoveredDeposits.notes
              .filter((note) => note.utxo.asset === asset)
              .map((note) => note.utxo.amount),
          ).toEqual([amount]);
        }
      } finally {
        depositKey.destroy();
      }
      const transfer = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        keys: sender.keys,
        feePayer: sender.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount: 350_000_000n,
      };
      await settle(
        await indexedHead(() => createRingTransferSubmission({ ...transfer, amount: 50_000_000n })),
        client,
        [sender.signer],
      );
      await sync(client, sender);
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
        readRingVelocityState({
          client,
          ringProgramId,
          member: sender.keypair.shieldedAddress(),
          keys: sender.keys,
        });
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
            keys: sender.keys,
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
      const beforeDelegate = await indexedHead(state);
      const move = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        source: sender.keys,
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
      const nullifierKey = sender.keypair.nullifierKey();
      try {
        const enrolment = await indexedHead(() =>
          prepareRingKeyRegistration({
            client,
            ringProgramId,
            member: { address: sender.keypair.shieldedAddress(), nullifierKey },
          }),
        );
        if (enrolment.kind !== "pending") throw new Error("fresh sender already enrolled");
        await settle(enrolment.submission, client, [sender.signer]);
      } finally {
        nullifierKey.destroy();
      }
      expect((await fetchRingKeyRegistryRoot(client, ringProgramId)).nextIndex).toBe(2n);
      const sealed = await indexedHead(() =>
        fetchRingSealedKey({
          client,
          ringProgramId,
          member: memberOfTag(sender.keypair.shieldedAddress().confidentialViewTag()),
        }),
      );
      const recoveredKey = openRingSealedKey(sealed, auditor);
      try {
        expect(recoveredKey.publicKey()).toEqual(sender.keypair.nullifierPublicKey());
        const recovered = await recoverRingMemberNotes({
          client,
          ringProgramId,
          auditor,
          source: sender.keypair.shieldedAddress(),
          nullifierKey: recoveredKey,
          assets: sender.wallet.registry,
          resolveTreeId: (tree) => {
            if (tree !== client.tree) throw new Error(`unknown tree ${tree}`);
            return client.treeId;
          },
        });
        expect(recovered.unopened).toEqual([]);
        expect(recovered.unsupportedDeposits).toEqual([]);
        const heldSol = recovered.notes
          .filter((note) => note.utxo.asset === SOL_MINT)
          .reduce((total, note) => total + note.utxo.amount, 0n);
        expect(heldSol).toBe(800_000_000n);
        await settle(
          await createRingDelegateRecoveredSubmission({
            client,
            ringProgramId,
            source: sender.keypair.shieldedAddress(),
            nullifierKey: recoveredKey,
            notes: recovered.notes,
            delegate,
            cosigner,
            feePayer: delegate.address,
            outputs: [
              {
                recipient: recipient.keypair.shieldedAddress(),
                asset: SOL_MINT,
                amount: 100_000_000n,
              },
            ],
          }),
          client,
          [delegate, cosigner],
        );
      } finally {
        recoveredKey.destroy();
      }
      await sync(client, sender);
      await sync(client, recipient);
      expect(
        sender.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === SOL_MINT)?.amount,
      ).toBe(700_000_000n);
      expect(
        recipient.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === SOL_MINT)?.amount,
      ).toBe(1_200_000_000n);
      await settle(
        await indexedHead(() =>
          createRingWithdrawalSubmission({
            client,
            ringProgramId,
            wallet: sender.wallet,
            keys: sender.keys,
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
      const solBalance = (actor: Actor) =>
        actor.wallet
          .ringBalances()
          .find((ring) => ring.ringProgramId === ringProgramId)
          ?.assets.find((balance) => balance.mint === SOL_MINT)?.amount ?? 0n;
      const beforeBalances = { sender: solBalance(sender), recipient: solBalance(recipient) };
      const beforeRoot = await fetchRingHeadMapRoot(client, ringProgramId);
      const oldWindow = (await client.getSlot()) / windowSlots;
      expect(drained.live.record.window).toBe(oldWindow);
      const rolloverAmount = 50_000_000n;
      const rollover = await indexedHead(() =>
        createRingTransferSubmission({ ...transfer, amount: rolloverAmount, cosigner }),
      );
      expect((await client.getSlot()) / windowSlots).toBe(oldWindow);
      const reservedNotes = () =>
        sender.wallet
          ._reservationEntries()
          .map((entry) => entry.utxoHashes.map((hash) => new Uint8Array(hash)));
      const retainedNotes = reservedNotes();
      expect(retainedNotes).toHaveLength(1);
      expect(retainedNotes[0]?.length).toBeGreaterThan(0);
      const signedNotes: Uint8Array[][][] = [];
      const sendResults: (RingSubmissionStatus | undefined)[] = [];
      const transport = createKitRingSubmissionTransport(client, [sender.signer, cosigner]);
      const observedTransport: RingSubmissionTransport = {
        ...transport,
        sign: async (transaction, context) => {
          signedNotes.push(reservedNotes());
          return transport.sign(transaction, context);
        },
        send: async (transaction, context) => {
          const result = await transport.send(transaction, context);
          sendResults.push(result);
          return result;
        },
      };
      await advanceScopedClock({
        client,
        rpcUrl: harness.rpcUrl,
        slot: (oldWindow + 1n) * windowSlots,
      });
      const settled = await settleWithTransport(rollover, observedTransport);
      expect(settled.attempts).toBe(2);
      expect(sendResults).toEqual([
        {
          kind: "failed",
          instructionIndex: 0,
          customCode: RingProgramError.proofVerificationFailed,
        },
        undefined,
      ]);
      expect(signedNotes).toEqual([retainedNotes, retainedNotes]);
      const reset = await indexedHead(state);
      if (reset.counters === undefined || reset.head === undefined)
        throw new Error("rollover record missing");
      expect(reset.live.record.version).toBe(drained.live.record.version + 1n);
      expect(reset.live.record.window).toBe(oldWindow + 1n);
      expect(reset.live.txSignature).toBe(settled.signature);
      expect(reset.live.nullifier).not.toEqual(drained.live.nullifier);
      expect(reset.head.nullifier).toEqual(reset.live.nullifier);
      expect(spendCountersSpent(reset.counters, memberOfAsset(SOL_MINT))).toBe(rolloverAmount);
      expect(spendCountersSpent(reset.counters, memberOfAsset(harness.mint))).toBe(0n);
      expect(spendCountersSpent(reset.counters, memberOfAsset(harness.token2022Mint))).toBe(0n);
      const afterRoot = await fetchRingHeadMapRoot(client, ringProgramId);
      expect(afterRoot.root).toEqual(reset.head.root);
      expect(afterRoot.root).not.toEqual(beforeRoot.root);
      expect(afterRoot.nextIndex).toBe(beforeRoot.nextIndex);
      await sync(client, sender);
      await sync(client, recipient);
      expect(solBalance(sender)).toBe(beforeBalances.sender - rolloverAmount);
      expect(solBalance(recipient)).toBe(beforeBalances.recipient + rolloverAmount);
      await expect(rollover.send(observedTransport)).rejects.toMatchObject({
        code: "RING_SUBMISSION_PENDING",
      });
      expect(sendResults).toHaveLength(2);
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
