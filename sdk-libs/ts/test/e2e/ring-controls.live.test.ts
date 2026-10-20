import { X25519Keypair } from "../../src/keypair/x25519.js";
import { readFile } from "node:fs/promises";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  createKeyPairSignerFromBytes,
  generateKeyPairSigner,
  getCompiledTransactionMessageDecoder,
  decompileTransactionMessage,
  type KeyPairSigner,
} from "@solana/kit";
import { describe, expect, it } from "vitest";
import { ClientError } from "../../src/client/error.js";
import type { RingSubmissionTransport } from "../../src/client/ports.js";
import { setRingActivationInstruction } from "../../src/interface/instructions/index.js";
import { SOL_MINT } from "../../src/transaction/asset.js";
import { SPL_TOKEN_2022_PROGRAM_ID } from "../../src/interface/program.js";
import { ShieldedAddress } from "../../src/keypair/shielded.js";

import { ZERO_NULLIFIER_PK } from "../../src/ring/policy.js";
import {
  RingProgramBinary,
  RingError,
  deployRingProgram,
  initializeRingConfigInstructions,
  buildRingCreatePolicyTransaction,
  initSppRingConfigInstruction,
  createRingMemberRegistryRootInstruction,
  fetchRingMemberRegistryRoot,
  fetchRingSealedKey,
  openRingSealedKey,
  prepareRingKeyRegistration,
  recoverRingMemberNotes,
  createRingDelegateRecoveredSubmission,
  setRingCoSignerInstruction,
  setRingDelegateInstruction,
  fetchRingCoSigner,
  fetchRingDepositAudit,
  fetchRingProgramConfig,
  clearRingCoSignerInstruction,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  ringAuthAddress,
  createKitRingSubmissionTransport,
  createRingTransferSubmission,
  createRingMergeSubmission,
  createRingWithdrawalSubmission,
  createRingDelegateSubmission,
  buildRingTransferTransaction,
  buildRingDelegateTransferTransaction,
  buildRingDepositTransaction,
  type RingTransactionSubmission,
} from "../../src/ring/index.js";
import { ListId, buildRuleTable, memberOfAsset, memberOfTag } from "../../src/ring/advanced.js";
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

async function indexedKeys<T>(read: () => Promise<T>): Promise<T> {
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
        !["CLIENT_MEMBER_REGISTRY_OUT_OF_SYNC", "CLIENT_MEMBER_REGISTRY_ROOT_CHANGED"].includes(
          code,
        ) ||
        Date.now() > deadline
      )
        throw cause;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

describe.each(["client", "prover"] as const)("controls %s", (proofDataSource) => {
  it("escrows keys, enforces policy and recovers notes", async () => {
    const harness = await liveHarness(proofDataSource);
    if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(harness.rpcUrl).hostname))
      throw new Error("controls fixture runs on a local validator only");
    const { client } = harness;
    await airdrop(client, harness.testAuthority.address);
    const authority = (await freshActor(client)).signer;
    const delegate = (await freshActor(client)).signer;
    const cosigner = (await freshActor(client)).signer;
    const program = await generateKeyPairSigner();
    const ringProgramId = program.address;
    const auditor = X25519Keypair.generate();
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
      }))
        await sendInstruction(client, instruction, authority);
      expect(await fetchRingDepositAudit(client, ringProgramId)).toBe(false);
      await signSendAndConfirm(
        client,
        await buildRingCreatePolicyTransaction({
          client,
          ringProgramId,
          payer: authority.address,
          authority: authority.address,
          addressTree: client.tree,
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
            limits: [
              {
                asset: memberOfAsset(SOL_MINT),
                cap: 500_000_000n,
                cosignAbove: 300_000_000n,
              },
              {
                asset: memberOfAsset(harness.mint),
                cap: 300n,
                cosignAbove: 90n,
              },
              {
                asset: memberOfAsset(harness.token2022Mint),
                cap: 500n,
                cosignAbove: 190n,
              },
            ],
          }),
        }),
        [authority],
      );
      await sendInstruction(
        client,
        await createRingMemberRegistryRootInstruction({
          ringProgramId,
          payer: authority,
          authority,
        }),
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
      expect((await fetchRingProgramConfig(client, ringProgramId)).keyEscrow).toBe(true);
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
      const sender = await freshActor(client),
        recipient = await freshActor(client),
        unregistered = await freshActor(client);
      await airdrop(client, sender.signer.address);
      await airdrop(client, recipient.signer.address);
      await enrolInAllow(client, ringProgramId, authority, [sender, recipient, unregistered]);
      const listedRoot = await fetchRingMemberRegistryRoot(client, ringProgramId);
      // The sentinel and all three listed members already occupy registry leaves.
      expect(listedRoot.nextIndex).toBe(4n);
      // Key escrow is on, every note owner registers before receiving.
      for (const member of [sender, recipient]) {
        const nullifierKey = member.keypair.nullifierKey();
        try {
          const enrolment = await indexedKeys(() =>
            prepareRingKeyRegistration({
              client,
              ringProgramId,
              member: {
                address: member.keypair.shieldedAddress(),
                nullifierKey,
              },
            }),
          );
          if (enrolment.kind !== "pending") throw new Error("fresh member already enrolled");
          await settle(enrolment.submission, client, [member.signer]);
        } finally {
          nullifierKey.destroy();
        }
      }
      // Registering keys updates existing list records without allocating new leaves.
      expect((await fetchRingMemberRegistryRoot(client, ringProgramId)).nextIndex).toBe(
        listedRoot.nextIndex,
      );
      const registered = recipient.keypair.shieldedAddress();
      const zeroKey = ShieldedAddress.fromPublicKeys(
        registered.signingPublicKey,
        ZERO_NULLIFIER_PK,
        registered.viewingPublicKey,
      );
      for (const refused of [unregistered.keypair.shieldedAddress(), zeroKey]) {
        await expect(
          indexedKeys(() =>
            buildRingDepositTransaction({
              client,
              ringProgramId,
              feePayer: sender.signer.address,
              recipient: refused,
              amount: 1n,
            }),
          ),
        ).rejects.toMatchObject({
          code: "RING_BUILD_DEPOSIT",
          causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
        });
      }
      for (const amount of [900_000_000n, 1_100_000_000n]) {
        await signSendAndConfirm(
          client,
          await buildRingDepositTransaction({
            client,
            ringProgramId,
            feePayer: sender.signer.address,
            recipient: sender.keypair.shieldedAddress(),
            amount,
          }),
          [sender.signer],
        );
      }
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
        expect(recoveredDeposits.notes).toHaveLength(4);
        for (const [asset, amount] of [
          [SOL_MINT, 2_000_000_000n],
          [harness.mint, 1000n],
          [harness.token2022Mint, 1000n],
        ] as const) {
          expect(
            deposits.filter((note) => note.utxo.asset === asset).map((note) => note.utxo.amount),
          ).toEqual(
            expect.arrayContaining(asset === SOL_MINT ? [900_000_000n, 1_100_000_000n] : [amount]),
          );
          expect(
            recoveredDeposits.notes
              .filter((note) => note.utxo.asset === asset)
              .map((note) => note.utxo.amount),
          ).toEqual(
            expect.arrayContaining(asset === SOL_MINT ? [900_000_000n, 1_100_000_000n] : [amount]),
          );
        }
      } finally {
        depositKey.destroy();
      }
      await settle(
        await createRingMergeSubmission({
          client,
          ringProgramId,
          wallet: sender.wallet,
          keys: sender.keys,
          feePayer: sender.signer.address,
        }),
        client,
        [sender.signer],
      );
      await sync(client, sender);
      expect(
        sender.wallet
          .utxos()
          .filter(
            (note) =>
              !note.spent &&
              note.utxo.ringProgramId === ringProgramId &&
              note.utxo.asset === SOL_MINT,
          )
          .map((note) => note.utxo.amount),
      ).toEqual([2_000_000_000n]);
      const transfer = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        keys: sender.keys,
        feePayer: sender.signer.address,
        recipient: recipient.keypair.shieldedAddress(),
        amount: 350_000_000n,
      };
      await expect(
        indexedKeys(() =>
          buildRingTransferTransaction({
            ...transfer,
            recipient: unregistered.keypair.shieldedAddress(),
            amount: 1n,
          }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_UNREGISTERED_OUTPUT_KEY",
      });
      await settle(
        await indexedKeys(() => createRingTransferSubmission({ ...transfer, amount: 50_000_000n })),
        client,
        [sender.signer],
      );
      await sync(client, sender);
      await expect(indexedKeys(() => buildRingTransferTransaction(transfer))).rejects.toMatchObject(
        {
          code: "RING_BUILD_TRANSFER",
          causeCode: "RING_COSIGNER_REQUIRED",
        },
      );
      await settle(
        await indexedKeys(() => createRingTransferSubmission({ ...transfer, cosigner })),
        client,
        [sender.signer, cosigner],
      );
      await sync(client, sender);
      await settle(
        await indexedKeys(() =>
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
      await sync(client, sender);
      // A single transfer above the SOL cap is refused before any proof.
      await expect(
        indexedKeys(() =>
          buildRingTransferTransaction({
            ...transfer,
            amount: 600_000_000n,
            cosigner,
          }),
        ),
      ).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_OUTFLOW_CAP_EXCEEDED",
      });
      for (const [asset, amount, rejected] of [
        [harness.mint, 100n, 301n],
        [harness.token2022Mint, 200n, 501n],
      ] as const) {
        await settle(
          await indexedKeys(() =>
            createRingTransferSubmission({
              ...transfer,
              asset,
              amount,
              cosigner,
            }),
          ),
          client,
          [sender.signer, cosigner],
        );
        await sync(client, sender);
        await expect(
          indexedKeys(() =>
            buildRingTransferTransaction({
              ...transfer,
              asset,
              amount: rejected,
              cosigner,
            }),
          ),
        ).rejects.toMatchObject({
          code: "RING_BUILD_TRANSFER",
          causeCode: "RING_OUTFLOW_CAP_EXCEEDED",
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
      // Delegation is exempt from the limits, the move passes the SOL cap.
      const move = {
        client,
        ringProgramId,
        wallet: sender.wallet,
        source: sender.keys,
        delegate,
        feePayer: delegate.address,
        outputs: [
          {
            recipient: recipient.keypair.shieldedAddress(),
            asset: SOL_MINT,
            amount: 700_000_000n,
          },
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
      const compactMove = await createRingDelegateSubmission({
        ...move,
        cosigner,
        compactPadding: true,
        outputs: [
          { recipient: recipient.keypair.shieldedAddress(), asset: harness.mint, amount: 900n },
          {
            recipient: recipient.keypair.shieldedAddress(),
            asset: harness.token2022Mint,
            amount: 600n,
          },
        ],
      });
      const compactTransport = createKitRingSubmissionTransport(client, [delegate, cosigner]);
      await settleWithTransport(compactMove, {
        ...compactTransport,
        sign: async (transaction, context) => {
          const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
          if (compiled.version !== 1) throw new Error("expected V1");
          const instruction = decompileTransactionMessage(compiled, {
            lastValidBlockHeight: 1n,
          }).instructions.find((instruction) => instruction.programAddress === ringProgramId);
          // Client paths select the exact2×3 key. Indexed paths use the general4×4 key.
          expect(instruction?.data?.[0]).toBe(proofDataSource === "client" ? 34 : 36);
          return compactTransport.sign(transaction, context);
        },
      });
      await sync(client, sender);
      await sync(client, recipient);
      for (const [asset, sourceAmount, recipientAmount] of [
        [SOL_MINT, 800_000_000n, 1_100_000_000n],
        [harness.mint, 0n, 1000n],
        [harness.token2022Mint, 200n, 800n],
      ] as const) {
        expect(
          sender.wallet
            .ringBalances()
            .find((ring) => ring.ringProgramId === ringProgramId)
            ?.assets.find((balance) => balance.mint === asset)?.amount ?? 0n,
        ).toBe(sourceAmount);
        expect(
          recipient.wallet
            .ringBalances()
            .find((ring) => ring.ringProgramId === ringProgramId)
            ?.assets.find((balance) => balance.mint === asset)?.amount,
        ).toBe(recipientAmount);
      }
      const sealed = await indexedKeys(() =>
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
        await indexedKeys(() =>
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
        causeCode:
          proofDataSource === "client" ? "RING_POLICY_RULE_UNSATISFIED" : "CLIENT_PROVER_HTTP",
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
      expect(await fetchRingCoSigner(client, ringProgramId)).toBeUndefined();
    } finally {
      auditor.destroy();
    }
  }, 1_800_000);
});
