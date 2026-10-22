import { AccountRole, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { publicAmountFields, publicSlots } from "../src/client/prover/assembly.js";
import { ringConfigAddress, ringMemberRegistryAddress } from "../src/interface/pda/index.js";
import { SOL_INTERFACE } from "../src/interface/program.js";
import {
  RING_AUTHORITY_MAX_INPUTS,
  RING_AUTHORITY_SHAPES,
  SPP_SUPPORTED_SHAPES,
  isRingAuthorityShape,
} from "../src/interface/shape.js";
import { TransactWithdrawal, type Bytes32 } from "../src/interface/types.js";
import { TRANSACTION_SIZE_LIMIT, transactionSize } from "../src/interface/transaction-size.js";
import { randomBlinding } from "../src/keypair/bytes.js";
import { ringIdField } from "../src/keypair/ring-stream.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { X25519Keypair, X25519PublicKey } from "../src/keypair/x25519.js";
import {
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  decodeRingMemberRegistry,
} from "../src/ring/codecs.js";
import { escrowKeyHash } from "../src/ring/member-registry.js";
import { checkEscrowedRecipients, readMemberRecords } from "../src/ring/registered-record.js";
import { sealAudit } from "../src/ring/audit-proof.js";
import type { ProvenRingTransfer } from "../src/ring/pipeline.js";
import {
  ListId,
  buildRuleTable,
  memberOfIdentity,
  recordBit,
  type RuleTable,
} from "../src/ring/policy.js";
import { buildRingDelegateTransferTransaction } from "../src/ring/delegate.js";
import { buildRingTransferTransaction } from "../src/ring/transfer.js";
import { RingOutputRail } from "../src/ring/rail.js";
import { CustomRingTransfer, DelegateTransfer } from "../src/ring/rails.js";
import { policyStatementHash } from "../src/ring/statement.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import {
  ConfidentialTransfer,
  WithdrawalTarget,
  assetField,
} from "../src/transaction/instructions/transact.js";
import { decodeConfidential } from "../src/transaction/serialization/codecs.js";
import { Utxo } from "../src/transaction/utxo.js";
import { approveIntent, type ApprovalRequest } from "../src/transaction/wallet/intent.js";
import { Wallet } from "../src/transaction/wallet/state.js";

import { BLOCKHASH, kitReads } from "./helpers/clients.js";

import type { FixtureRecord } from "./helpers/member-registry.js";
import {
  checkAccounts,
  checkAudit,
  checkDisclosure,
  checkFrameCounted,
  checkRingSecrets,
  expanded,
  filled,
  itemAt,
  noteInput,
  openDelivered,
  openPacked,
  randomAddress,
  ringError,
  ringFixture,
  small,
  walletKeys,
  type Fixture,
  type RingFixtureOptions,
} from "./helpers/ring-pipeline.js";

const assets = new AssetRegistry();
const EMPTY_TABLE: RuleTable = buildRuleTable({ rules: [] });

function transferTo(
  fixture: Fixture,
  sender: ShieldedKeypair,
  recipients: readonly ShieldedKeypair[],
  options: Readonly<{ amount?: bigint; each?: bigint; compact?: boolean }> = {},
): ConfidentialTransfer {
  const inputs = [noteInput(sender, options.amount ?? 10_000n, fixture.ringProgramId)];
  const transfer =
    options.compact === true
      ? ConfidentialTransfer.compact(sender.shieldedAddress(), inputs, fixture.authority)
      : new ConfidentialTransfer(sender.shieldedAddress(), inputs, fixture.authority);
  for (const recipient of recipients)
    transfer.send(recipient.shieldedAddress(), SOL_MINT, options.each ?? 400n);
  return transfer;
}

async function prove(
  fixture: Fixture,
  sender: ShieldedKeypair,
  transfer: ConfidentialTransfer,
  withdrawal?: TransactWithdrawal,
): Promise<ProvenRingTransfer> {
  const rail = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: walletKeys(sender),
    transfer,
    assets,
  });
  return (withdrawal === undefined ? rail : rail.withWithdrawalAccounts(withdrawal)).prove(
    fixture.client,
  );
}

/** An escrowed key record for each owner, the registry ring binds every output key. */
function escrowed(owners: readonly ShieldedKeypair[]): FixtureRecord[] {
  return owners.map((owner, index) => {
    const address = owner.shieldedAddress();
    const ciphertext = filled(0x60 + index);
    return {
      member: memberOfIdentity(address.signingPublicKey.ownerProofInputHash()),
      lists: 0n,
      escrowKey: escrowKeyHash({ nullifierPk: address.nullifierPublicKey, ciphertext }),
      sealed: {
        owner: randomAddress(),
        nullifierPk: address.nullifierPublicKey,
        ephemeralPublicKey: X25519Keypair.generate().publicKey(),
        ciphertext,
      },
    };
  });
}

async function registryOf(fixture: Fixture) {
  const account = fixture.accounts.get(await ringMemberRegistryAddress(fixture.ringProgramId));
  if (account === undefined) throw new Error("no registry");
  return {
    address: await ringMemberRegistryAddress(fixture.ringProgramId),
    ...decodeRingMemberRegistry(account.data),
  };
}

function readonly(address: Address) {
  return { address, role: AccountRole.READONLY };
}

function signer(address: Address) {
  return { address, role: AccountRole.READONLY_SIGNER };
}

describe("confidential rail", () => {
  it("packs two outputs as scheme 11 under the ring secret of each slot", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const proven = await prove(fixture, sender, transferTo(fixture, sender, [recipient]));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    expect([data.nIn, data.nOut]).toEqual([1, 2]);
    expect(data.outputs.map((output) => output.kind)).toEqual(["packed", "packed"]);
    expect(data.dataFree).toBe(true);
    expect(data.policy).toBeUndefined();
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [],
      payer: fixture.authority,
      ownerSigners: [sender.shieldedAddress().solanaAddress()],
    });
    expect(fixture.ringRequests).toHaveLength(1);
    checkAudit(fixture, data, { kind: "packedAudit" });
    checkDisclosure(fixture, call, data, sender.shieldedAddress());
    checkRingSecrets(call, data);
    const opened = openPacked(recipient, call, data, 1);
    expect(opened.amount).toBe(400n);
    expect(opened.blinding).toEqual(call.proofInputs.outputs[1]?.blinding);
    expect(openPacked(sender, call, data, 0).amount).toBe(9_600n);
  });

  it("delivers eight outputs as proven bodies the recipient opens to the committed note", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipients = Array.from({ length: 7 }, () => ShieldedKeypair.generate());
    const proven = await prove(fixture, sender, transferTo(fixture, sender, recipients));
    const { data, call } = await expanded(fixture, proven, "confidential");

    expect(data.nOut).toBe(8);
    expect(data.outputs.every((output) => output.kind === "delivered")).toBe(true);
    checkAudit(fixture, data, { kind: "deliveredAudit" });
    checkDisclosure(fixture, call, data, sender.shieldedAddress());
    checkRingSecrets(call, data);
    const open = (recipient: ShieldedKeypair) =>
      openDelivered({
        fixture,
        keys: walletKeys(recipient),
        recipient: { kind: "viewing", viewingPublicKey: recipient.viewingPublicKey() },
        call,
        data,
        slotIndex: 3,
      });
    const note = await open(itemAt(recipients, 2));
    expect(note?.utxo.amount).toBe(400n);
    expect(note?.utxoHash).toEqual(data.outputs[3]?.hash);
    expect(await open(itemAt(recipients, 3))).toBeUndefined();
  });

  it("frames a default-ring recipient as a scheme 3 exit and settles a public withdrawal", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const transfer = transferTo(fixture, sender, []);
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const recipient = randomAddress();
    transfer.withdraw(SOL_MINT, 200n, WithdrawalTarget.sol({ recipient }));
    const proven = await prove(fixture, sender, transfer, TransactWithdrawal.sol({ recipient }));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    expect(data.outputs.map((output) => output.kind)).toEqual(["packed", "exit"]);
    expect(data.interfaceTransfers).toHaveLength(1);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [],
      payer: fixture.authority,
      ownerSigners: [sender.shieldedAddress().solanaAddress()],
      settlement: [
        { address: SOL_INTERFACE, role: AccountRole.WRITABLE },
        { address: recipient, role: AccountRole.WRITABLE },
      ],
    });
    checkDisclosure(fixture, call, data, sender.shieldedAddress());
    checkRingSecrets(call, data);
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
    expect(opened.ringProgramId).toBeUndefined();
  });

  it("refuses withdrawal accounts that name another recipient or a withdrawal the transfer lacks", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const transfer = transferTo(fixture, sender, []);
    transfer.withdraw(SOL_MINT, 200n, WithdrawalTarget.sol({ recipient: randomAddress() }));
    await expect(
      prove(fixture, sender, transfer, TransactWithdrawal.sol({ recipient: randomAddress() })),
    ).rejects.toThrow(ringError("RING_SETTLEMENT_ACCOUNTS_INVALID"));
    await expect(
      prove(
        fixture,
        sender,
        transferTo(fixture, sender, []),
        TransactWithdrawal.sol({ recipient: randomAddress() }),
      ),
    ).rejects.toThrow(ringError("RING_SETTLEMENT_ACCOUNTS_INVALID"));
    expect(fixture.ringRequests).toHaveLength(0);
  });

  it("refuses an owner as the co-signer its scope or a withdrawal past its threshold demands", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const owner = sender.shieldedAddress().solanaAddress();
    const isOwner = ringError("RING_COSIGNER_REQUIRED", {
      reason: "coSignerIsOwner",
      expected: owner,
    });
    const scoped = async (signer: Address) => {
      const fixture = await ringFixture({
        coSigner: { signer, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
      });
      return { fixture, proven: prove(fixture, sender, transferTo(fixture, sender, [recipient])) };
    };
    const other = randomAddress();
    expect((await (await scoped(other)).proven).coSigner).toBe(other);
    const refused = await scoped(owner);
    await expect(refused.proven).rejects.toThrow(isOwner);
    expect(refused.fixture.ringRequests).toHaveLength(0);
    expect(refused.fixture.sppCalls).toHaveLength(0);

    const fixture = await ringFixture({
      coSigner: {
        signer: owner,
        scope: RING_COSIGN_WITHDRAWALS,
        thresholds: [{ mint: SOL_MINT, amount: 200n }],
      },
    });
    const withdraw = (amount: bigint) => {
      const transfer = transferTo(fixture, sender, []);
      const target = randomAddress();
      transfer.withdraw(SOL_MINT, amount, WithdrawalTarget.sol({ recipient: target }));
      return prove(fixture, sender, transfer, TransactWithdrawal.sol({ recipient: target }));
    };
    expect((await withdraw(200n)).coSigner).toBeUndefined();
    await expect(withdraw(201n)).rejects.toThrow(isOwner);
    expect(fixture.sppCalls).toHaveLength(1);
  });

  it("counts the setup instructions and the priority fee before approval and any proof", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        CustomRingTransfer.new({
          ringProgramId: fixture.ringProgramId,
          keys: walletKeys(sender),
          transfer: transferTo(fixture, sender, [recipient]),
          assets,
        }).proveApproved(fixture.client, approval),
    });
  });

  it("publishes only the real slots of a compact transfer", async () => {
    const fixture = await ringFixture();
    const sender = ShieldedKeypair.generate();
    const recipients = [ShieldedKeypair.generate(), ShieldedKeypair.generate()];
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, recipients, { compact: true }),
    );
    const { data, call } = await expanded(fixture, proven, "confidential");

    expect([data.nIn, data.nOut]).toEqual([1, 4]);
    expect(data.outputs).toHaveLength(3);
    expect(call.proofInputs.outputs[3]?.isCompact()).toBe(true);
    checkAudit(fixture, data, { kind: "packedAudit" });
    checkDisclosure(fixture, call, data, sender.shieldedAddress());
    checkRingSecrets(call, data);
  });

  it("refuses an anonymous ring, a paused ring and a ring SPP never activated", async () => {
    const sender = ShieldedKeypair.generate();
    for (const [options, code] of [
      [{ mode: "anonymous" }, "RING_ANONYMOUS_SIGNER_REQUIRED"],
      [{ registration: { activated: true, paused: true } }, "RING_PAUSED"],
      [{ registration: { activated: false, paused: false } }, "RING_NOT_ACTIVATED"],
    ] as const) {
      const fixture = await ringFixture(options);
      await expect(prove(fixture, sender, transferTo(fixture, sender, []))).rejects.toThrow(
        ringError(code),
      );
      expect(fixture.ringRequests).toHaveLength(0);
      expect(fixture.sppCalls).toHaveLength(0);
    }
  });
});

describe("policy ring", () => {
  const allowOwners = (limit: Readonly<{ cap: bigint; cosignAbove: bigint }>): RuleTable =>
    buildRuleTable({
      rules: [
        {
          subject: "outputOwner",
          source: { kind: "lists", present: [ListId.allow], absent: [] },
          guard: { kind: "always" },
        },
      ],
      limits: [{ asset: assetField(SOL_MINT), ...limit }],
    });

  async function curatedRing(
    owners: readonly ShieldedKeypair[],
    options: Readonly<{
      coSigner?: Readonly<{ signer: Address; scope: number }>;
      cap?: bigint;
    }> = {},
  ) {
    return ringFixture({
      table: allowOwners({ cap: options.cap ?? 0n, cosignAbove: 100n }),
      curator: {
        lists: [ListId.allow],
        records: owners.map((owner) => ({
          member: memberOfIdentity(owner.shieldedAddress().signingPublicKey.ownerProofInputHash()),
          lists: 1n,
        })),
      },
      ...(options.coSigner === undefined
        ? {}
        : { coSigner: { ...options.coSigner, thresholds: [] } }),
    });
  }

  it("reads the curator's list, sets the approval bit past the co-sign bound and demands the co-signer", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const coSigner = randomAddress();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: coSigner, scope: RING_COSIGN_DEPOSITS },
    });
    const proven = await prove(fixture, sender, transferTo(fixture, sender, [recipient]));
    const { instruction, data, call } = await expanded(fixture, proven, "confidential");

    expect(proven.approvalRequired).toBe(true);
    expect(proven.coSigner).toBe(coSigner);
    expect(data.approvalRequired).toBe(true);
    expect(data.policy?.curatorRootIndex).toBe(0);
    const registry = await registryOf(fixture);
    expect(proven.policy).toEqual({
      ringProgramId: fixture.ringProgramId,
      policyHash: registry.policyHash,
    });
    if (fixture.curatorRegistry === undefined || fixture.curatorTree === undefined)
      throw new Error("no curator");
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [readonly(registry.address), readonly(fixture.curatorRegistry), signer(coSigner)],
      payer: fixture.authority,
      ownerSigners: [sender.shieldedAddress().solanaAddress()],
    });
    const policy = fixture.ringRequests.find((request) => request.kind === "memberPolicy");
    const slots = publicSlots(call.proofInputs.externalData.interfaceTransfers);
    expect(policy?.publicInputHash).toEqual(
      policyStatementHash({
        key: { kind: "member", anonymous: false },
        privateTxHash: data.privateTxHash,
        policyHash: registry.policyHash,
        ringId: ringIdField(fixture.ringProgramId),
        approvalRequired: true,
        keyEscrow: false,
        ownRoot: fixture.ownTree.root,
        curatorRoot: fixture.curatorTree.root,
        sender: sender.shieldedAddress().signingPublicKey.ownerProofInputHash(),
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
      }),
    );
    checkAudit(fixture, data, { kind: "packedAudit" });
    checkDisclosure(fixture, call, data, sender.shieldedAddress());
    checkRingSecrets(call, data);
  });

  it("refuses an output owner off the required list before any proof, naming the rule and its slot", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender]);
    await expect(
      prove(fixture, sender, transferTo(fixture, sender, [recipient], { each: 100n })),
    ).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", {
        reason: "lists",
        ruleIndex: 0,
        subject: "owner",
        slotIndex: 1,
      }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("refuses an outflow past the co-sign bound on a ring without a co-signer", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient]);
    await expect(prove(fixture, sender, transferTo(fixture, sender, [recipient]))).rejects.toThrow(
      ringError("RING_COSIGNER_REQUIRED"),
    );
    expect(fixture.ringRequests).toHaveLength(0);
  });

  it("refuses the owner as the co-signer an approval demands, and proves inside the bound without it", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const owner = sender.shieldedAddress().solanaAddress();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: owner, scope: RING_COSIGN_DEPOSITS },
    });
    await expect(prove(fixture, sender, transferTo(fixture, sender, [recipient]))).rejects.toThrow(
      ringError("RING_COSIGNER_REQUIRED", { reason: "coSignerIsOwner", expected: owner }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, [recipient], { each: 100n }),
    );
    expect([proven.approvalRequired, proven.coSigner]).toEqual([false, undefined]);
  });

  it("refuses an outflow past the cap before any proof", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient], { cap: 399n });
    await expect(prove(fixture, sender, transferTo(fixture, sender, [recipient]))).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "399", outflow: "400" }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });

  it("keeps the approval bit clear inside the bound and names no co-signer outside its scope", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: randomAddress(), scope: RING_COSIGN_DEPOSITS },
    });
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, [recipient], { each: 100n }),
    );
    expect(proven.approvalRequired).toBe(false);
    expect(proven.coSigner).toBeUndefined();
    const { data } = await expanded(fixture, proven, "confidential");
    expect(data.approvalRequired).toBe(false);
  });

  it("names the configured co-signer of transfers inside the bound", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const coSigner = randomAddress();
    const fixture = await curatedRing([sender, recipient], {
      coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS },
    });
    const proven = await prove(
      fixture,
      sender,
      transferTo(fixture, sender, [recipient], { each: 100n }),
    );
    expect(proven.approvalRequired).toBe(false);
    expect(proven.coSigner).toBe(coSigner);
    await expanded(fixture, proven, "confidential", coSigner);
  });

  it("binds every output owner's escrowed key on a registry ring and refuses an owner without one", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      records: escrowed([sender, recipient]),
    });
    const proven = await prove(fixture, sender, transferTo(fixture, sender, [recipient]));
    const { data } = await expanded(fixture, proven, "confidential");
    const policy = fixture.ringRequests.find((request) => request.kind === "memberPolicy");
    if (policy?.kind !== "memberPolicy") throw new Error("no policy proof");
    expect(policy.keyEscrow).toBe(true);
    expect(policy.outputs.map((output) => output.ctHash !== undefined)).toEqual([true, true]);
    expect(data.policy?.curatorRootIndex).toBeUndefined();

    const unregistered = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      records: escrowed([sender]),
    });
    await expect(
      prove(unregistered, sender, transferTo(unregistered, sender, [recipient])),
    ).rejects.toThrow(ringError("RING_UNREGISTERED_OUTPUT_KEY"));
    expect(unregistered.ringRequests).toHaveLength(0);
  });

  it("names the refusing rule before an owner's missing escrow on a registry ring", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const fixture = await ringFixture({
      mode: "registry",
      table: allowOwners({ cap: 0n, cosignAbove: 100n }),
      records: escrowed([sender]),
      curator: {
        lists: [ListId.allow],
        records: [
          {
            member: memberOfIdentity(
              sender.shieldedAddress().signingPublicKey.ownerProofInputHash(),
            ),
            lists: 1n,
          },
        ],
      },
    });
    await expect(
      prove(fixture, sender, transferTo(fixture, sender, [recipient], { each: 100n })),
    ).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", { subject: "owner", slotIndex: 1 }),
    );
  });
});

describe("delegate rail", () => {
  async function delegateRing(owners: readonly ShieldedKeypair[]) {
    const delegate = randomAddress();
    const fixture = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      delegate,
      records: escrowed(owners),
    });
    return { fixture, delegate };
  }

  function move(
    input: Readonly<{
      fixture: Fixture;
      delegate: Address;
      source: ShieldedKeypair;
      recipients: readonly ShieldedKeypair[];
      spender?: ShieldedKeypair;
    }>,
  ): DelegateTransfer {
    const { fixture, source } = input;
    return DelegateTransfer.new({
      ringProgramId: fixture.ringProgramId,
      delegate: input.delegate,
      payer: fixture.authority,
      source: source.shieldedAddress(),
      sourceProofs: walletKeys(source),
      inputs: [noteInput(input.spender ?? source, 10_000n, fixture.ringProgramId)],
      outputs: input.recipients.map((recipient) => ({
        recipient: recipient.shieldedAddress(),
        asset: SOL_MINT,
        amount: 100n,
      })),
      assets,
    });
  }

  it("moves a member's notes on the authority rail with the delegate signing", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    const proven = await move({ fixture, delegate, source, recipients: [recipient] }).prove(
      fixture.client,
    );
    const { instruction, data, call } = await expanded(fixture, proven, "delegate");

    expect(call.circuit.kind).toBe("ringAuthority");
    expect(data.outputs.every((output) => output.kind === "packed")).toBe(true);
    const registry = await registryOf(fixture);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [readonly(registry.address), signer(delegate)],
      payer: fixture.authority,
    });
    const policy = fixture.ringRequests.find((request) => request.kind === "delegatePolicy");
    const slots = publicSlots(call.proofInputs.externalData.interfaceTransfers);
    const zero = new Uint8Array(32) as Bytes32;
    expect(policy?.publicInputHash).toEqual(
      policyStatementHash({
        key: { kind: "delegate" },
        privateTxHash: data.privateTxHash,
        policyHash: registry.policyHash,
        ringId: ringIdField(fixture.ringProgramId),
        approvalRequired: false,
        keyEscrow: true,
        ownRoot: fixture.ownTree.root,
        curatorRoot: zero,
        sender: zero,
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
      }),
    );
    checkAudit(fixture, data, { kind: "packedAudit" });
    checkDisclosure(fixture, call, data, source.shieldedAddress());
    checkRingSecrets(call, data);
    expect(openPacked(recipient, call, data, 1).amount).toBe(100n);
  });

  it("delivers an eight-output move as proven bodies", async () => {
    const source = ShieldedKeypair.generate();
    const recipients = Array.from({ length: 7 }, () => ShieldedKeypair.generate());
    const { fixture, delegate } = await delegateRing([source, ...recipients]);
    const proven = await move({ fixture, delegate, source, recipients }).prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "delegate");

    expect(data.nOut).toBe(8);
    expect(data.outputs.every((output) => output.kind === "delivered")).toBe(true);
    checkAudit(fixture, data, { kind: "deliveredAudit" });
    checkDisclosure(fixture, call, data, source.shieldedAddress());
    checkRingSecrets(call, data);
    const first = itemAt(recipients, 0);
    const note = await openDelivered({
      fixture,
      keys: walletKeys(first),
      recipient: { kind: "viewing", viewingPublicKey: first.viewingPublicKey() },
      call,
      data,
      slotIndex: 1,
    });
    expect(note?.utxo.amount).toBe(100n);
  });

  it("pads a move to each ring authority shape it names and refuses any other shape", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    const base = move({ fixture, delegate, source, recipients: [recipient] });
    for (const shape of RING_AUTHORITY_SHAPES) {
      const proving = base.withShape(shape).prove(fixture.client);
      if (shape.inputs === RING_AUTHORITY_MAX_INPUTS) {
        // Rust pins the widest delegate move past one transaction too.
        const proofs = fixture.sppCalls.length;
        await expect(proving).rejects.toThrow(
          expect.objectContaining({ code: "INTERFACE_TRANSACTION_TOO_LARGE" }),
        );
        expect(fixture.sppCalls).toHaveLength(proofs);
        continue;
      }
      const { data } = await expanded(fixture, await proving, "delegate");
      expect([data.nIn, data.nOut]).toEqual([shape.inputs, shape.outputs]);
    }
    for (const shape of SPP_SUPPORTED_SHAPES.filter((shape) => !isRingAuthorityShape(shape)))
      expect(() => base.withShape(shape)).toThrow(
        ringError("RING_TRANSACT_DATA_INVALID", { reason: "RingShapeUnkeyed", rail: "delegate" }),
      );
    const wide = move({ fixture, delegate, source, recipients: [recipient, recipient] });
    await expect(wide.withShape({ inputs: 1, outputs: 2 }).prove(fixture.client)).rejects.toThrow(
      expect.objectContaining({ code: "TRANSACTION_TOO_MANY_OUTPUTS_FOR_SHAPE" }),
    );
  });

  it("counts the setup instructions and the priority fee before approval and any proof", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        move({ fixture, delegate, source, recipients: [recipient] }).proveApproved(
          fixture.client,
          approval,
        ),
    });
  });

  it("refuses another delegate, a ring without one, a ring without escrow and another member's notes", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const { fixture, delegate } = await delegateRing([source, recipient]);
    const refused = async (
      input: Parameters<typeof move>[0],
      details: Readonly<Record<string, unknown>>,
      code = "RING_DELEGATE_INVALID",
    ) => {
      await expect(move(input).prove(input.fixture.client)).rejects.toThrow(
        ringError(code, details),
      );
      expect(input.fixture.ringRequests).toHaveLength(0);
    };
    await refused(
      { fixture, delegate: randomAddress(), source, recipients: [recipient] },
      { reason: "unauthorized" },
    );
    await refused(
      {
        fixture: await ringFixture({ mode: "registry", table: EMPTY_TABLE }),
        delegate,
        source,
        recipients: [recipient],
      },
      { reason: "missing" },
    );
    await refused(
      {
        fixture: await ringFixture({ table: EMPTY_TABLE, delegate }),
        delegate,
        source,
        recipients: [recipient],
      },
      { reason: "escrow" },
    );
    await refused(
      { fixture, delegate, source, recipients: [recipient], spender: recipient },
      { index: 0 },
      "RING_MIXED_OWNERS",
    );
  });

  it("refuses the delegate as the co-signer of its move before any proof", async () => {
    const source = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const delegate = randomAddress();
    const fixture = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      delegate,
      records: escrowed([source, recipient]),
      coSigner: { signer: delegate, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
    });
    await expect(
      move({ fixture, delegate, source, recipients: [recipient] }).prove(fixture.client),
    ).rejects.toThrow(
      ringError("RING_COSIGNER_REQUIRED", { reason: "coSignerIsDelegate", expected: delegate }),
    );
    expect(fixture.ringRequests).toHaveLength(0);
    expect(fixture.sppCalls).toHaveLength(0);
  });
});

describe("member records", () => {
  const identity = (keys: ShieldedKeypair): Bytes32 =>
    keys.shieldedAddress().signingPublicKey.ownerProofInputHash();

  it("reads records in member order with their lists and escrowed key like Rust `MemberRecords::read`", async () => {
    const registered = ShieldedKeypair.generate();
    const stranger = ShieldedKeypair.generate();
    const [record] = escrowed([registered]);
    if (record === undefined) throw new Error("no record");
    const fixture = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      records: [{ ...record, lists: recordBit(ListId.allow) }],
    });
    const [absent, present] = await readMemberRecords({
      client: fixture.client,
      ringProgramId: fixture.ringProgramId,
      members: [identity(stranger), identity(registered)],
    });
    expect(absent?.record()).toBeUndefined();
    expect(absent?.listed(ListId.allow)).toBe(false);
    expect(present?.listed(ListId.allow)).toBe(true);
    expect(present?.listed(ListId.block)).toBe(false);
    const nullifierPk = registered.shieldedAddress().nullifierPublicKey;
    expect(present?.escrowed(nullifierPk)?.record.member).toEqual(identity(registered));
    expect(present?.escrowed(stranger.shieldedAddress().nullifierPublicKey)).toBeUndefined();
  });

  it("refuses the first recipient without an escrowed key on a key escrow ring alone", async () => {
    const registered = ShieldedKeypair.generate();
    const stranger = ShieldedKeypair.generate();
    const check = (fixture: Fixture, recipients: readonly ShieldedKeypair[]) =>
      checkEscrowedRecipients({
        client: fixture.client,
        ringProgramId: fixture.ringProgramId,
        recipients: recipients.map((keys) => keys.shieldedAddress()),
      });
    const escrowing = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      records: escrowed([registered]),
    });
    await expect(check(escrowing, [registered])).resolves.toBeUndefined();
    await expect(check(escrowing, [registered, stranger])).rejects.toThrow(
      ringError("RING_UNREGISTERED_OUTPUT_KEY", {
        owner: Buffer.from(identity(stranger)).toString("hex"),
      }),
    );
    await expect(check(await ringFixture(), [registered, stranger])).resolves.toBeUndefined();
  });
});

describe("delegate move builder", () => {
  /** A move paying `amounts` out of `notes` source notes of 100, the delegate paying on one tree. */
  async function delegateMove(
    input: Readonly<{ amounts: readonly bigint[]; notes?: number; coSigner?: boolean }>,
  ) {
    const source = ShieldedKeypair.generate();
    const recipients = input.amounts.map(() => ShieldedKeypair.generate());
    const delegate = randomAddress();
    const coSigner = randomAddress();
    const fixture = await ringFixture({
      mode: "registry",
      table: EMPTY_TABLE,
      delegate,
      records: escrowed([source, ...recipients]),
      ...(input.coSigner === true
        ? { coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] } }
        : {}),
    });
    const wallet = new Wallet({ identity: source.shieldedAddress() });
    wallet._replace({
      utxos: Array.from({ length: input.notes ?? 40 }, (_, index) => ({
        utxo: new Utxo({
          owner: source.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: randomBlinding(),
          ringProgramId: fixture.ringProgramId,
        }),
        outputContext: {
          hash: small(index + 1),
          tree: fixture.client.tree,
          leafIndex: BigInt(index),
        },
        nullifier: small(index + 100),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: ApprovalRequest[] = [];
    const config = await ringConfigAddress(fixture.ringProgramId);
    const reads = { config: 0, openings: 0, proofsAtApproval: [] as number[] };
    const build = buildRingDelegateTransferTransaction({
      client: {
        ...fixture.client,
        getAccount: async (address) => {
          if (address === config) reads.config += 1;
          return fixture.client.getAccount(address);
        },
        getRingMemberOpenings: async (request) => {
          reads.openings += 1;
          return fixture.client.getRingMemberOpenings(request);
        },
        getLatestBlockhash: async () => BLOCKHASH,
        ...kitReads({ solanaRpc: { getProgramAccounts: () => ({ send: async () => [] }) } }),
      },
      ringProgramId: fixture.ringProgramId,
      wallet,
      source: walletKeys(source),
      approve: async (request) => {
        requests.push(request);
        reads.proofsAtApproval.push(fixture.ringRequests.length + fixture.sppCalls.length);
        return approveIntent(request.intent);
      },
      delegate,
      feePayer: delegate,
      ...(input.coSigner === true ? { cosigner: coSigner } : {}),
      outputs: input.amounts.map((amount, index) => ({
        recipient: itemAt(recipients, index).shieldedAddress(),
        asset: SOL_MINT,
        amount,
      })),
    });
    return { fixture, requests, reads, build };
  }

  it("reads the ring and seals the move once, approving between its size check and its proofs", async () => {
    const { fixture, reads, build } = await delegateMove({ amounts: [400n], notes: 4 });
    await build;
    expect(reads).toEqual({ config: 1, openings: 1, proofsAtApproval: [0] });
    expect(fixture.sppCalls).toHaveLength(1);
  });

  it("bounds a move's notes by the widest authority shape holding its payments and change", async () => {
    const one = await delegateMove({ amounts: [2_401n], notes: 30 });
    await one.build;
    expect(one.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 32,
      outputs: 2,
    });
    const two = await delegateMove({ amounts: [1_200n, 1_150n], notes: 30 });
    await two.build;
    expect(two.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 24,
      outputs: 4,
    });
    // Two payments and the change fit no authority shape wider than 24 inputs.
    const wide = await delegateMove({ amounts: [1_200n, 1_201n], notes: 30 });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { selected: 30, maximum: 24 } },
    });
    expect(wide.requests).toEqual([]);
  });

  it("lands a forty note move in one transaction when the delegate pays on one tree", async () => {
    const { fixture, requests, build } = await delegateMove({ amounts: [4_000n] });
    const transaction = await build;
    expect(requests).toHaveLength(1);
    expect(transactionSize(transaction)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({ inputs: 40, outputs: 2 });
  });

  it("refuses the same move with a co-signer before approval and lands a narrower one", async () => {
    const wide = await delegateMove({ amounts: [4_000n], coSigner: true });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { selected: 40, limit: TRANSACTION_SIZE_LIMIT } },
    });
    expect(wide.requests).toEqual([]);
    expect(wide.fixture.ringRequests).toHaveLength(0);
    expect(wide.fixture.sppCalls).toHaveLength(0);
    const narrow = await delegateMove({ amounts: [3_200n], coSigner: true });
    await narrow.build;
    expect(narrow.requests).toHaveLength(1);
    expect(narrow.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 32,
      outputs: 2,
    });
  });
});

describe("ring transfer builder", () => {
  /** A payment of `amount` out of `notes` ring notes of 100, the owner paying the fee. */
  async function ringTransfer(
    input: Readonly<{
      amount: bigint;
      notes: number;
      ring?: RingFixtureOptions;
      cosigner?: Address;
    }>,
  ) {
    const owner = ShieldedKeypair.generate();
    const fixture = await ringFixture(input.ring);
    const wallet = new Wallet({ identity: owner.shieldedAddress() });
    wallet._replace({
      utxos: Array.from({ length: input.notes }, (_, index) => ({
        utxo: new Utxo({
          owner: owner.signingPublicKey(),
          asset: SOL_MINT,
          amount: 100n,
          blinding: randomBlinding(),
          ringProgramId: fixture.ringProgramId,
        }),
        outputContext: {
          hash: small(index + 1),
          tree: fixture.client.tree,
          leafIndex: BigInt(index),
        },
        nullifier: small(index + 100),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: ApprovalRequest[] = [];
    const build = buildRingTransferTransaction({
      client: { ...fixture.client, getLatestBlockhash: async () => BLOCKHASH },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(owner),
      feePayer: owner.shieldedAddress().solanaAddress(),
      approve: async (request) => {
        requests.push(request);
        return approveIntent(request.intent);
      },
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: input.amount,
      ...(input.cosigner === undefined ? {} : { cosigner: input.cosigner }),
    });
    return { fixture, requests, build };
  }

  it("refuses a payment past one transaction before approval and any proof as too many notes", async () => {
    const wide = await ringTransfer({ amount: 4_750n, notes: 48 });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { selected: 48, limit: TRANSACTION_SIZE_LIMIT } },
    });
    expect(wide.requests).toEqual([]);
    expect(wide.fixture.ringRequests).toHaveLength(0);
    expect(wide.fixture.sppCalls).toHaveLength(0);
    const narrow = await ringTransfer({ amount: 3_950n, notes: 48 });
    expect(transactionSize(await narrow.build)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(narrow.requests).toHaveLength(1);
  });

  it("refuses a missing or another co-signer before approval and any proof", async () => {
    const coSigner = randomAddress();
    const ring = { coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] } };
    for (const [cosigner, reason] of [
      [undefined, "missing"],
      [randomAddress(), "mismatch"],
    ] as const) {
      const refused = await ringTransfer({
        amount: 300n,
        notes: 4,
        ring,
        ...(cosigner === undefined ? {} : { cosigner }),
      });
      await expect(refused.build).rejects.toMatchObject({
        code: "RING_BUILD_TRANSFER",
        causeCode: "RING_COSIGNER_REQUIRED",
        cause: { details: { reason, expected: coSigner } },
      });
      expect(refused.requests).toEqual([]);
      expect(refused.fixture.ringRequests).toHaveLength(0);
      expect(refused.fixture.sppCalls).toHaveLength(0);
    }
    const signed = await ringTransfer({ amount: 300n, notes: 4, ring, cosigner: coSigner });
    await signed.build;
    expect(signed.requests).toHaveLength(1);
  });
});

describe("audit seal", () => {
  it("makes no ephemeral key for a disclosure it refuses", () => {
    const sender = ShieldedKeypair.generate();
    const proofInputs = new ConfidentialTransfer(
      sender.shieldedAddress(),
      [noteInput(sender, 10n)],
      randomAddress(),
    ).sign(sender, new AssetRegistry());
    const txViewingKey = ViewingKey.generate();
    const auditor = X25519Keypair.generate();
    const generate = vi.spyOn(X25519Keypair, "generate");
    try {
      expect(() =>
        sealAudit({
          rail: new RingOutputRail(txViewingKey, proofInputs.firstNullifier(), { kind: "packed" }),
          audit: { exits: false, keyEscrow: false, dataFree: true, fullOpenings: false },
          layout: { kind: "packed", outputs: 1, exits: false, keyEscrow: false, dataFree: true },
          published: [],
          proofInputs,
          sender: sender.shieldedAddress(),
          auditor: auditor.publicKey(),
        }),
      ).toThrow(expect.objectContaining({ code: "KEYPAIR_DISCLOSURE_SHAPE" }));
      expect(generate).not.toHaveBeenCalled();
    } finally {
      generate.mockRestore();
      auditor.destroy();
    }
  });
});
