import { readFileSync } from "node:fs";
import { AccountState, getTokenEncoder } from "@solana-program/token";
import {
  AccountRole,
  address,
  getAddressDecoder,
  getProgramDerivedAddress,
  none,
  some,
  type Address,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import { asField, prepareTransfer } from "../src/client/prover/assembly.js";
import {
  customRingBaseProofRequest,
  customRingPolicyProofRequest,
  proverRequestBody,
} from "../src/client/prover/client.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingOpening,
  CustomRingPolicyProofRequest,
  CustomRingSubjectWitness,
  ProverInputs,
  TransferCircuit,
} from "../src/client/prover/types.js";
import type { AnonymousRingTransactProofInput } from "../src/client/ports.js";
import { LocalKeys } from "../src/client/keys.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { SOLANA_OWNER_TAG, initializePoseidon, solanaOwnerIdentity } from "../src/hasher/index.js";
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import { wireDecoder } from "../src/interface/decode.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { addressBytes } from "../src/interface/internal.js";
import {
  associatedTokenAddress,
  splInterfaceWithBump,
  treeAddress,
} from "../src/interface/pda/index.js";
import {
  InstructionTag,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
} from "../src/interface/program.js";
import {
  TransactWithdrawal,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type Bytes128,
  type TransactInstructionData,
  type TransactOutput,
} from "../src/interface/types.js";
import { auditPublicInputHash, parseAuditorMessage } from "../src/keypair/audit.js";
import { RingAddress } from "../src/keypair/ring-address.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import {
  AnonymousPreparedTransfer,
  anonymousExitTokenOwner,
  anonymousIdentities,
  checkAnonymousOutputs,
  signingKeySpendSigner,
  type AnonymousRingPayment,
} from "../src/ring/anonymous.js";
import { ringTransactInstruction } from "../src/ring/instructions.js";
import {
  proveAnonymousRingTransfer,
  proveCustomRingTransfer,
  type AnonymousRingTransferClient,
} from "../src/ring/transfer.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import {
  ConfidentialTransfer,
  SppProofInputs,
  WithdrawalTarget,
  createExternalData,
  ringSpendMessage,
} from "../src/transaction/instructions/transact.js";
import {
  decodeRingAnonymous,
  readOutputData,
  ringAnonymousBodyHash,
} from "../src/transaction/serialization/codecs.js";
import { ProofInputUtxo, Utxo, createProofOutput } from "../src/transaction/utxo.js";
import { ringTransferClient, transactionsPage } from "./helpers/clients.js";

await initializePoseidon();

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE = treeAddress(0);
const decoder = wireDecoder((path) => new Error(`invalid fixture ${path}`));

function filled(value: number, length = 32): Uint8Array {
  return new Uint8Array(length).fill(value);
}

function hexBytes(value: unknown, length = 32): Uint8Array {
  const text = decoder.string(value, "hex");
  const bytes = new Uint8Array(Buffer.from(text.slice(2), "hex"));
  if (!text.startsWith("0x") || bytes.length !== length) throw new Error("invalid fixture bytes");
  return bytes;
}

function field(value: unknown): Bytes32 {
  return hexBytes(value) as Bytes32;
}

function integer(value: unknown): bigint {
  return BigInt(decoder.string(value, "integer"));
}

function golden(name: string): Record<string, unknown> {
  return decoder.record(
    JSON.parse(
      readFileSync(
        new URL(
          `../../../custom-rings/sdk/tests/fixtures/prover-json/${name}.json`,
          import.meta.url,
        ),
        "utf8",
      ),
    ),
    name,
  );
}

function list(wire: Record<string, unknown>, key: string): readonly unknown[] {
  return decoder.list(wire[key], key);
}

function opening(value: unknown): CustomRingOpening {
  const row = decoder.record(value, "opening");
  return {
    domain: field(row["domain"]),
    treeId: field(row["treeId"]),
    ownerPkHash: field(row["ownerPkHash"]),
    nullifierPk: field(row["nullifierPk"]),
    asset: field(row["asset"]),
    amount: field(row["amount"]),
    blinding: field(row["blinding"]),
    dataHash: field(row["dataHash"]),
    ringDataHash: field(row["ringDataHash"]),
    ringProgramId: field(row["ringProgramId"]),
    ...(row["ctHash"] === undefined ? {} : { ctHash: field(row["ctHash"]) }),
  };
}

function subject(value: unknown): CustomRingSubjectWitness | undefined {
  if (value === null) return undefined;
  const row = decoder.record(value, "subject");
  return {
    present: decoder.boolean(row["present"], "present"),
    next: field(row["next"]),
    lists: BigInt(decoder.integer(row["lists"], "lists")),
    escrowKey: field(row["escrowKey"]),
    index: BigInt(decoder.integer(row["index"], "index")),
    path: list(row, "path").map(field),
    lowMember: field(row["lowMember"]),
    lowNext: field(row["lowNext"]),
    lowLists: BigInt(decoder.integer(row["lowLists"], "lowLists")),
    lowEscrow: field(row["lowEscrow"]),
  };
}

/** The anonymous parts every anonymous statement carries, the trailing padding slot left to the request. */
function anonymousParts(wire: Record<string, unknown>) {
  const delivery = decoder.record(wire["delivery"], "delivery");
  return {
    identities: {
      sender: hexBytes(wire["sender"], 33),
      recipients: list(wire, "recipients").map((value) => hexBytes(value, 33)),
      recipientViewingKeys: list(wire, "recipientViewingKeys").map((value) => hexBytes(value, 33)),
    },
    delivery: {
      ringProgramId: getAddressDecoder().decode(hexBytes(delivery["ringProgramId"])),
      outputs: decoder
        .list(delivery["outputs"], "outputs")
        .slice(0, 2)
        .map((value) => {
          const row = decoder.record(value, "output");
          return {
            assetAddress: field(row["assetAddress"]),
            pairU: field(row["pairU"]),
            ciphertext: hexBytes(row["ciphertext"], 104),
          };
        }),
    },
  };
}

function audit(wire: Record<string, unknown>) {
  return {
    publicInputHash: field(wire["publicInputHash"]),
    privateTxHash: field(wire["privateTxHash"]),
    txViewingSecret: field(wire["txViewingSk"]),
    ephemeralSecret: field(wire["ephSk"]),
    auditorPublicKey: hexBytes(wire["auditorPk"]),
    salt: hexBytes(wire["salt"], 16) as Bytes16,
  };
}

describe("anonymous prover requests against the Rust goldens", () => {
  it("rebuilds the 2x2 anonymous base request", () => {
    const wire = golden("custom-ring-base-anonymous");
    const anonymousOutputs = list(wire, "anonymousOutputs").map(opening);
    const request: CustomRingBaseProofRequest = {
      ...audit(wire),
      nIn: Number(decoder.integer(wire["nIn"], "nIn")),
      nOut: Number(decoder.integer(wire["nOut"], "nOut")),
      outputs: anonymousOutputs,
      anonymous: {
        ...anonymousParts(wire),
        inputs: list(wire, "inputs").map(opening),
        anonymousOutputs,
        privateTxBlinding: field(wire["privateTxBlinding"]),
      },
    };
    const body = customRingBaseProofRequest(request);
    // The golden's audit openings carry free owner hashes, the request derives them from its openings.
    expect({ ...body, outputs: undefined }).toEqual({ ...wire, outputs: undefined });
    expect(body["outputs"]).toHaveLength(list(wire, "outputs").length);
    const wide = customRingBaseProofRequest({
      ...request,
      nIn: 6,
      anonymous: {
        ...request.anonymous!,
        inputs: Array.from({ length: 12 }, () => request.anonymous!.inputs[0]!),
      },
    });
    expect(wide["circuitType"]).toBe("custom-ring-base-anonymous-wide");
    expect(() => customRingBaseProofRequest({ ...request, nIn: 13 })).toThrow(
      "CLIENT_INVALID_PROOF_INPUTS",
    );
  });

  it("rebuilds the anonymous policy request", () => {
    const wire = golden("custom-ring-policy-anonymous");
    const limitCount = Number(decoder.integer(wire["limitCount"], "limitCount"));
    const request: CustomRingPolicyProofRequest = {
      ...audit(wire),
      nIn: Number(decoder.integer(wire["nIn"], "nIn")),
      nOut: Number(decoder.integer(wire["nOut"], "nOut")),
      inputs: list(wire, "inputs").map(opening),
      outputs: list(wire, "outputs").map(opening),
      addressChain: field(wire["addressChain"]),
      privateTxBlinding: field(wire["privateTxBlinding"]),
      sources: list(wire, "sources").map((value) => {
        const row = decoder.record(value, "source");
        return {
          listId: Number(decoder.integer(row["listId"], "listId")),
          registry: field(row["registry"]),
        };
      }),
      policyLen: Number(decoder.integer(wire["policyLen"], "policyLen")),
      rules: list(wire, "ruleEnc").map(field),
      inlineAssets: list(wire, "inlineAssets").map(field),
      inlineLimits: list(wire, "inlineLimits").map(integer),
      inlineCount: Number(decoder.integer(wire["inlineCount"], "inlineCount")),
      treeSlots: list(wire, "treeSlots").map((value) => {
        const row = decoder.record(value, "treeSlot");
        return {
          id: Number(integer(row["id"])),
          utxoRoot: field(row["utxoRoot"]),
          nullifierRoot: field(row["nullifierRoot"]),
        };
      }),
      addressTreeId: Number(integer(wire["addressTreeId"])),
      limits: {
        limits: list(wire, "limits")
          .slice(0, limitCount)
          .map((value) => {
            const row = decoder.record(value, "limit");
            return {
              asset: field(row["asset"]),
              cap: integer(row["cap"]),
              cosignAbove: integer(row["cosignAbove"]),
            };
          }),
        ringId: field(wire["ringId"]),
        namespaceOwnerHash: field(wire["namespaceOwnerHash"]),
        approvalRequired: decoder.boolean(wire["approvalRequired"], "approvalRequired"),
      },
      keyEscrow: decoder.boolean(wire["keyEscrow"], "keyEscrow"),
      memberRegistryRoot: field(wire["memberRegistryRoot"]),
      subjects: list(wire, "subjects").map(subject),
      foreignRoot: field(wire["foreignRoot"]),
      foreignSubjects: list(wire, "foreignSubjects").map(subject),
      anonymous: anonymousParts(wire),
    };
    const body = customRingPolicyProofRequest(request);
    expect(body).toEqual(wire);
    const shaped = customRingPolicyProofRequest({
      ...request,
      nOut: 2,
      shape: { inputs: 2, outputs: 2 },
      inputs: request.inputs.slice(0, 2),
      outputs: request.outputs.slice(0, 2),
      subjects: Array.from({ length: 6 }, () => undefined),
      foreignSubjects: Array.from({ length: 6 }, () => undefined),
    });
    expect(shaped["circuitType"]).toBe("custom-ring-policy-2-2-anonymous");
  });

  it("writes the hidden owner fields of the anonymous SPP request like Rust", () => {
    const zero = asField(0n);
    const inputs: ProverInputs = {
      circuit: "transferEddsaRing",
      payload: {
        inputs: [],
        outputs: [],
        treeSlots: [],
        outputTreeId: zero,
        externalDataHash: zero,
        privateTxHash: zero,
        blindingSeed: asField(1n),
        publicAssets: [],
        publicAmounts: [],
        ringProgramId: zero,
        signerPublicKeyHashes: [],
        inputFlags: zero,
        publishedOutputOwnerPublicKeyHashes: [],
        cacheTreeId: zero,
        cacheReadHashChain: zero,
        cacheReadHashes: [],
        cacheIsCached: [],
        cacheReadIndex: [],
        publicInputHash: zero,
      },
      authorization: {
        ownerPublicKey: filled(1) as Bytes32,
        ownerSignature: filled(2, 64) as Bytes64,
        ringProgramAddress: filled(5) as Bytes32,
        messageDigest: Uint8Array.from({ length: 32 }, (_, index) => index) as Bytes32,
        defaultOwnerPkHash: filled(3) as Bytes32,
        parties: [filled(4) as Bytes32, filled(0) as Bytes32, filled(6) as Bytes32],
      },
    };
    const body = proverRequestBody(inputs);
    expect(body["circuitType"]).toBe("transfer-eddsa-ring");
    expect(body["ownerPublicKey"]).toBe(`0x${"01".repeat(32)}`);
    expect(body["ownerSignature"]).toBe(`0x${"02".repeat(64)}`);
    expect(body["ringProgramAddress"]).toBe(`0x${"05".repeat(32)}`);
    expect(body["messageHashHigh"]).toBe("0x000102030405060708090a0b0c0d0e0f");
    expect(body["messageHashLow"]).toBe("0x101112131415161718191a1b1c1d1e1f");
    expect(body["defaultOwnerPkHash"]).toBe(`0x3${"03".repeat(31)}`);
    expect(body["payerPkHash"]).toBe(`0x4${"04".repeat(31)}`);
    expect(body["cosignerPkHash"]).toBe("0x0");
    expect(body["exitDestinationPkHash"]).toBe(`0x6${"06".repeat(31)}`);
    const go = decoder.record(
      JSON.parse(
        readFileSync(
          new URL(
            "../../../prover/server/prover/transfer_eddsa/testdata/eddsa-ring-2x2.json",
            import.meta.url,
          ),
          "utf8",
        ),
      ),
      "go",
    );
    for (const key of Object.keys(go)) expect(body).toHaveProperty(key);
  });
});

describe("anonymous transact selector", () => {
  it("encodes the Rust anonymous settlement vector", () => {
    const data: TransactInstructionData = {
      expiryUnixTs: 0n,
      privateTxHash: filled(1) as Bytes32,
      circuit: {
        kind: "anonymousRingEddsa",
        inputs: 1,
        outputs: 2,
        publicAssetSlots: 1,
        proofData: {
          bsb22Commitment: {
            commitment: filled(21) as Bytes32,
            commitmentPok: filled(22) as Bytes32,
          },
        },
      },
      txViewingPk: filled(2, 33) as Bytes33,
      salt: filled(3, 16) as Bytes16,
      proof: { a: filled(0) as Bytes32, b: filled(0, 128) as Bytes128, c: filled(0) as Bytes32 },
      interfaceTransfers: [
        { kind: "solWithdrawal", amount: 7n },
        { kind: "splWithdrawal", amount: 9n, splInterfaceBump: 254 },
      ],
      dataHash: filled(4) as Bytes32,
      ringDataHash: filled(5) as Bytes32,
      outputs: [
        {
          utxoHash: filled(6) as Bytes32,
          ownerTag: { kind: "inline", value: filled(7) as Bytes32 },
          data: Uint8Array.of(8, 9),
        },
        { utxoHash: filled(10) as Bytes32, ownerTag: { kind: "account", index: 1 } },
      ],
      messages: [{ viewTag: filled(11) as Bytes32, data: Uint8Array.of(12, 13, 14) }],
      inputs: [{ nullifierHash: filled(20) as Bytes32, treeIndex: 0 }],
      treeContexts: [{ utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 }],
    };
    const pinned = readFileSync(
      new URL("../../../test-vectors/anonymous_ring_settlement.hex", import.meta.url),
      "utf8",
    ).trim();
    expect(Buffer.from(encodeTransactInstructionData(data)).toString("hex")).toBe(pinned);
    const owner = filled(9) as Bytes32;
    const withOwner = encodeTransactInstructionData({
      ...data,
      circuit: { ...data.circuit, proofData: { ...proofData(data), defaultOwnerTag: owner } },
    } as TransactInstructionData);
    expect(Buffer.from(withOwner).toString("hex")).toBe(
      pinned.replace(
        `${"16".repeat(32)}00${"00".repeat(32)}`,
        `${"16".repeat(32)}01${"09".repeat(32)}`,
      ),
    );
  });
});

function proofData(data: TransactInstructionData) {
  if (data.circuit.kind !== "anonymousRingEddsa") throw new Error("not anonymous");
  return data.circuit.proofData;
}

function seed(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function keypair(value: number): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed(value)));
}

function ringAddress(owner: ShieldedKeypair, ring: Address = RING, inbox = 0): RingAddress {
  return new RingAddress({
    recipient: owner.shieldedAddress(),
    ringProgramId: ring,
    inboxSecret: owner.viewingKey().inboxSecret(inbox),
  });
}

const SENDER = keypair(3);
const RECIPIENT = keypair(4);
const SENDER_TWIN = ShieldedKeypair.withViewingKey(
  SigningKey.fromEd25519Bytes(seed(3)),
  keypair(8).viewingKey(),
);
const PAYER = keypair(9).shieldedAddress().solanaAddress();
const AUDITOR = X25519Keypair.fromBytes(filled(0x33) as Bytes32);

/** A 10 SOL ring note of the sender paying 4 to the recipient's address in a 2x2 transfer. */
function prepared(
  input: Readonly<{
    payer?: Address;
    shape?: Readonly<{ inputs: number; outputs: number }>;
    payments?: readonly AnonymousRingPayment[];
  }> = {},
): AnonymousPreparedTransfer {
  return AnonymousPreparedTransfer.prepare(
    ringTransfer(input),
    input.payments ?? [inboxPayment(ringAddress(RECIPIENT))],
  );
}

function inboxPayment(address: RingAddress): AnonymousRingPayment {
  return { to: { kind: "address", address }, asset: SOL_MINT, amount: 4n };
}

function slotOf(proofInputs: SppProofInputs, amount: bigint): number {
  return proofInputs.outputs.findIndex((output) => !output.isDummy() && output.amount === amount);
}

function ringTransfer(
  input: Readonly<{ payer?: Address; shape?: Readonly<{ inputs: number; outputs: number }> }>,
): ConfidentialTransfer {
  const spend = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: SENDER.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: seed(6),
      ringProgramId: RING,
    }),
    SENDER,
  );
  return new ConfidentialTransfer(SENDER.shieldedAddress(), [spend], input.payer ?? PAYER)
    .withRingProgramId(RING)
    .withShape(input.shape ?? { inputs: 2, outputs: 2 });
}

async function configAccount(mode: number) {
  const [config, bump] = await getProgramDerivedAddress({
    programAddress: RING,
    seeds: [new TextEncoder().encode("config")],
  });
  return async (account: Address) =>
    account === config
      ? {
          owner: RING,
          lamports: 1n,
          data: Uint8Array.from([
            1,
            ...new Uint8Array(32),
            ...AUDITOR.publicKey().toBytes(),
            bump,
            0,
            mode,
          ]),
        }
      : undefined;
}

interface Captured {
  spp?: AnonymousRingTransactProofInput;
  base?: CustomRingBaseProofRequest;
  /** Payer, co-signer and exit identities the SPP proof binds. */
  parties?: readonly Bytes32[];
}

async function anonymousClient(
  mode = 2,
  captured: Captured = {},
  accounts: ReadonlyMap<Address, RpcAccount> = new Map(),
): Promise<AnonymousRingTransferClient> {
  const config = await configAccount(mode);
  return {
    ...ringTransferClient({
      tree: TREE,
      getAccount: async (account) => accounts.get(account) ?? config(account),
      proveCustomRingBase: async (request) => {
        captured.base = request;
        return new Uint8Array(192);
      },
    }),
    getShieldedTransactionsByTags: async () => transactionsPage(),
    proveAnonymousRingTransact: async (input) => {
      captured.spp = input;
      const circuit: TransferCircuit = {
        kind: "ringAnonymous",
        ring: input.ringProgramId,
        owner: input.owner,
        ...(input.cosigner === undefined ? {} : { cosigner: input.cosigner }),
        ...(input.exitTokenOwner === undefined ? {} : { exitTokenOwner: input.exitTokenOwner }),
      };
      const assembly = prepareTransfer(input.proofInputs, circuit);
      if ("authorization" in assembly.inputs)
        captured.parties = assembly.inputs.authorization?.parties;
      const finished = assembly.finish([
        {
          treeId: 0,
          slot: { id: 0, utxoRoot: seed(1), nullifierRoot: seed(2) },
          utxoRootIndex: 0,
          nullifierRootIndex: 0,
        },
      ]);
      return {
        data: finished.withProof(
          { a: seed(0), b: filled(0, 128) as Bytes128, c: seed(0) },
          { commitment: seed(7), commitmentPok: seed(8) },
        ),
        roots: finished.roots,
      };
    },
  };
}

async function transfer(
  overrides: Partial<Parameters<typeof proveAnonymousRingTransfer>[0]> = {},
  captured: Captured = {},
  mode = 2,
) {
  const keys = LocalKeys.fromKeypair(SENDER, {
    prove: () => Promise.reject(new Error("unused")),
    proveMerge: () => Promise.reject(new Error("unused")),
  });
  return proveAnonymousRingTransfer({
    client: await anonymousClient(mode, captured),
    ringProgramId: RING,
    prepared: prepared(),
    keys,
    assets: new AssetRegistry(),
    tree: TREE,
    signer: signingKeySpendSigner(SigningKey.fromEd25519Bytes(seed(3))),
    viewingKey: SENDER.viewingKey(),
    ...overrides,
  });
}

describe("anonymous ring transfer", () => {
  it("sends a viewing key for a ring output only, an exit and padding send zeros", () => {
    const ring = createProofOutput({
      ownerAddress: RECIPIENT.shieldedAddress(),
      asset: SOL_MINT,
      amount: 4n,
      blinding: seed(1),
      ringProgramId: RING,
    });
    const exit = createProofOutput({
      ownerAddress: keypair(10).shieldedAddress(),
      asset: SOL_MINT,
      amount: 3n,
      blinding: seed(2),
    });
    const padding = createProofOutput({ asset: SOL_MINT, amount: 0n, ringProgramId: RING });
    const identities = anonymousIdentities(SENDER.shieldedAddress(), [ring, exit, padding]);
    expect(identities.recipientViewingKeys).toEqual([
      RECIPIENT.shieldedAddress().viewingPublicKey.toBytes(),
      new Uint8Array(33),
      new Uint8Array(33),
      new Uint8Array(33),
    ]);
    expect(identities.recipients.map((identity) => identity[0])).toEqual([
      SOLANA_OWNER_TAG,
      SOLANA_OWNER_TAG,
      0,
      0,
    ]);
  });

  it("seals a 2x2 transfer the recipient opens and binds the hidden owner's signature", async () => {
    const captured: Captured = {};
    const proven = await transfer({}, captured);
    const spp = captured.spp!;
    const base = captured.base!;
    const proofInputs = spp.proofInputs;
    const external = proofInputs.externalData;
    const slot = proofInputs.outputs.findIndex(
      (output) =>
        output.ownerAddress !== undefined &&
        output.ownerAddress.signingPublicKey.equals(RECIPIENT.signingPublicKey()),
    );
    // The first payment to the address takes inbox index zero.
    expect(external.resolvedOwnerTags[slot]).toEqual(
      ringAddress(RECIPIENT).inboxSecret.viewTag(0n),
    );
    const ciphertext = base.anonymous!.delivery.outputs[slot]!.ciphertext;
    const opened = decodeRingAnonymous(
      RECIPIENT.viewingKey().openAnonymousOutput(
        ciphertext,
        external.txViewingPublicKey,
        external.salt,
        slot,
      ),
    );
    expect(opened.amount).toBe(4n);
    expect(
      SigningKey.fromEd25519Bytes(seed(3)).verify(
        ringSpendMessage(RING, proofInputs.messageHash()),
        spp.owner.signature,
      ),
    ).toBe(true);
    expect(spp.owner.publicKey).toEqual(SENDER.signingPublicKey().ed25519());
    expect(proven.ownerSigners).toEqual([]);
    expect(proven.data.circuit.kind).toBe("anonymousRingEddsa");
    expect(external.messages).toHaveLength(1);
    expect(external.instructionDiscriminator).toBe(InstructionTag.ringTransact);

    const message = parseAuditorMessage(external.messages[0]!.data, {
      anonymous: true,
      inputs: 2,
      outputs: 2,
    });
    const bodies = external.outputs.map((output) =>
      ringAnonymousBodyHash(readOutputData(output.data!).body),
    );
    expect(base.publicInputHash).toEqual(
      auditPublicInputHash({
        privateTxHash: proven.data.privateTxHash,
        txViewingPublicKey: external.txViewingPublicKey,
        auditorPublicKey: AUDITOR.publicKey(),
        message,
        outputHashes: external.outputs.map((output) => output.utxoHash),
        outputBodyHashes: bodies,
        salt: external.salt,
        anonymous: true,
      }),
    );
    expect(base.nIn).toBe(2);
    expect(base.anonymous!.inputs).toHaveLength(4);
    expect(base.anonymous!.identities.sender).toEqual(
      Uint8Array.of(SOLANA_OWNER_TAG, ...SENDER.signingPublicKey().ed25519()),
    );

    const instruction = await ringTransactInstruction({
      ringProgramId: RING,
      payer: proven.payer,
      inputTrees: proven.inputTrees,
      outputTree: proven.outputTree,
      proof: proven.proof,
      data: proven.data,
    });
    const signers = instruction.accounts?.filter(
      (account) =>
        account.role === AccountRole.READONLY_SIGNER ||
        account.role === AccountRole.WRITABLE_SIGNER,
    );
    expect(signers?.map((account) => account.address)).toEqual([PAYER]);
  });

  it("refuses the rail and the spends the ring program refuses before any prover round", async () => {
    await expect(transfer({}, {}, 0)).rejects.toMatchObject({ code: "RING_NOT_ANONYMOUS" });
    await expect(
      transfer({ signer: signingKeySpendSigner(SigningKey.fromEd25519Bytes(seed(5))) }),
    ).rejects.toMatchObject({ code: "RING_ANONYMOUS_SIGNER_MISMATCH" });
    await expect(
      transfer({ prepared: prepared({ payer: SENDER.shieldedAddress().solanaAddress() }) }),
    ).rejects.toMatchObject({ code: "RING_ANONYMOUS_SIGNER_LINKS_OWNER" });
    await expect(
      transfer({ prepared: prepared({ shape: { inputs: 1, outputs: 8 } }) }),
    ).rejects.toMatchObject({ code: "RING_ANONYMOUS_SHAPE_UNSUPPORTED" });
    for (const owner of [RECIPIENT, SENDER_TWIN]) {
      const unpaired = ringTransfer({});
      unpaired.send(owner.shieldedAddress(), SOL_MINT, 4n);
      const captured: Captured = {};
      await expect(
        transfer({ prepared: AnonymousPreparedTransfer.prepare(unpaired, []) }, captured),
      ).rejects.toMatchObject({ code: "RING_ANONYMOUS_RECIPIENT_UNKNOWN" });
      expect(captured).toEqual({});
    }
    await expect(
      transfer({
        prepared: prepared({
          payments: [
            {
              to: { kind: "paired", address: ringAddress(RECIPIENT, PAYER) },
              asset: SOL_MINT,
              amount: 4n,
            },
          ],
        }),
      }),
    ).rejects.toMatchObject({ code: "RING_FOREIGN_RING" });
    const keys = LocalKeys.fromKeypair(SENDER, {
      prove: () => Promise.reject(new Error("unused")),
      proveMerge: () => Promise.reject(new Error("unused")),
    });
    await expect(
      proveCustomRingTransfer({
        client: {
          ...(await anonymousClient()),
          proveRingTransact: () => Promise.reject(new Error("unused")),
        },
        ringProgramId: RING,
        prepared: prepared().transfer,
        keys,
        assets: new AssetRegistry(),
        tree: TREE,
      }),
    ).rejects.toMatchObject({ code: "RING_ANONYMOUS_SIGNER_REQUIRED" });
  });

  it("tags each payment from the inbox stream of the address it pays", async () => {
    // Two requests of one wallet share the shielded address and differ in the inbox secret.
    const first = ringAddress(RECIPIENT, RING, 0);
    const second = ringAddress(RECIPIENT, RING, 1);
    for (const order of [
      [
        { address: first, amount: 2n },
        { address: second, amount: 3n },
      ],
      [
        { address: second, amount: 3n },
        { address: first, amount: 2n },
      ],
    ]) {
      const captured: Captured = {};
      await transfer(
        {
          prepared: prepared({
            shape: { inputs: 2, outputs: 4 },
            payments: order.map(({ address, amount }) => ({
              to: { kind: "address", address },
              asset: SOL_MINT,
              amount,
            })),
          }),
        },
        captured,
      );
      const proofInputs = captured.spp!.proofInputs;
      for (const { address, amount } of order) {
        const slot = proofInputs.outputs.findIndex(
          (output) =>
            output.amount === amount &&
            output.ownerAddress?.signingPublicKey.equals(RECIPIENT.signingPublicKey()),
        );
        expect(proofInputs.externalData.resolvedOwnerTags[slot]).toEqual(
          address.inboxSecret.viewTag(0n),
        );
      }
    }
  });

  it("tags a payment to the sender's own address from its inbox and the builder's change as change", async () => {
    const own = ringAddress(SENDER, RING, 7);
    const captured: Captured = {};
    await transfer({ prepared: prepared({ payments: [inboxPayment(own)] }) }, captured);
    const proofInputs = captured.spp!.proofInputs;
    const tags = proofInputs.externalData.resolvedOwnerTags;
    const change = slotOf(proofInputs, 6n);
    expect(tags[slotOf(proofInputs, 4n)]).toEqual(own.inboxSecret.viewTag(0n));
    expect(tags[change]).toEqual(
      SENDER.viewingKey().ringChangeViewTag(proofInputs.firstNullifier(), change),
    );
  });

  it("seals a payment sharing the sender's signing and nullifier keys to its own viewing key", async () => {
    const address = ringAddress(SENDER_TWIN);
    const captured: Captured = {};
    await transfer({ prepared: prepared({ payments: [inboxPayment(address)] }) }, captured);
    const external = captured.spp!.proofInputs.externalData;
    const slot = slotOf(captured.spp!.proofInputs, 4n);
    expect(external.resolvedOwnerTags[slot]).toEqual(address.inboxSecret.viewTag(0n));
    const opened = decodeRingAnonymous(
      SENDER_TWIN.viewingKey().openAnonymousOutput(
        readOutputData(external.outputs[slot]!.data!).body,
        external.txViewingPublicKey,
        external.salt,
        slot,
      ),
    );
    expect(opened.amount).toBe(4n);
  });

  it("refuses every published slot the ring program would refuse", async () => {
    const captured: Captured = {};
    await transfer({}, captured);
    const proofInputs = captured.spp!.proofInputs;
    expect(() => checkAnonymousOutputs(proofInputs)).not.toThrow();
    const external = proofInputs.externalData;
    const variant = (outputs: readonly TransactOutput[]): SppProofInputs =>
      new SppProofInputs({
        payer: proofInputs.payer,
        inputUtxos: proofInputs.inputUtxos,
        outputs: proofInputs.outputs,
        externalData: createExternalData({ ...external, outputs }),
        blindingSeed: proofInputs.blindingSeed,
        outputTreeId: proofInputs.outputTreeId,
      });
    const [first, second] = external.outputs as [TransactOutput, TransactOutput];
    const tagged = (tag: Uint8Array): TransactOutput => ({
      ...second,
      ownerTag: { kind: "inline", value: tag as Bytes32 },
    });
    const cases: readonly [readonly TransactOutput[], string][] = [
      [[first], "RING_ANONYMOUS_OUTPUT_COUNT"],
      [
        [first, { ...second, data: second.data!.subarray(0, second.data!.length - 1) }],
        "RING_ANONYMOUS_OUTPUT_SCHEME",
      ],
      [[first, tagged(filled(1))], "RING_ANONYMOUS_TAG"],
      [[first, tagged(new Uint8Array(32))], "RING_ANONYMOUS_TAG"],
      [[first, { ...second, ownerTag: { kind: "account", index: 0 } }], "RING_ANONYMOUS_TAG"],
      [[first, { ...second, ownerTag: first.ownerTag }], "RING_ANONYMOUS_DUPLICATE_TAG"],
      [
        [first, { ...second, utxoHash: new Uint8Array(32) as Bytes32 }],
        "RING_ANONYMOUS_OUTPUT_HASH",
      ],
      [[first, { ...second, data: shortBody(second.data!) }], "RING_ANONYMOUS_OUTPUT_BODY"],
    ];
    for (const [outputs, code] of cases) {
      expect(() => checkAnonymousOutputs(variant(outputs))).toThrow(code);
    }
  });

  it("refuses a hidden owner signature over another digest before proving", async () => {
    const captured: Captured = {};
    await transfer({}, captured);
    const spp = captured.spp!;
    const circuit = (signature: Uint8Array, publicKey = spp.owner.publicKey): TransferCircuit => ({
      kind: "ringAnonymous",
      ring: RING,
      owner: { publicKey, signature: signature as Bytes64 },
    });
    expect(() =>
      prepareTransfer(
        spp.proofInputs,
        circuit(SigningKey.fromEd25519Bytes(seed(3)).sign(filled(1))),
      ),
    ).toThrow("CLIENT_ANONYMOUS_SPEND_SIGNATURE_INVALID");
    expect(() =>
      prepareTransfer(
        spp.proofInputs,
        circuit(spp.owner.signature, RECIPIENT.signingPublicKey().ed25519()),
      ),
    ).toThrow("CLIENT_ANONYMOUS_PROOF_WITHOUT_HIDDEN_INPUT");
  });
});

/** A scheme-9 frame one byte short, the length prefix rewritten so only the body length is wrong. */
function shortBody(data: Uint8Array): Uint8Array {
  const frame = readOutputData(data);
  const body = frame.body.subarray(0, frame.body.length - 1);
  const out = new Uint8Array(5 + 1 + body.length);
  out[0] = data[0]!;
  new DataView(out.buffer).setUint32(1, 1 + body.length, true);
  out[5] = data[5]!;
  out.set(body, 6);
  return out;
}

const MINT = address("So11111111111111111111111111111111111111112");
const HIDDEN = SENDER.shieldedAddress().solanaAddress();
const STRANGER = keypair(10).shieldedAddress().solanaAddress();
/** A keypair address, on the ed25519 curve. */
const DESTINATION = keypair(11).shieldedAddress().solanaAddress();
const TOKEN_ACCOUNT = await associatedTokenAddress(STRANGER, MINT, SPL_TOKEN_PROGRAM_ID);

function withdrawal(asset: Address, target: WithdrawalTarget): AnonymousPreparedTransfer {
  const spend = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: SENDER.signingPublicKey(),
      asset,
      amount: 10n,
      blinding: seed(6),
      ringProgramId: RING,
    }),
    SENDER,
  );
  const transfer = new ConfidentialTransfer(SENDER.shieldedAddress(), [spend], PAYER)
    .withRingProgramId(RING)
    .withShape({ inputs: 2, outputs: 2 });
  transfer.withdraw(asset, 4n, target);
  return AnonymousPreparedTransfer.prepare(transfer, []);
}

async function splWithdrawal(destination: Address) {
  const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(MINT);
  return {
    prepared: withdrawal(
      MINT,
      WithdrawalTarget.spl({
        recipientTokenAccount: destination,
        splTokenInterface,
        splInterfaceBump,
      }),
    ),
    transaction: {
      withdrawal: TransactWithdrawal.spl({
        mint: MINT,
        splTokenInterface,
        recipientTokenAccount: destination,
        tokenProgram: SPL_TOKEN_PROGRAM_ID,
      }),
    },
  };
}

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

describe("anonymous ring withdrawal destination", () => {
  it("refuses an SPL destination naming the hidden owner or a second key before proving", async () => {
    const associated = await associatedTokenAddress(HIDDEN, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Address, RpcAccount | undefined, string])[] = [
      [TOKEN_ACCOUNT, tokenAccount(HIDDEN), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [HIDDEN, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
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
      const captured: Captured = {};
      const accounts = new Map(account === undefined ? [] : [[destination, account] as const]);
      await expect(
        transfer({
          ...(await splWithdrawal(destination)),
          client: await anonymousClient(2, captured, accounts),
        }),
      ).rejects.toMatchObject({ code, details: { destination } });
      expect(captured).toEqual({});
    }
  });

  it("refuses a SOL recipient that is the hidden owner or holds data before proving", async () => {
    for (const [recipient, account, code] of [
      [HIDDEN, undefined, "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA"],
      [
        DESTINATION,
        { owner: SYSTEM_PROGRAM, lamports: 1n, data: new Uint8Array(80) },
        "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA",
      ],
    ] as const) {
      const captured: Captured = {};
      const accounts = new Map(account === undefined ? [] : [[recipient, account] as const]);
      await expect(
        transfer({
          prepared: withdrawal(SOL_MINT, WithdrawalTarget.sol({ recipient })),
          transaction: { withdrawal: TransactWithdrawal.sol({ recipient }) },
          client: await anonymousClient(2, captured, accounts),
        }),
      ).rejects.toMatchObject({ code, details: { destination: recipient } });
      expect(captured).toEqual({});
    }
  });

  const tokenOwnerOf = (account: RpcAccount) =>
    anonymousExitTokenOwner({
      client: { getAccount: async (key) => (key === TOKEN_ACCOUNT ? account : undefined) },
      transfers: [
        {
          kind: "spl",
          mint: MINT,
          isDeposit: false,
          amount: 4n,
          tokenAccount: TOKEN_ACCOUNT,
          splInterfaceBump: 255,
        },
      ],
      hiddenOwner: addressBytes(HIDDEN) as Bytes32,
    });

  const token2022 = (
    tail: readonly number[],
    edit: (data: Uint8Array) => void = () => undefined,
  ) => {
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
    await expect(tokenOwnerOf(account)).rejects.toMatchObject({
      code,
      details: { destination: TOKEN_ACCOUNT },
    });
  });

  it("binds the SPL token account owner or the SOL recipient, never the token account", async () => {
    const spl: Captured = {};
    await transfer({
      ...(await splWithdrawal(TOKEN_ACCOUNT)),
      client: await anonymousClient(2, spl, new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]])),
    });
    expect(spl.spp?.exitTokenOwner).toBe(STRANGER);
    expect(spl.parties?.[2]).toEqual(solanaOwnerIdentity(addressBytes(STRANGER)));
    const sol: Captured = {};
    await transfer({
      prepared: withdrawal(SOL_MINT, WithdrawalTarget.sol({ recipient: DESTINATION })),
      transaction: { withdrawal: TransactWithdrawal.sol({ recipient: DESTINATION }) },
      client: await anonymousClient(2, sol),
    });
    expect(sol.spp?.exitTokenOwner).toBeUndefined();
    expect(sol.parties?.[2]).toEqual(solanaOwnerIdentity(addressBytes(DESTINATION)));
    // The builder takes the token owner exactly when an SPL leg withdraws.
    for (const [run, exitTokenOwner] of [
      [spl, undefined],
      [sol, STRANGER],
    ] as const) {
      const spp = run.spp!;
      expect(() =>
        prepareTransfer(spp.proofInputs, {
          kind: "ringAnonymous",
          ring: RING,
          owner: spp.owner,
          ...(exitTokenOwner === undefined ? {} : { exitTokenOwner }),
        }),
      ).toThrow("CLIENT_ANONYMOUS_EXIT_TOKEN_OWNER_MISMATCH");
    }
  });
});
