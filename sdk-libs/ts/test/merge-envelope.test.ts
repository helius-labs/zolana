import { getAddressEncoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { solInput } from "./helpers/utxos.js";
import { proveThroughAuthority } from "../src/client/prover/indexed.js";
import { assembleMergeWithProofs, prepareMerge } from "../src/client/prover/merge.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../src/interface/tree-slot.js";
import type { Bytes32, Bytes128 } from "../src/interface/types.js";
import {
  P256PublicKey,
  ShieldedKeypair,
  ViewingKey,
  decryptMergeEnvelope,
} from "../src/keypair/index.js";
import { encryptMergeEnvelope } from "../src/keypair/merge/index.js";
import {
  Merge,
  MergeOutputEnvelope,
  PreparedMerge,
  SOL_MINT,
  createProofOutput,
} from "../src/transaction/index.js";

describe("merge envelope guards", () => {
  const owner = ShieldedKeypair.generate();
  const submitTree = treeAddress(DEFAULT_TREE_ID);

  function rebuilt(
    prepared: PreparedMerge,
    change: Readonly<{ envelope?: MergeOutputEnvelope; blinding?: Bytes32 }>,
  ): PreparedMerge {
    return new PreparedMerge({
      inputs: prepared.inputs,
      output:
        change.blinding === undefined
          ? prepared.output
          : createProofOutput({
              ownerAddress: owner.shieldedAddress(),
              asset: prepared.output.asset,
              amount: prepared.output.amount,
              blinding: change.blinding,
            }),
      envelope: change.envelope,
      expiryUnixTs: prepared.expiryUnixTs,
      signingPublicKey: prepared.signingPublicKey,
      nullifierPublicKey: prepared.nullifierPublicKey,
      dummyNullifiers: prepared.dummyNullifiers(),
      privateTxBlinding: prepared.privateTxBlinding(),
      outputTreeId: prepared.outputTreeId,
    });
  }

  it("encrypts a default merge to the owner's viewing key and takes the encrypted blinding", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const encrypted = prepared.encryptedEnvelope();
    expect(prepared.envelope?.recipient.equals(owner.viewingPublicKey())).toBe(true);
    expect(encrypted?.outputBlinding).toEqual(prepared.output.blinding);
    expect(encrypted?.ciphertext).toHaveLength(40);
  });

  it("refuses a default merge without its envelope", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    expect(() => assembleMergeWithProofs(rebuilt(prepared, {}), [], submitTree)).toThrow(
      expect.objectContaining({ code: "CLIENT_MERGE_ENVELOPE_RAIL_MISMATCH" }),
    );
  });

  it("refuses an envelope encrypted to a key other than the output owner's", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const other = ShieldedKeypair.generate();
    try {
      const envelope = new MergeOutputEnvelope({ recipient: other.viewingPublicKey() });
      const blinding = envelope.encrypt(
        prepared.output.amount,
        prepared.output.asset,
      ).outputBlinding;
      expect(() =>
        assembleMergeWithProofs(rebuilt(prepared, { envelope, blinding }), [], submitTree),
      ).toThrow(expect.objectContaining({ code: "CLIENT_MERGE_OUTPUT_MISMATCH" }));
    } finally {
      other.destroy();
    }
  });

  it("refuses an output blinding the envelope does not derive", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const envelope = new MergeOutputEnvelope({ recipient: owner.viewingPublicKey() });
    expect(() => assembleMergeWithProofs(rebuilt(prepared, { envelope }), [], submitTree)).toThrow(
      expect.objectContaining({ code: "CLIENT_OUTPUT_BLINDING_MISMATCH", details: { index: 0 } }),
    );
  });

  it("requires the proof commitment the envelope carries", () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const complete = prepareMerge(prepared, submitTree).finish({
      slot: {
        id: DEFAULT_TREE_ID,
        utxoRoot: new Uint8Array(32) as Bytes32,
        nullifierRoot: new Uint8Array(32) as Bytes32,
      },
      utxoRootIndex: 0,
      nullifierRootIndex: 0,
    });
    const proof = {
      a: new Uint8Array(32),
      b: new Uint8Array(128) as Bytes128,
      c: new Uint8Array(32),
    };
    expect(() => complete.instructionData(proof)).toThrow(
      expect.objectContaining({
        code: "CLIENT_PROOF_PARSE",
        details: { path: "$.proof.proofCommitment", reason: "missing commitment" },
      }),
    );
    const commitment = new Uint8Array(32).fill(3);
    const commitmentPok = new Uint8Array(32).fill(4);
    const encrypted = prepared.encryptedEnvelope();
    const data = complete.instructionData({ ...proof, commitment, commitmentPok });
    expect("proofCommitment" in data ? data.proofCommitment : undefined).toEqual({
      commitment,
      commitmentPok,
    });
    expect("envelope" in data ? data.envelope : undefined).toEqual({
      ephemeralPk: encrypted?.ephemeralPublicKey.toBytes(),
      ciphertext: encrypted?.ciphertext,
    });
  });

  it("refuses an output blinding source of the other rail", () => {
    const input = solInput(owner, 5n);
    const common = {
      address: owner.shieldedAddress(),
      inputs: [input],
      privateTxBlinding: new Uint8Array(32) as Bytes32,
      dummyNullifiers: PreparedMerge.dummySlots(1).map(() => new Uint8Array(32) as Bytes32),
    };
    expect(
      () =>
        new Merge({
          ...common,
          blinding: { kind: "derived", outputBlinding: new Uint8Array(32) as Bytes32 },
        }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_MERGE_BLINDING_RAIL_MISMATCH" }));
  });

  it("proves a default merge an integrator assembles around its own envelope", async () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const envelope = new MergeOutputEnvelope({ recipient: owner.viewingPublicKey() });
    try {
      const blinding = envelope.encrypt(
        prepared.output.amount,
        prepared.output.asset,
      ).outputBlinding;
      const request = await prepareMerge(
        rebuilt(prepared, { envelope, blinding }),
        submitTree,
      ).withInputs((inputs) => inputs);
      expect(request.publicInputs).toHaveLength(12);
    } finally {
      envelope.destroy();
    }
  });

  it("lends the ephemeral secret only while the callback runs", async () => {
    const envelope = new MergeOutputEnvelope({ recipient: owner.viewingPublicKey() });
    try {
      let lent: Uint8Array = new Uint8Array();
      await envelope.withEphemeralSecret(async (secret) => {
        lent = secret;
        expect(secret.some((byte) => byte !== 0)).toBe(true);
      });
      expect(lent).toEqual(new Uint8Array(32));
      await expect(
        envelope.withEphemeralSecret((secret) => {
          lent = secret;
          throw new Error("prover down");
        }),
      ).rejects.toThrow("prover down");
      expect(lent).toEqual(new Uint8Array(32));
    } finally {
      envelope.destroy();
    }
  });

  it("wipes the secret in the prover request once proving settles", async () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    const local = prepareMerge(prepared, submitTree);
    const lent: Uint8Array[] = [];
    await expect(
      local.withInputs((inputs) =>
        proveThroughAuthority(
          {
            proveIndexed(request: Parameters<typeof proveThroughAuthority>[1]) {
              if (request.circuit !== "merge") throw new Error("expected a merge request");
              const secret = request.payload.envelope?.ephemeralSecret;
              if (secret === undefined) throw new Error("expected an envelope");
              expect(secret.some((byte) => byte !== 0)).toBe(true);
              lent.push(secret);
              throw new Error("key holder down");
            },
          },
          inputs,
        ),
      ),
    ).rejects.toThrow("key holder down");
    const request = await local.withInputs((inputs) => inputs);
    const secret = request.payload.envelope?.ephemeralSecret;
    if (secret === undefined) throw new Error("expected an envelope");
    expect([...lent, secret]).toEqual([new Uint8Array(32), new Uint8Array(32)]);
  });

  it("refuses to encrypt or prove with a destroyed envelope", async () => {
    const prepared = Merge.fromKeypair(owner, [solInput(owner, 5n)]).prepare();
    prepared.envelope?.destroy();
    const destroyed = expect.objectContaining({ code: "KEYPAIR_INVALID_SECRET_KEY" });
    expect(() => prepared.encryptedEnvelope()).toThrow(destroyed);
    await expect(prepared.envelope?.withEphemeralSecret((secret) => secret)).rejects.toMatchObject({
      code: "KEYPAIR_INVALID_SECRET_KEY",
    });
    expect(() => prepareMerge(prepared, submitTree)).toThrow(destroyed);
  });
});

describe("merge envelope encryption inputs", () => {
  const recipient = ShieldedKeypair.generate();
  const mint = new Uint8Array(getAddressEncoder().encode(SOL_MINT)) as Bytes32;

  it("refuses an amount outside u64 with its own code", () => {
    const ephemeral = ViewingKey.generate();
    try {
      for (const amount of [-1n, 1n << 64n, 7]) {
        expect(() =>
          Reflect.apply(encryptMergeEnvelope, undefined, [
            { recipient: recipient.viewingPublicKey(), ephemeral, amount, mint },
          ]),
        ).toThrow(expect.objectContaining({ code: "KEYPAIR_INVALID_AMOUNT" }));
      }
    } finally {
      ephemeral.destroy();
    }
  });

  it("revalidates the keys and lengths a caller hands in", () => {
    const ephemeral = ViewingKey.generate();
    const viewingKey = recipient.viewingKey();
    try {
      const encrypted = encryptMergeEnvelope({
        recipient: recipient.viewingPublicKey(),
        ephemeral,
        amount: 7n,
        mint,
      });
      const publicKeyBytes = recipient.viewingPublicKey().toBytes();
      const encryptWith = (input: unknown) => () =>
        Reflect.apply(encryptMergeEnvelope, undefined, [input]);
      const decryptWith = (input: unknown) => () =>
        Reflect.apply(decryptMergeEnvelope, undefined, [input]);
      const valid = { recipient: recipient.viewingPublicKey(), ephemeral, amount: 7n, mint };
      const opened = {
        viewingKey,
        ephemeralPublicKey: encrypted.ephemeralPublicKey,
        ciphertext: encrypted.ciphertext,
      };
      const cases: readonly [() => unknown, string][] = [
        [encryptWith(null), "KEYPAIR_INVALID_INPUT"],
        [
          encryptWith({ ...valid, recipient: { toBytes: () => publicKeyBytes } }),
          "KEYPAIR_INVALID_PUBLIC_KEY",
        ],
        [
          encryptWith({ ...valid, ephemeral: { publicKey: () => recipient.viewingPublicKey() } }),
          "KEYPAIR_INVALID_SECRET_KEY",
        ],
        [encryptWith({ ...valid, mint: mint.subarray(1) }), "KEYPAIR_INVALID_LENGTH"],
        [decryptWith(undefined), "KEYPAIR_INVALID_INPUT"],
        [
          decryptWith({ ...opened, viewingKey: { publicKey: () => recipient.viewingPublicKey() } }),
          "KEYPAIR_INVALID_SECRET_KEY",
        ],
        [
          decryptWith({ ...opened, ephemeralPublicKey: encrypted.ephemeralPublicKey.toBytes() }),
          "KEYPAIR_INVALID_PUBLIC_KEY",
        ],
        [
          decryptWith({ ...opened, ciphertext: encrypted.ciphertext.subarray(1) }),
          "KEYPAIR_INVALID_LENGTH",
        ],
      ];
      for (const [call, code] of cases) {
        expect(call).toThrow(expect.objectContaining({ code }));
      }
      expect(
        decryptMergeEnvelope({
          viewingKey,
          ephemeralPublicKey: P256PublicKey.fromBytes(encrypted.ephemeralPublicKey.toBytes()),
          ciphertext: encrypted.ciphertext,
        }),
      ).toMatchObject({ amount: 7n, mint, outputBlinding: encrypted.outputBlinding });
    } finally {
      ephemeral.destroy();
      viewingKey.destroy();
    }
  });
});
