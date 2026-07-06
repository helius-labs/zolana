import { describe, expect, it, vi } from "vitest";
import {
  ProverClient,
  bigUintToString,
  proofFromGnarkJson,
  transactProofFromJson,
  toJson,
  toJsonBatchAddressAppend,
  toJsonMerge,
  toJsonZoneAuthority,
  type BatchAddressAppendInputs,
  type MergeInputs,
  type TransferInput,
  type TransferInputs,
  type TransferOutput,
  type UtxoInputs,
} from "../src/index.js";

const zeroUtxo = (): UtxoInputs => ({
  domain: 1n,
  owner: 2n,
  asset: 1n,
  amount: 5n,
  blinding: 7n,
  dataHash: 0n,
  zoneDataHash: 0n,
  zoneProgramId: 0n,
});

const input = (): TransferInput => ({
  utxo: zeroUtxo(),
  isDummy: 0n,
  statePathElements: Array.from({ length: 32 }, () => 0n),
  statePathIndex: 0n,
  nullifierLowValue: 0n,
  nullifierNextValue: 0n,
  nullifierLowPathElements: Array.from({ length: 40 }, () => 0n),
  nullifierLowPathIndex: 0n,
  utxoTreeRoot: 11n,
  nullifierTreeRoot: 13n,
  nullifier: 99n,
  ownerPkHash: 7n,
  nullifierSecret: 4n,
});

const output = (): TransferOutput => ({
  utxo: zeroUtxo(),
  isDummy: 0n,
  hash: 0xabcn,
  ownerPkHash: 0n,
  nullifierPk: 0n,
});

const transfer = (): TransferInputs => ({
  inputs: [input()],
  outputs: [output()],
  externalDataHash: 6n,
  privateTxHash: 7n,
  publicSolAmount: 0n,
  publicSplAmount: 0n,
  publicSplAssetPubkey: 0n,
  zoneProgramId: 0x55n,
  payerPubkeyHash: 8n,
  publicInputHash: 9n,
});

describe("prover JSON", () => {
  it("formats bigints as lower-case hex strings", () => {
    expect(bigUintToString(0xabcn)).toBe("0xabc");
  });

  it("serializes transfer and zone-authority requests", () => {
    const value = JSON.parse(toJsonZoneAuthority(transfer()));

    expect(value.circuitType).toBe("transfer-zone-authority");
    expect(value.nInputs).toBe(1);
    expect(value.nOutputs).toBe(1);
    expect(value.inputs[0].utxo.domain).toBe("0x1");
    expect(value.outputs[0].hash).toBe("0xabc");
    expect(value.zoneProgramId).toBe("0x55");
    expect(value.p256PubX).toBeUndefined();
    expect(JSON.parse(toJson(transfer())).circuitType).toBe("transfer-confidential");
  });

  it("serializes merge requests with the Rust key set", () => {
    const merge: MergeInputs = {
      inputs: Array.from({ length: 8 }, input),
      output: output(),
      p256PubX: 1n,
      p256PubY: 2n,
      ownerPkHash: 0n,
      userNullifierPk: 3n,
      userNullifierSecret: 4n,
      txViewingSk: 5n,
      userViewingPubkey: Array.from({ length: 65 }, (_, i) => BigInt(i)),
      externalDataHash: 6n,
      privateTxHash: 7n,
      publicInputHash: 8n,
      zoneProgramId: 0n,
    };
    const value = JSON.parse(toJsonMerge(merge));

    expect(value.circuitType).toBe("merge");
    expect(value.inputs).toHaveLength(8);
    expect(value.userViewingPubkey).toHaveLength(65);
    expect(value.output.hash).toBe("0xabc");
    expect(value.zoneProgramId).toBe("0x0");
  });

  it("serializes batch address-append requests", () => {
    const inputs: BatchAddressAppendInputs = {
      publicInputHash: 1n,
      oldRoot: 2n,
      newRoot: 3n,
      hashchainHash: 4n,
      startIndex: 5,
      lowElementValues: [6n, 7n],
      lowElementIndices: [8n, 9n],
      lowElementNextValues: [10n, 11n],
      newElementValues: [12n, 13n],
      lowElementProofs: [[14n, 15n], [16n, 17n]],
      newElementProofs: [[18n, 19n], [20n, 21n]],
      treeHeight: 40,
      batchSize: 2,
    };
    const value = JSON.parse(toJsonBatchAddressAppend(inputs));

    expect(value.circuitType).toBe("address-append");
    expect(value.stateTreeHeight).toBe(0);
    expect(value.lowElementValues).toEqual(["0x6", "0x7"]);
    expect(value.lowElementProofs).toEqual([["0xe", "0xf"], ["0x10", "0x11"]]);
  });

  it("parses gnark proof envelopes returned by the server", async () => {
    const proofJson = {
      ar: ["0x1", "0x2"],
      bs: [["0x3", "0x4"], ["0x5", "0x6"]],
      krs: ["0x7", "0x8"],
      proof_commitment: ["0x9", "0xa"],
      proof_commitment_pok: ["0xb", "0xc"],
    };
    const proof = proofFromGnarkJson(JSON.stringify(proofJson));
    expect(proof?.a).toHaveLength(64);
    expect(proof?.b).toHaveLength(128);
    expect(proof?.c).toHaveLength(64);
    expect(proof?.commitment?.commitment).toHaveLength(64);

    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ proof: proofJson })));
    const client = new ProverClient("http://example.invalid", fetchImpl as unknown as typeof fetch);
    const response = await client.proveTransfer(transfer());
    expect(response.c).toHaveLength(64);
    expect(fetchImpl).toHaveBeenCalledWith("http://example.invalid/prove", expect.any(Object));
  });

  it("requests server-side transact proof formatting", async () => {
    const transactProof = {
      kind: "p256",
      a: `0x${"01".repeat(32)}`,
      b: `0x${"02".repeat(64)}`,
      c: `0x${"03".repeat(32)}`,
      commitment: `0x${"04".repeat(32)}`,
      commitment_pok: `0x${"05".repeat(32)}`,
    };
    const parsed = transactProofFromJson(JSON.stringify(transactProof));
    expect(parsed.kind).toBe("p256");
    expect(parsed.a).toHaveLength(32);
    expect(parsed.b).toHaveLength(64);
    if (parsed.kind === "p256") {
      expect(parsed.commitmentPok).toHaveLength(32);
    }

    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(transactProof)));
    const client = new ProverClient("http://example.invalid", fetchImpl as unknown as typeof fetch);
    await client.proveTransactTransferP256({
      ...transfer(),
      p256PubX: 1n,
      p256PubY: 2n,
      p256SigR: 3n,
      p256SigS: 4n,
      p256MessageHashLow: 5n,
      p256MessageHashHigh: 6n,
      p256SigningPkField: 7n,
    });

    const calls = (fetchImpl as unknown as { mock: { calls: Array<[string, RequestInit]> } }).mock.calls;
    const init = calls[0]?.[1];
    expect(init?.headers).toMatchObject({ "x-zolana-proof-format": "transact" });
  });
});
