import fixtureJson from "../../../../prover/server/prover/request/testdata/transfer-2x2.json" with { type: "json" };
import type {
  CircuitUtxo,
  ProverInputs,
  TransferInput,
  TransferOutput,
} from "../../src/client/index.js";
import { asField } from "../../src/client/prover/assembly.js";
import { wireDecoder } from "../../src/interface/decode.js";

// A committed, valid circuit witness, independent of any chain or wallet.
const fixture: unknown = fixtureJson;
const decode = wireDecoder((path) => new Error(`Invalid proof fixture: ${path}`));
const record = decode.record(fixture, "fixture");

function field(
  source: Readonly<Record<string, unknown>>,
  name: string,
): ReturnType<typeof asField> {
  const encoded = decode.string(source[name], name);
  if (!/^0x[0-9a-f]{64}$/u.test(encoded)) throw new Error(`Invalid fixture field: ${name}`);
  return asField(BigInt(encoded));
}

function fields(
  source: Readonly<Record<string, unknown>>,
  name: string,
): ReturnType<typeof asField>[] {
  return decode.list(source[name], name).map((value) => field({ value }, "value"));
}

function utxo(value: unknown): CircuitUtxo {
  const item = decode.record(value, "utxo");
  return {
    domain: field(item, "domain"),
    owner: field(item, "owner"),
    asset: field(item, "asset"),
    amount: field(item, "amount"),
    blinding: field(item, "blinding"),
    dataHash: field(item, "dataHash"),
    ringDataHash: field(item, "ringDataHash"),
    ringProgramId: field(item, "ringProgramId"),
  };
}

function input(value: unknown): TransferInput {
  const item = decode.record(value, "input");
  return {
    circuit: utxo(item["utxo"]),
    isDummy: field(item, "isDummy"),
    statePathElements: fields(item, "statePathElements"),
    statePathIndex: field(item, "statePathIndex"),
    nullifierLowValue: field(item, "nullifierLowValue"),
    nullifierNextValue: field(item, "nullifierNextValue"),
    nullifierLowPathElements: fields(item, "nullifierLowPathElements"),
    nullifierLowPathIndex: field(item, "nullifierLowPathIndex"),
    treeSlot: field(item, "treeSlot"),
    nullifier: field(item, "nullifier"),
    ownerPublicKeyHash: field(item, "ownerPkHash"),
    nullifierSecret: field(item, "nullifierSecret"),
  };
}

function output(value: unknown): TransferOutput {
  const item = decode.record(value, "output");
  return {
    circuit: utxo(item["utxo"]),
    isDummy: field(item, "isDummy"),
    hash: field(item, "hash"),
    ownerPublicKeyHash: field(item, "ownerPkHash"),
    nullifierPublicKey: field(item, "nullifierPk"),
  };
}

export function transferFixtureInputs(): ProverInputs {
  return {
    circuit: "transfer",
    payload: {
      inputs: decode.list(record["inputs"], "inputs").map(input),
      outputs: decode.list(record["outputs"], "outputs").map(output),
      treeSlots: decode.list(record["treeSlots"], "treeSlots").map((value) => {
        const item = decode.record(value, "treeSlot");
        return {
          id: field(item, "id"),
          utxoRoot: field(item, "utxoRoot"),
          nullifierRoot: field(item, "nullifierRoot"),
        };
      }),
      outputTreeId: field(record, "outputTreeId"),
      externalDataHash: field(record, "externalDataHash"),
      privateTxHash: field(record, "privateTxHash"),
      blindingSeed: field(record, "blindingSeed"),
      publicAssets: fields(record, "publicAssets"),
      publicAmounts: fields(record, "publicAmounts"),
      ringProgramId: field(record, "ringProgramId"),
      signerPublicKeyHashes: fields(record, "signerPkHashes"),
      inputFlags: field(record, "inputFlags"),
      publishedOutputOwnerPublicKeyHashes: fields(record, "publishedOutputOwnerPkHashes"),
      cacheTreeId: field(record, "cacheTreeId"),
      cacheReadHashChain: field(record, "cacheReadHashChain"),
      cacheReadHashes: fields(record, "cacheReadHashes"),
      cacheIsCached: fields(record, "cacheIsCached"),
      cacheReadIndex: fields(record, "cacheReadIndex"),
      publicInputHash: field(record, "publicInputHash"),
    },
  };
}

export function transferFixturePublicInputHash(): string {
  return decode.string(record["publicInputHash"], "publicInputHash");
}
