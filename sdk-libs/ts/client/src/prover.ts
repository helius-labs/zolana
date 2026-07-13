import { hexToBe32, toHex } from "./bytes.js";

export interface UtxoInputs {
  domain: bigint;
  owner: bigint;
  asset: bigint;
  amount: bigint;
  blinding: bigint;
  dataHash: bigint;
  zoneDataHash: bigint;
  zoneProgramId: bigint;
}

export interface TransferInput {
  utxo: UtxoInputs;
  isDummy: bigint;
  statePathElements: bigint[];
  statePathIndex: bigint;
  nullifierLowValue: bigint;
  nullifierNextValue: bigint;
  nullifierLowPathElements: bigint[];
  nullifierLowPathIndex: bigint;
  utxoTreeRoot: bigint;
  nullifierTreeRoot: bigint;
  nullifier: bigint;
  ownerPkHash: bigint;
  nullifierSecret: bigint;
}

export interface TransferOutput {
  utxo: UtxoInputs;
  isDummy: bigint;
  hash: bigint;
  ownerPkHash: bigint;
  nullifierPk: bigint;
}

export interface TransferInputs {
  inputs: TransferInput[];
  outputs: TransferOutput[];
  externalDataHash: bigint;
  privateTxHash: bigint;
  publicSolAmount: bigint;
  publicSplAmount: bigint;
  publicSplAssetPubkey: bigint;
  zoneProgramId: bigint;
  payerPubkeyHash: bigint;
  publicInputHash: bigint;
}

export interface TransferP256Inputs extends TransferInputs {
  p256PubX: bigint;
  p256PubY: bigint;
  p256SigR: bigint;
  p256SigS: bigint;
  p256MessageHashLow: bigint;
  p256MessageHashHigh: bigint;
  p256SigningPkField: bigint;
}

export interface MergeInputs {
  inputs: TransferInput[];
  output: TransferOutput;
  p256PubX: bigint;
  p256PubY: bigint;
  ownerPkHash: bigint;
  userNullifierPk: bigint;
  userNullifierSecret: bigint;
  txViewingSk: bigint;
  userViewingPubkey: bigint[];
  externalDataHash: bigint;
  privateTxHash: bigint;
  publicInputHash: bigint;
  zoneProgramId: bigint;
}

export interface BatchAddressAppendInputs {
  publicInputHash: bigint;
  oldRoot: bigint;
  newRoot: bigint;
  hashchainHash: bigint;
  startIndex: number;
  lowElementValues: bigint[];
  lowElementIndices: bigint[];
  lowElementNextValues: bigint[];
  newElementValues: bigint[];
  lowElementProofs: bigint[][];
  newElementProofs: bigint[][];
  treeHeight: number;
  batchSize: number;
}

export interface Commitments {
  commitment: Uint8Array;
  commitmentPok: Uint8Array;
}

export interface Proof {
  a: Uint8Array;
  b: Uint8Array;
  c: Uint8Array;
  commitment?: Commitments;
}

export interface CompressedCommitments {
  commitment: Uint8Array;
  commitmentPok: Uint8Array;
}

export interface ProofCompressed {
  a: Uint8Array;
  b: Uint8Array;
  c: Uint8Array;
  commitment?: CompressedCommitments;
}

export type TransactProof =
  | { kind: "eddsa"; a: Uint8Array; b: Uint8Array; c: Uint8Array }
  | {
      kind: "p256";
      a: Uint8Array;
      b: Uint8Array;
      c: Uint8Array;
      commitment: Uint8Array;
      commitmentPok: Uint8Array;
    };

export const SERVER_ADDRESS = "http://127.0.0.1:3001";
export const HEALTH_CHECK = "/health";
export const PROVE_PATH = "/prove";

export function serverAddress(env = process.env): string {
  const override = env.ZOLANA_PROVER_URL?.trim();
  return override && override.length > 0 ? override : SERVER_ADDRESS;
}

export function bigUintToString(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function utxoToJson(utxo: UtxoInputs) {
  return {
    domain: bigUintToString(utxo.domain),
    owner: bigUintToString(utxo.owner),
    asset: bigUintToString(utxo.asset),
    amount: bigUintToString(utxo.amount),
    blinding: bigUintToString(utxo.blinding),
    dataHash: bigUintToString(utxo.dataHash),
    zoneDataHash: bigUintToString(utxo.zoneDataHash),
    zoneProgramId: bigUintToString(utxo.zoneProgramId),
  };
}

function inputToJson(input: TransferInput) {
  return {
    utxo: utxoToJson(input.utxo),
    isDummy: bigUintToString(input.isDummy),
    statePathElements: input.statePathElements.map(bigUintToString),
    statePathIndex: bigUintToString(input.statePathIndex),
    nullifierLowValue: bigUintToString(input.nullifierLowValue),
    nullifierNextValue: bigUintToString(input.nullifierNextValue),
    nullifierLowPathElements: input.nullifierLowPathElements.map(bigUintToString),
    nullifierLowPathIndex: bigUintToString(input.nullifierLowPathIndex),
    utxoTreeRoot: bigUintToString(input.utxoTreeRoot),
    nullifierTreeRoot: bigUintToString(input.nullifierTreeRoot),
    nullifier: bigUintToString(input.nullifier),
    ownerPkHash: bigUintToString(input.ownerPkHash),
    nullifierSecret: bigUintToString(input.nullifierSecret),
  };
}

function outputToJson(output: TransferOutput) {
  return {
    utxo: utxoToJson(output.utxo),
    isDummy: bigUintToString(output.isDummy),
    hash: bigUintToString(output.hash),
    ownerPkHash: bigUintToString(output.ownerPkHash),
    nullifierPk: bigUintToString(output.nullifierPk),
  };
}

export function transferInputsJson(inputs: TransferInputs, circuitType: string): string {
  return JSON.stringify({
    circuitType,
    nInputs: inputs.inputs.length,
    nOutputs: inputs.outputs.length,
    inputs: inputs.inputs.map(inputToJson),
    outputs: inputs.outputs.map(outputToJson),
    externalDataHash: bigUintToString(inputs.externalDataHash),
    privateTxHash: bigUintToString(inputs.privateTxHash),
    publicSolAmount: bigUintToString(inputs.publicSolAmount),
    publicSplAmount: bigUintToString(inputs.publicSplAmount),
    publicSplAssetPubkey: bigUintToString(inputs.publicSplAssetPubkey),
    zoneProgramId: bigUintToString(inputs.zoneProgramId),
    payerPubkeyHash: bigUintToString(inputs.payerPubkeyHash),
    publicInputHash: bigUintToString(inputs.publicInputHash),
  });
}

export function transferP256InputsJson(inputs: TransferP256Inputs, circuitType: string): string {
  return JSON.stringify({
    ...JSON.parse(transferInputsJson(inputs, circuitType)),
    p256PubX: bigUintToString(inputs.p256PubX),
    p256PubY: bigUintToString(inputs.p256PubY),
    p256SigR: bigUintToString(inputs.p256SigR),
    p256SigS: bigUintToString(inputs.p256SigS),
    p256MessageHashLow: bigUintToString(inputs.p256MessageHashLow),
    p256MessageHashHigh: bigUintToString(inputs.p256MessageHashHigh),
    p256SigningPkField: bigUintToString(inputs.p256SigningPkField),
  });
}

export function toJson(inputs: TransferInputs): string {
  return transferInputsJson(inputs, "transfer-confidential");
}

export function toJsonZoneAuthority(inputs: TransferInputs): string {
  return transferInputsJson(inputs, "transfer-zone-authority");
}

export function toJsonZone(inputs: TransferInputs): string {
  return transferInputsJson(inputs, "transfer-zone");
}

export function toJsonP256(inputs: TransferP256Inputs): string {
  return transferP256InputsJson(inputs, "transfer-p256-confidential");
}

export function toJsonP256Zone(inputs: TransferP256Inputs): string {
  return transferP256InputsJson(inputs, "transfer-p256-zone");
}

export function toJsonMerge(inputs: MergeInputs, circuitType = "merge"): string {
  return JSON.stringify({
    circuitType,
    inputs: inputs.inputs.map(inputToJson),
    output: outputToJson(inputs.output),
    p256PubX: bigUintToString(inputs.p256PubX),
    p256PubY: bigUintToString(inputs.p256PubY),
    ownerPkHash: bigUintToString(inputs.ownerPkHash),
    userNullifierPk: bigUintToString(inputs.userNullifierPk),
    userNullifierSecret: bigUintToString(inputs.userNullifierSecret),
    txViewingSk: bigUintToString(inputs.txViewingSk),
    userViewingPubkey: inputs.userViewingPubkey.map(bigUintToString),
    externalDataHash: bigUintToString(inputs.externalDataHash),
    privateTxHash: bigUintToString(inputs.privateTxHash),
    publicInputHash: bigUintToString(inputs.publicInputHash),
    zoneProgramId: bigUintToString(inputs.zoneProgramId),
  });
}

export function toJsonMergeZone(inputs: MergeInputs): string {
  return toJsonMerge(inputs, "merge-zone");
}

export function toJsonBatchAddressAppend(inputs: BatchAddressAppendInputs): string {
  return JSON.stringify({
    circuitType: "address-append",
    stateTreeHeight: 0,
    publicInputHash: bigUintToString(inputs.publicInputHash),
    oldRoot: bigUintToString(inputs.oldRoot),
    newRoot: bigUintToString(inputs.newRoot),
    hashchainHash: bigUintToString(inputs.hashchainHash),
    startIndex: inputs.startIndex,
    lowElementValues: inputs.lowElementValues.map(bigUintToString),
    lowElementIndices: inputs.lowElementIndices.map(bigUintToString),
    lowElementNextValues: inputs.lowElementNextValues.map(bigUintToString),
    newElementValues: inputs.newElementValues.map(bigUintToString),
    lowElementProofs: inputs.lowElementProofs.map((proof) => proof.map(bigUintToString)),
    newElementProofs: inputs.newElementProofs.map((proof) => proof.map(bigUintToString)),
    treeHeight: inputs.treeHeight,
    batchSize: inputs.batchSize,
  });
}

export function proofFromGnarkJson(json: string): Proof | undefined {
  const parsed = JSON.parse(json) as {
    ar?: string[];
    bs?: string[][];
    krs?: string[];
    proof_commitment?: string[];
    proof_commitment_pok?: string[];
  };
  if (!parsed.ar || !parsed.bs || !parsed.krs) return undefined;
  const a = negateG1(g1FromHexPair(parsed.ar));
  const c = g1FromHexPair(parsed.krs);
  if (parsed.bs.length !== 2 || !parsed.bs[0] || !parsed.bs[1]) return undefined;
  const bx = g1FromHexPair(parsed.bs[0]);
  const by = g1FromHexPair(parsed.bs[1]);
  const b = new Uint8Array(128);
  b.set(bx);
  b.set(by, 64);
  const hasCommitment =
    (parsed.proof_commitment?.length ?? 0) > 0 || (parsed.proof_commitment_pok?.length ?? 0) > 0;
  const commitment = hasCommitment
    ? {
        commitment: g1FromHexPair(parsed.proof_commitment ?? []),
        commitmentPok: g1FromHexPair(parsed.proof_commitment_pok ?? []),
      }
    : undefined;
  return { a, b, c, ...(commitment ? { commitment } : {}) };
}

function g1FromHexPair(pair: string[]): Uint8Array {
  if (pair.length !== 2 || pair[0] === undefined || pair[1] === undefined) {
    throw new Error("expected G1 hex pair");
  }
  const out = new Uint8Array(64);
  out.set(hexToBe32(pair[0]));
  out.set(hexToBe32(pair[1]), 32);
  return out;
}

function negateG1(point: Uint8Array): Uint8Array {
  // This preserves the Rust proof object shape. Full BN254 negation/compression is
  // intentionally left to the verifier/prover bindings once a stable JS alt_bn128
  // dependency is selected.
  return new Uint8Array(point);
}

export class ProverClient {
  constructor(readonly address = serverAddress(), readonly fetchImpl: typeof fetch = fetch) {}

  async proveTransferP256(inputs: TransferP256Inputs): Promise<Proof> {
    return this.send(toJsonP256(inputs));
  }

  async proveTransfer(inputs: TransferInputs): Promise<Proof> {
    return this.send(toJson(inputs));
  }

  async proveMerge(inputs: MergeInputs): Promise<Proof> {
    return this.send(toJsonMerge(inputs));
  }

  async proveZoneAuthority(inputs: TransferInputs): Promise<Proof> {
    return this.send(toJsonZoneAuthority(inputs));
  }

  async proveMergeZone(inputs: MergeInputs): Promise<Proof> {
    return this.send(toJsonMergeZone(inputs));
  }

  async proveTransferZone(inputs: TransferInputs): Promise<Proof> {
    return this.send(toJsonZone(inputs));
  }

  async proveTransferP256Zone(inputs: TransferP256Inputs): Promise<Proof> {
    return this.send(toJsonP256Zone(inputs));
  }

  async proveBatchAddressAppend(inputs: BatchAddressAppendInputs): Promise<Proof> {
    return this.send(toJsonBatchAddressAppend(inputs));
  }

  async proveTransactTransfer(inputs: TransferInputs): Promise<TransactProof> {
    return this.sendTransactProof(toJson(inputs));
  }

  async proveTransactTransferP256(inputs: TransferP256Inputs): Promise<TransactProof> {
    return this.sendTransactProof(toJsonP256(inputs));
  }

  private async send(body: string): Promise<Proof> {
    const response = await this.fetchImpl(`${this.address}${PROVE_PATH}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`prover server status ${response.status}: ${text}`);
    }
    const value = JSON.parse(text) as unknown;
    const proofValue = typeof value === "object" && value !== null && "proof" in value
      ? (value as { proof: unknown }).proof
      : value;
    const proof = proofFromGnarkJson(JSON.stringify(proofValue));
    if (!proof) throw new Error(`could not parse proof: ${text}`);
    return proof;
  }

  private async sendTransactProof(body: string): Promise<TransactProof> {
    const response = await this.fetchImpl(`${this.address}${PROVE_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-zolana-proof-format": "transact",
      },
      body,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new Error(`prover server status ${response.status}: ${text}`);
    }
    return transactProofFromJson(text);
  }
}

export function transactProofFromJson(json: string): TransactProof {
  const value = JSON.parse(json) as {
    kind?: string;
    a?: string;
    b?: string;
    c?: string;
    commitment?: string;
    commitment_pok?: string;
  };
  if (value.kind !== "eddsa" && value.kind !== "p256") {
    throw new Error(`invalid transact proof kind ${value.kind}`);
  }
  if (!value.a || !value.b || !value.c) {
    throw new Error("missing transact proof points");
  }
  if (value.kind === "eddsa") {
    return {
      kind: "eddsa",
      a: hexToBe32(value.a),
      b: hexToFixed(value.b, 64),
      c: hexToBe32(value.c),
    };
  }
  if (!value.commitment || !value.commitment_pok) {
    throw new Error("missing p256 proof commitments");
  }
  return {
    kind: "p256",
    a: hexToBe32(value.a),
    b: hexToFixed(value.b, 64),
    c: hexToBe32(value.c),
    commitment: hexToBe32(value.commitment),
    commitmentPok: hexToBe32(value.commitment_pok),
  };
}

function hexToFixed(hex: string, length: number): Uint8Array {
  const bytes = hexToBe32(hex);
  if (length === 32) return bytes;
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  const even = raw.length % 2 === 0 ? raw : `0${raw}`;
  const decoded = new Uint8Array(Buffer.from(even, "hex"));
  if (decoded.length > length) return decoded.slice(decoded.length - length);
  const out = new Uint8Array(length);
  out.set(decoded, length - decoded.length);
  return out;
}

export function proofToDebugHex(proof: Proof): Record<string, string> {
  return {
    a: toHex(proof.a),
    b: toHex(proof.b),
    c: toHex(proof.c),
    ...(proof.commitment
      ? {
          commitment: toHex(proof.commitment.commitment),
          commitmentPok: toHex(proof.commitment.commitmentPok),
        }
      : {}),
  };
}
