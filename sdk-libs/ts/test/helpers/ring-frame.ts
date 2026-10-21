import { CUSTOM_RING_PROOF_LENGTH } from "../../src/interface/custom-ring-proof.js";
import { disclosureFieldCount } from "../../src/interface/ring-disclosure-layout.js";
import { RING_AUTHORITY_SHAPES, SPP_SUPPORTED_SHAPES } from "../../src/interface/shape.js";
import type { Bytes16, Bytes31, Bytes32 } from "../../src/interface/types.js";
import { RingInstructionTag } from "../../src/ring/admin.js";
import {
  PLAIN_GROTH16_PROOF_LENGTH,
  RingTransactData,
  ringDisclosureLayout,
  type RingOutput,
  type RingRail,
} from "../../src/ring/transact.js";

function field(byte: number): Bytes32 {
  const value = new Uint8Array(32);
  value[31] = byte;
  return value as Bytes32;
}

/** A data-free exit-free frame of `inputs` and `outputs` the rail's audit key serves, no proof valid. */
export function ringFrame(
  input: Readonly<{ rail: RingRail; inputs: number; outputs: number; fullOpenings?: boolean }>,
): RingTransactData {
  const { rail, inputs, outputs } = input;
  const keyed = rail === "delegate" ? RING_AUTHORITY_SHAPES : SPP_SUPPORTED_SHAPES;
  const shape = keyed.find((entry) => entry.inputs >= inputs && entry.outputs === outputs);
  if (shape === undefined) throw new Error("no shape serves the counts");
  const flags = {
    exits: false,
    keyEscrow: rail === "delegate",
    dataFree: true,
    fullOpenings: input.fullOpenings ?? false,
  };
  const layout = ringDisclosureLayout({
    rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    inputs,
    outputs,
    layout: flags,
  });
  const slot = (index: number): RingOutput =>
    rail === "anonymous"
      ? {
          kind: "anonymous",
          hash: field(10 + index),
          tag: new Uint8Array(31).fill(index + 1) as Bytes31,
          body: new Uint8Array(40),
        }
      : {
          kind: "packed",
          hash: field(10 + index),
          u: field(40 + index),
          ciphertext: new Uint8Array(49),
        };
  return {
    rail,
    nIn: shape.inputs,
    nOut: shape.outputs,
    auditProof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH),
    approvalRequired: false,
    previousEpoch: false,
    expiryUnixTs: 0,
    txViewingU: field(1),
    salt: new Uint8Array(16).fill(3) as Bytes16,
    interfaceTransfers: [],
    dataFree: flags.dataFree,
    keyEscrow: flags.keyEscrow,
    fullOpenings: flags.fullOpenings,
    outputs: Array.from({ length: outputs }, (_, index) => slot(index)),
    ephU: field(2),
    sealed: field(3),
    disclosure: Array.from({ length: disclosureFieldCount(layout) }, (_, index) =>
      field(index + 1),
    ),
    privateTxHash: field(4),
    ...(rail === "anonymous"
      ? { anonymous: { commitment: field(5), commitmentPok: field(6) } }
      : {}),
    sppProof: new Uint8Array(PLAIN_GROTH16_PROOF_LENGTH),
    nullifiers: Array.from({ length: inputs }, (_, index) => field(70 + index)),
    inputTrees: { kind: "one", context: { utxoTreeRootIndex: 0, nullifierTreeRootIndex: 0 } },
  };
}

/** The ring program's own instruction data around `frame`. */
export function ringInstructionData(frame: RingTransactData): Uint8Array {
  const tag =
    frame.rail === "delegate" ? RingInstructionTag.delegateTransact : RingInstructionTag.transact;
  return Uint8Array.of(tag, ...RingTransactData.encode(frame));
}
