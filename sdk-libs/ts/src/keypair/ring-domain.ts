import { rightAlign } from "../interface/merge-utils.js";

import { type Bytes32, checkedBytes, u32be } from "./bytes.js";
import { poseidon } from "./poseidon.js";

/** Distinct ASCII tags, the first Poseidon input, mirroring Rust `custom_ring_interface::domain`. */
export const RingDomain = Object.freeze({
  auditStatement: 0x4352_4155, // "CRAU"
  packedSlotSecret: 0x4352_4153, // "CRAS"
  deliveredSlotSecret: 0x4352_4453, // "CRDS"
  confidentialRingSecret: 0x4352_5243, // "CRRC"
  anonymousRingSecret: 0x4352_5241, // "CRRA"
  inboxKey: 0x4352_494b, // "CRIK"
  inboxTag: 0x4352_4954, // "CRIT"
  pairKey: 0x4352_504b, // "CRPK"
  pairTag: 0x4352_5054, // "CRPT"
  senderCommitment: 0x4352_5343, // "CRSC"
  disclosurePad: 0x4352_4f44, // "CROD"
  policyStatement: 0x4352_504f, // "CRPO"
  policyTable: 0x4352_5442, // "CRTB"
  queueWrite: 0x4352_5157, // "CRQW"
  applyRecords: 0x4352_4150, // "CRAP"
  registerKey: 0x4352_5247, // "CRRG"
  depositBlinding: 0x4352_4442, // "CRDB"
} as const);
export type RingDomain = (typeof RingDomain)[keyof typeof RingDomain];

export function domainField(domain: RingDomain): Bytes32 {
  return rightAlign(u32be(domain));
}

/** `Poseidon(domain, ...fields)` over fresh copies, wiped once hashed since they may hold secrets. */
export function domainHash(domain: RingDomain, fields: readonly Uint8Array[]): Bytes32 {
  try {
    return poseidon([domainField(domain), ...fields]) as Bytes32;
  } finally {
    fields.forEach((field) => field.fill(0));
  }
}

/** `Poseidon(CRDB, blinding_secret)`, a deposit blinding no anchor opens as a first contact. */
export function depositBlinding(blindingSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.depositBlinding, [
    checkedBytes<Bytes32>(blindingSecret, 32, "deposit blinding secret"),
  ]);
}
