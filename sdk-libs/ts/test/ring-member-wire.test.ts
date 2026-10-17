import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { wireDecoder } from "../src/interface/decode.js";
import type { Bytes32, RecordUpdateWitness } from "../src/interface/index.js";
import { initializePoseidon } from "../src/hasher/index.js";
import {
  customRingRegisterKeyProofRequest,
  customRingUpdateMembersProofRequest,
} from "../src/client/prover/client.js";
import { updateMembersPublicInputHash } from "../src/ring/member-registry-tree.js";
const decoder = wireDecoder((path) => new Error(`invalid fixture ${path}`));
function field(value: unknown): Bytes32 {
  const text = decoder.string(value, "field");
  if (!/^0x[0-9a-f]{64}$/u.test(text)) throw new Error("invalid fixture field");
  const bytes = new Uint8Array(Buffer.from(text.slice(2), "hex"));
  if (bytes.length !== 32) throw new Error("invalid field length");
  return bytes as Bytes32;
}
function fixture(name: string) {
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
    "fixture",
  );
}
function update(row: Record<string, unknown>): RecordUpdateWitness {
  return {
    exists: decoder.boolean(row["exists"], "exists"),
    next: field(row["next"]),
    index: decoder.integer(row["index"], "index"),
    path: decoder.list(row["path"], "path").map(field),
    lowMember: field(row["lowMember"]),
    lowNext: field(row["lowNext"]),
    lowLists: decoder.integer(row["lowLists"], "lowLists"),
    lowEscrow: field(row["lowEscrow"]),
    lowIndex: decoder.integer(row["lowIndex"], "lowIndex"),
    lowPath: decoder.list(row["lowPath"], "lowPath").map(field),
  };
}
beforeAll(initializePoseidon);
describe("Rust member-registry wire fixtures", () => {
  it("reproduces the registration body including a pre-existing member's list bits", () => {
    const body = fixture("custom-ring-register-key");
    expect(
      customRingRegisterKeyProofRequest({
        publicInputHash: field(body["publicInputHash"]),
        registryOldRoot: field(body["registryOldRoot"]),
        registryNewRoot: field(body["registryNewRoot"]),
        member: field(body["member"]),
        oldLists: decoder.integer(body["lists"], "lists"),
        update: update(body),
        nullifierSecret: field(body["nullifierSecret"]),
        ephemeralSecret: field(body["ephSk"]),
        auditorPublicKey: field(body["auditorPk"]),
      }),
    ).toEqual(body);
  });
  it("reproduces the padded update body and its public input hash", () => {
    const body = fixture("custom-ring-update-members");
    const items = decoder
      .list(body["items"], "items")
      .filter((value) => value !== null)
      .map((value) => {
        const row = decoder.record(value, "item");
        return {
          member: field(row["member"]),
          oldLists: decoder.integer(row["oldLists"], "oldLists"),
          oldEscrowKey: field(row["oldEscrowKey"]),
          lists: decoder.integer(row["lists"], "lists"),
          escrowKey: field(row["escrowKey"]),
          index: decoder.integer(row["index"], "index"),
          update: update(row),
        };
      });
    const request = {
      publicInputHash: field(body["publicInputHash"]),
      oldRoot: field(body["oldRoot"]),
      newRoot: field(body["newRoot"]),
      items,
    };
    expect(customRingUpdateMembersProofRequest(request)).toEqual(body);
    expect(updateMembersPublicInputHash(request.oldRoot, request.newRoot, items)).toEqual(
      request.publicInputHash,
    );
  });
});
