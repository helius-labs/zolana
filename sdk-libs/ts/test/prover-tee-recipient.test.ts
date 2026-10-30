import vectors from "../../../prover/tee/testdata/recipient_ids.json" with { type: "json" };
import { hexToBytes } from "@noble/hashes/utils.js";
import { expect, it } from "vitest";
import { HEADER_KEY_ID, recipientId } from "../src/client/prover/tee/encryption.js";

it.each(vectors.vectors)("derives the cross-language recipient $recipient_id", (vector) => {
  expect(HEADER_KEY_ID).toBe(vectors.header);
  expect(recipientId(hexToBytes(vector.hpke_public_key))).toBe(vector.recipient_id);
});
it.each([0, 31, 33])("rejects a recipient key of length %s", (length) => {
  expect(() => recipientId(new Uint8Array(length))).toThrow();
});
