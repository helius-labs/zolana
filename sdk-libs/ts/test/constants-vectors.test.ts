import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/constants.json" with { type: "json" };
import { NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT } from "../src/client/prover/assembly.js";
import { MERGE_INPUT_COUNT } from "../src/interface/constants.js";
import { InstructionTag } from "../src/interface/program.js";
import { VIEW_TAG_LENGTH } from "../src/keypair/index.js";
import { MERGE_INPUTS, VIEW_TAG_LEN } from "../src/transaction/index.js";

describe("shared constants vector", () => {
  it("matches the Rust-pinned values", () => {
    expect(Object.keys(vector)).toHaveLength(6);
    expect(MERGE_INPUT_COUNT).toBe(vector.mergeInputs);
    expect(MERGE_INPUTS).toBe(vector.mergeInputs);
    expect(STATE_TREE_HEIGHT).toBe(vector.stateTreeHeight);
    expect(NULLIFIER_TREE_HEIGHT).toBe(vector.nullifierTreeHeight);
    expect(InstructionTag.transact).toBe(vector.transactTag);
    expect(InstructionTag.mergeTransact).toBe(vector.mergeTransactTag);
    expect(VIEW_TAG_LENGTH).toBe(vector.viewTagLength);
    expect(VIEW_TAG_LEN).toBe(vector.viewTagLength);
  });
});
