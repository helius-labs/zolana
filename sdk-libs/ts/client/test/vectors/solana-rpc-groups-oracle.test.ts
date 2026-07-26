import type { Signature } from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import fixture from "../../../vectors/solana-rpc-groups-v1.json" with { type: "json" };
import { SolanaRpc } from "../../src/index.js";

/**
 * Replays `xtask/src/bin/solana-rpc-groups.rs`. The generator answers a real
 * Rust `SolanaRpc` with each `getTransaction` body and records what
 * `fetch_confirmed_instruction_groups` made of it, so `groups` is Rust's own
 * grouping and `accepted` is Rust's own decision.
 *
 * The refusals are compared as decisions, not as messages: Rust returns one
 * `ClientError::Rpc(String)` for every malformed body while the port names a
 * structured code per path. Both refuse the same bodies, which is the part a
 * caller can act on.
 */

interface Instruction {
  readonly programId: string;
  readonly accounts: readonly string[];
  readonly data: string;
  readonly stackHeight: number | null;
}

interface Group {
  readonly outer: Instruction;
  readonly inner: readonly Instruction[];
}

interface Case {
  readonly name: string;
  readonly result: unknown;
  readonly accepted: boolean;
  readonly groups: readonly Group[] | null;
}

const SIGNATURE = fixture.signature as Signature;
const CASES = fixture.cases as readonly Case[];

/**
 * The path each refusal names. Rust has no counterpart to compare against --
 * every malformed body there is one `ClientError::Rpc(String)` -- so this table
 * is the port's own, and it is here so a refusal that moved to an unrelated
 * cause fails rather than passing as "still refused".
 *
 * `parsedMessage` and `parsedInnerInstruction` are the two Rust names outright
 * ("expected raw transaction message", "expected compiled inner instruction");
 * the port reaches the same refusal one step later, when the parsed form turns
 * out to carry no `programIdIndex`.
 */
const REFUSAL_PATHS: Readonly<Record<string, string>> = {
  missingMeta: "result.meta",
  missingInnerInstructions: "result.meta.innerInstructions",
  innerIndexPastLastOuter: "result.meta.innerInstructions[3].index",
  programIdIndexOutOfBounds: "instruction.programIdIndex",
  accountIndexOutOfBounds: "instruction.accounts[]",
  loadedAddressIndexWithoutTable: "instruction.accounts[]",
  base64Transaction: "result.transaction",
  parsedMessage: "programIdIndex",
  parsedInnerInstruction: "programIdIndex",
};

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Answers the recorded `getTransaction` body once; a retry is a test failure. */
function rpcFor(testCase: Case): SolanaRpc {
  let served = 0;
  return new SolanaRpc({
    url: "https://solana.example.test",
    fetch: vi.fn(() => {
      served += 1;
      expect(served, `${testCase.name} was re-requested`).toBe(1);
      return Promise.resolve(
        Response.json({ jsonrpc: "2.0", id: 1, result: testCase.result ?? null }),
      );
    }),
  });
}

describe("confirmed instruction grouping against the Rust oracle", () => {
  it("covers a body Rust accepts and a body Rust refuses", () => {
    expect(CASES.some((testCase) => testCase.accepted)).toBe(true);
    expect(CASES.some((testCase) => !testCase.accepted)).toBe(true);
  });

  for (const testCase of CASES) {
    if (testCase.accepted) {
      it(`groups ${testCase.name} as Rust does`, async () => {
        const groups = await rpcFor(testCase).confirmedInstructionGroups(SIGNATURE);
        expect(
          groups.groups.map((group) => ({
            outer: describeInstruction(group.outer),
            inner: group.inner.map(describeInstruction),
          })),
        ).toEqual(testCase.groups);
      });
      continue;
    }

    it(`refuses ${testCase.name} as Rust does`, async () => {
      await expect(rpcFor(testCase).confirmedInstructionGroups(SIGNATURE)).rejects.toMatchObject({
        code: "CLIENT_INVALID_RPC_RESPONSE",
        details: { path: REFUSAL_PATHS[testCase.name] },
      });
    });
  }
});

function describeInstruction(instruction: {
  readonly programId: string;
  readonly accounts: readonly string[];
  readonly data: Uint8Array;
  readonly stackHeight?: number;
}): Instruction {
  return {
    programId: instruction.programId,
    accounts: [...instruction.accounts],
    data: hex(instruction.data),
    stackHeight: instruction.stackHeight ?? null,
  };
}
