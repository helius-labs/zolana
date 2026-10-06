import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { Merge, PreparedMerge } from "../transaction/instructions/builders.js";
import { deriveAnswers } from "../transaction/wallet/key-batch.js";
import type { ShieldedKeys } from "../transaction/wallet/keys.js";
import type { ProofInputUtxo } from "../transaction/utxo.js";

export async function prepareMerge(
  input: Readonly<{
    keys: ShieldedKeys;
    inputs: readonly ProofInputUtxo[];
    invalidAnswers(): Error;
    outputTreeId?: number;
    ring?: Readonly<{ programId: Address; outputDataHash?: Bytes32 }>;
  }>,
  context?: RequestContext,
): Promise<PreparedMerge> {
  const firstNullifier = input.inputs[0]?.nullifier();
  if (firstNullifier === undefined) throw input.invalidAnswers();
  const slots = PreparedMerge.dummySlots(input.inputs.length);
  const answers = await input.keys.derive(
    [
      { kind: "mergeOutputBlinding", firstNullifier },
      { kind: "mergePrivateTxBlinding", firstNullifier },
      ...slots.map((slotIndex) => ({
        kind: "mergeDummyNullifier" as const,
        firstNullifier,
        slotIndex,
      })),
    ],
    context,
  );
  const [outputBlinding, privateTxBlinding, ...dummyNullifiers] = deriveAnswers(
    answers,
    2 + slots.length,
    input.invalidAnswers,
  );
  if (outputBlinding === undefined || privateTxBlinding === undefined) throw input.invalidAnswers();
  return new Merge({
    address: input.keys.address(),
    inputs: input.inputs,
    outputBlinding,
    privateTxBlinding,
    dummyNullifiers,
    ...(input.outputTreeId === undefined ? {} : { outputTreeId: input.outputTreeId }),
    ...(input.ring === undefined ? {} : { ring: input.ring }),
  }).prepare();
}
