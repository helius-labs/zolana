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
  const ring = input.ring;
  const answers = await input.keys.derive(
    [
      ...(ring === undefined ? [] : [{ kind: "mergeOutputBlinding" as const, firstNullifier }]),
      { kind: "mergePrivateTxBlinding", firstNullifier },
      ...slots.map((slotIndex) => ({
        kind: "mergeDummyNullifier" as const,
        firstNullifier,
        slotIndex,
      })),
    ],
    context,
  );
  const derived = deriveAnswers(
    answers,
    (ring === undefined ? 1 : 2) + slots.length,
    input.invalidAnswers,
  );
  const outputBlinding = ring === undefined ? undefined : derived[0];
  const [privateTxBlinding, ...dummyNullifiers] = ring === undefined ? derived : derived.slice(1);
  if (privateTxBlinding === undefined) throw input.invalidAnswers();
  if (ring !== undefined && outputBlinding === undefined) throw input.invalidAnswers();
  return new Merge({
    address: input.keys.address(),
    inputs: input.inputs,
    blinding:
      outputBlinding === undefined ? { kind: "envelope" } : { kind: "derived", outputBlinding },
    privateTxBlinding,
    dummyNullifiers,
    ...(input.outputTreeId === undefined ? {} : { outputTreeId: input.outputTreeId }),
    ...(ring === undefined ? {} : { ring }),
  }).prepare();
}
