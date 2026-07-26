// One WebAssembly instance and two fixed buffers, shared by six packages. The
// Rust fixture pins the digests; it does not pin what the buffers hold between
// calls, and every way that can go wrong returns a well-formed 32-byte digest
// rather than an error.
//
// The alignment tests cover a narrower blind spot. The wrapper writes input
// `i` at `(i + 1) * 32 - length`, and the fixture's short inputs only ever sit
// at `i = 0`, where a wrong offset is indistinguishable from the right one.
import { describe, expect, it } from "vitest";

import fixture from "../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { HasherWasmError, MAX_POSEIDON_INPUTS, poseidon } from "@zolana/hasher";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fieldOf(value: number): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes;
}

const arities = Array.from({ length: MAX_POSEIDON_INPUTS }, (_, index) => index + 1);
const FILLER = fieldOf(9);

describe("short inputs are right-aligned at every position", () => {
  for (const short of fixture.shortInputs) {
    const shortBytes = hexToBytes(short.shortBytes);
    const alignedBytes = hexToBytes(short.alignedBytes);

    for (const arity of arities) {
      it(`${short.id} at each of ${String(arity)} positions`, () => {
        for (let position = 0; position < arity; position += 1) {
          const withShort = Array.from({ length: arity }, (_, index) =>
            index === position ? shortBytes : FILLER,
          );
          const withAligned = Array.from({ length: arity }, (_, index) =>
            index === position ? alignedBytes : FILLER,
          );
          expect(bytesToHex(poseidon(withShort))).toBe(bytesToHex(poseidon(withAligned)));
        }
      });
    }
  }

  // A zero-length input is the field element zero, including in the last slot,
  // where the write offset lands exactly at the end of the input buffer.
  it("reads an empty input as zero", () => {
    for (const arity of arities) {
      const empty = Array.from({ length: arity }, () => new Uint8Array(0));
      const zeros = Array.from({ length: arity }, () => new Uint8Array(32));
      expect(bytesToHex(poseidon(empty))).toBe(bytesToHex(poseidon(zeros)));
    }
  });
});

describe("the shared instance keeps nothing between calls", () => {
  // A narrow call reads only the slots it filled. If the wrapper stopped
  // clearing them, a preceding wide call would show through.
  it("a wide call does not reach a narrow one", () => {
    const alone = bytesToHex(poseidon([fieldOf(1)]));
    poseidon(Array.from({ length: MAX_POSEIDON_INPUTS }, (_, index) => fieldOf(index + 200)));
    expect(bytesToHex(poseidon([fieldOf(1)]))).toBe(alone);
  });

  it("a refused call does not disturb the next one", () => {
    const clean = bytesToHex(poseidon([fieldOf(5), fieldOf(6)]));
    const refused: readonly Uint8Array[][] = [
      [],
      Array.from({ length: MAX_POSEIDON_INPUTS + 1 }, () => fieldOf(1)),
      [new Uint8Array(33)],
      [hexToBytes(fixture.field.modulusBytes)],
    ];
    for (const inputs of refused) {
      expect(() => poseidon(inputs)).toThrow(HasherWasmError);
    }
    expect(bytesToHex(poseidon([fieldOf(5), fieldOf(6)]))).toBe(clean);
  });

  // Six packages hash through one instance, so a digest handed to one caller
  // has to survive the next caller's hash. It would not if it were a view.
  it("a returned digest is a copy, not a view into the module", () => {
    const digests = arities.map((arity) =>
      poseidon(Array.from({ length: arity }, (_, index) => fieldOf(index + 1))),
    );
    const captured = digests.map(bytesToHex);
    for (let round = 0; round < 8; round += 1) {
      poseidon([fieldOf(round + 1), fieldOf(round + 2)]);
    }
    expect(digests.map(bytesToHex)).toStrictEqual(captured);
    expect(digests.every((digest) => digest.buffer.byteLength === 32)).toBe(true);
  });

  it("a mutated digest does not reach the module", () => {
    const before = bytesToHex(poseidon([fieldOf(7)]));
    poseidon([fieldOf(7)]).fill(0xff);
    expect(bytesToHex(poseidon([fieldOf(7)]))).toBe(before);
  });

  it("interleaved arities repeat", () => {
    const round = (): string =>
      arities
        .map((arity) =>
          bytesToHex(poseidon(Array.from({ length: arity }, (_, index) => fieldOf(index + 1)))),
        )
        .join(",");
    const first = round();
    for (let repeat = 0; repeat < 8; repeat += 1) expect(round()).toBe(first);
  });
});
