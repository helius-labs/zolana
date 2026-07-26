import {
  type Bytes16 as InterfaceBytes16,
  type Bytes31 as InterfaceBytes31,
  type Bytes32 as InterfaceBytes32,
  type Bytes33 as InterfaceBytes33,
  type Bytes64 as InterfaceBytes64,
} from "@zolana/interface";
import { depositInstructionDataCodec } from "@zolana/interface/codecs";
import {
  SigningKey,
  ViewingKey,
  randomBlinding,
  randomSalt,
  type P256PublicKey,
} from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import { ownerUtxoHash } from "../src/index.js";

type KeypairBytes16 = ReturnType<typeof randomSalt>;
type KeypairBytes31 = ReturnType<typeof randomBlinding>;
type KeypairBytes32 = ReturnType<SigningKey["secretBytes"]>;
type KeypairBytes33 = ReturnType<P256PublicKey["toBytes"]>;
type KeypairBytes64 = ReturnType<SigningKey["sign"]>;

function assertMatchingLengths(
  interfaceBytes: readonly [
    InterfaceBytes16,
    InterfaceBytes31,
    InterfaceBytes32,
    InterfaceBytes33,
    InterfaceBytes64,
  ],
  keypairBytes: readonly [
    KeypairBytes16,
    KeypairBytes31,
    KeypairBytes32,
    KeypairBytes33,
    KeypairBytes64,
  ],
): void {
  const keypair16: KeypairBytes16 = interfaceBytes[0];
  const keypair31: KeypairBytes31 = interfaceBytes[1];
  const keypair32: KeypairBytes32 = interfaceBytes[2];
  const keypair33: KeypairBytes33 = interfaceBytes[3];
  const keypair64: KeypairBytes64 = interfaceBytes[4];
  const interface16: InterfaceBytes16 = keypairBytes[0];
  const interface31: InterfaceBytes31 = keypairBytes[1];
  const interface32: InterfaceBytes32 = keypairBytes[2];
  const interface33: InterfaceBytes33 = keypairBytes[3];
  const interface64: InterfaceBytes64 = keypairBytes[4];

  // @ts-expect-error fixed byte lengths differ
  const wrong16: InterfaceBytes16 = keypairBytes[1];
  // @ts-expect-error fixed byte lengths differ
  const wrong31: KeypairBytes31 = interfaceBytes[2];
  // @ts-expect-error fixed byte lengths differ
  const wrong32: InterfaceBytes32 = keypairBytes[3];
  // @ts-expect-error fixed byte lengths differ
  const wrong33: KeypairBytes33 = interfaceBytes[4];
  // @ts-expect-error fixed byte lengths differ
  const wrong64: InterfaceBytes64 = keypairBytes[0];

  void [
    keypair16,
    keypair31,
    keypair32,
    keypair33,
    keypair64,
    interface16,
    interface31,
    interface32,
    interface33,
    interface64,
    wrong16,
    wrong31,
    wrong32,
    wrong33,
    wrong64,
  ];
}

describe("cross-package fixed bytes", () => {
  it("assigns matching lengths in both directions", () => {
    const signing = SigningKey.generate();
    const viewingPublicKey = ViewingKey.generate().publicKey();
    const values = [
      randomSalt(),
      randomBlinding(),
      signing.secretBytes(),
      viewingPublicKey.toBytes(),
      signing.sign(new Uint8Array(32)),
    ] as const;

    assertMatchingLengths(values, values);
    expect(values.map((value) => value.length)).toEqual([16, 31, 32, 33, 64]);
  });

  it("validates forged lengths at public boundaries", () => {
    expect(() => SigningKey.fromBytes(new Uint8Array(31) as InterfaceBytes32)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }),
    );
    expect(() =>
      ownerUtxoHash(new Uint8Array(31) as unknown as InterfaceBytes32, randomBlinding()),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }));
  });

  it("copies interface-branded input and keypair output bytes", () => {
    const source = new Uint8Array(32);
    source[31] = 1;
    const signing = SigningKey.fromBytes(source as InterfaceBytes32);
    source.fill(0);
    expect(signing.secretBytes()[31]).toBe(1);

    const exported = signing.secretBytes();
    const blinding = randomBlinding();
    const encoded = depositInstructionDataCodec.encode({
      viewTag: exported,
      owner: exported,
      blinding,
      amount: 1n,
    });
    const snapshot = encoded.slice();
    exported.fill(0);
    blinding.fill(0);
    expect(encoded).toEqual(snapshot);

    const secondExport = signing.secretBytes();
    secondExport.fill(0);
    expect(signing.secretBytes()[31]).toBe(1);
  });
});
