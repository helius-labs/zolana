import { InterfaceError } from "./errors.js";

/**
 * The sha256 of every proving key the program's verifying keys were
 * generated from, by key file name as `proving-keys.lock` and the prover's
 * `GET /proving-keys` name them. Mirrors the `PROVING_KEY_SHA256S` tables of
 * the Rust interface, nullifier-tree and custom-ring crates;
 * `test/proving-keys.test.ts` pins it to
 * `prover/server/prover/provingkeys/proving-keys.lock`. A proving-key
 * rotation updates this table in the same change.
 */
export const PROVING_KEY_SHA256S: Readonly<Record<string, string>> = Object.freeze({
  "batch_address-append_40_10.key":
    "589c90ea00bc771e7b61c28c20290c4dfaa9a33790d7231261d7bbe621459843",
  "batch_address-append_40_250.key":
    "aacd3c81c4681acf0eb21e395df4f566738412da158153b1dee7ac83219dc425",
  "custom_ring_base.key": "c4a6e3b31546317cf2448b9392dab5a3172caf5c90542230e70a7e17901d9f1f",
  "custom_ring_compressed_policy.key":
    "bba441c5d149f6e7291dcab85022b18d8c68ab2017474017dc2fd833eb81ebc3",
  "custom_ring_delegate_policy.key":
    "922288c3dbff7bb5d7b5af91c84c223c33809668ecce87f01a02be4beaac1a06",
  "custom_ring_deposit.key": "3a385a554a49c25d1eea8e3f5368874347ccb7c457512b5f0fe42ec519c498ad",
  "custom_ring_policy.key": "b73e9883cac61948add911295fbaf36856020d9b77293b9da3981f9d1c25b011",
  "custom_ring_register_key.key":
    "926bc02fe4d70f3d8163e190a572be82f8a0506e4ce734525fd3f92cf40c3357",
  "merge_36_1.key": "60444a2b76befff6207050ae292f7265dbfa57cf8289725e0b1a4949648927d4",
  "merge_8_1.key": "6658a6d76fe21dd44ae027c35ed5d05b6a53ed869937bb3e110cb311ec673329",
  "merge_ring_36_1.key": "45cb914998f9bac8a61edaa607b30ba6ce23be5af81d173ca4b6573e60e3b937",
  "merge_ring_8_1.key": "ab92956659914554cd561a15c6ab2041d844c87ae6ce8828711aaf68282b7386",
  "transfer_confidential_1_1.key":
    "56816e7b4887386c24839671cfbebe500d35d8ec4b733a11b1f02af4c08629d1",
  "transfer_confidential_1_2.key":
    "3e9cc4fae9f6432b16e2e77db74dfe20986a821b0bff4797b13286ae3c4c2f3f",
  "transfer_confidential_1_8.key":
    "39b7b80dc231614017bb757c8b08aea7efdf4dc7e592072ab02ccae0fa4e7f7a",
  "transfer_confidential_2_2.key":
    "363d50a9a31e85e83922427be0311cab9d41034da5f3723a464dc7fe0c2bd231",
  "transfer_confidential_2_3.key":
    "dc40be6315c921ff9c69651e51d891ca3cef936630d98873bb0a767c039ab0dd",
  "transfer_confidential_36_2.key":
    "3e9d3645f193e1fad991b67b682d1a0a6e8ff9155191855bd23ab9cbb79183b8",
  "transfer_confidential_3_3.key":
    "e3975ff86766b39087cf3a4bf3602e68a06767864adb683da73e2c4fd4eb657e",
  "transfer_confidential_4_3.key":
    "36d517654f349d0d5dc8a79f54a8b7ef1556cb60a381bc7be68dc9fd3770580d",
  "transfer_confidential_4_4.key":
    "ef02a4d9862585b22b97957916f3034cc49fb6078f04dd2c07e57b4432faca78",
  "transfer_confidential_5_3.key":
    "f38a53aeb9b2cf674a3faeee97ce9182d9be354c0480144e85354d89d4f326d0",
  "transfer_confidential_5_4.key":
    "5da2821da6c1fd1183ebee5fb3477bd527a1fa82a2efa053bc75ca357c05be5b",
  "transfer_p256_ring_1_1.key": "13e30bda4015db68bf4571519fae45e84ba3258600fabade25ddb0f134665af6",
  "transfer_p256_ring_1_2.key": "8d534d464c648e4efb99a7114903eba8b22d4233be3849d68f8e1175dcfd7d82",
  "transfer_p256_ring_1_8.key": "3399026c70f64305e042e9c7886e016eaaa869d7d35257c196928c4379b27e99",
  "transfer_p256_ring_2_2.key": "83f3f83a2d76cc823bf5679f95e5b3f58b36e62d5087b94f3ab433ddf67d83dc",
  "transfer_p256_ring_2_3.key": "63a60bc3352f335fd6be00cb7f6521ae6832ede9295204d32d9b1f5183bb6889",
  "transfer_p256_ring_36_2.key": "25f101527559c9134d8ec5ca106ffd9793d06806682d299c59fb7a99ff7b26e6",
  "transfer_p256_ring_3_3.key": "9c45ba380c889616ad5c6c5ca0445f037982105d8297ff473719db5c088b202f",
  "transfer_p256_ring_4_3.key": "91a33d0f6c44b9dc964392bdf0e1da854bc2d3e8ee165726822f44bd074da129",
  "transfer_p256_ring_4_4.key": "81e56df6fd87414b80cba15e12637f379d42720050f622b29b07f60de28f7d5f",
  "transfer_p256_ring_5_3.key": "8db09666a8e2a0890c438efb62105123997e2812183fed7c1e9870d7275bf19d",
  "transfer_p256_ring_5_4.key": "d706c0cceaa3e2825c2d06417bb784307b20d85b8449b4ebe302236d9da42fcd",
  "transfer_ring_1_1.key": "fa3e85bcc4a992575eb70799e49e1afaeb00cb1b3417daf4d85ca199ccf9d69f",
  "transfer_ring_1_2.key": "f1c3255602c256206d5fc299a642541f19a432692e8c2c0d01bf83884b402f79",
  "transfer_ring_1_8.key": "49753462d0ae8f441ebcea4b69f13a8e3b97882db50eca0492397729abe26a1a",
  "transfer_ring_2_2.key": "a6885269fcd307f1be92770fc3a32ded2e67230d6b45a811de7ab75ca5007897",
  "transfer_ring_2_3.key": "0373a18d3725f3b0d2b0e8e5eca0577e75c06aba7f0f786546632f69b0b0dd77",
  "transfer_ring_36_2.key": "c3c56dedd4bcc66b914321c38984287de8ea4e5f482d4bc1185546df3adcd866",
  "transfer_ring_3_3.key": "e28f0fec223fcf6b72d44fe38fb445caffadabccf9ccc6e97c4f85253e56a279",
  "transfer_ring_4_3.key": "2bc946b607cacdeb72f9a1de29cf18a772d7ee392e146e6ea932a516c44016f2",
  "transfer_ring_4_4.key": "390a6aad2334d0c90cd78187c047e40915a954cc57dba98b7cc8f4389ff95b2d",
  "transfer_ring_5_3.key": "af3339f8cfc83debae2c5ae93e109f97a53f23d73cb25f966f94e5294bddf80d",
  "transfer_ring_5_4.key": "5208110cfe9d04a4bc24fc3ef65d70fa9bb4ca8bee66720ab27a0c453f178c9c",
  "transfer_ring_authority_1_1.key":
    "03493e06812091add92abdd8117bbfcfd376951f3c63cca7f2786fca8d3923ec",
  "transfer_ring_authority_2_2.key":
    "5343ca34d6ddd3f189b005ce8de5124944ff91ccde1fb14eba27939ebf91d65a",
  "transfer_ring_authority_3_3.key":
    "a45b5c13fa972cf5b87681a23d1e479fa3e041dd12beb58e121de1a070aac780",
  "transfer_ring_authority_4_4.key":
    "d8d43f37cbe8e2ab053122f5039253c9222f2e698e0bb2c30746772a17f56870",
});

/** A prove request's circuit, as the prover names its key file. */
export type ProvingKeyCircuit =
  | {
      readonly circuit: "transfer-confidential";
      readonly nInputs: number;
      readonly nOutputs: number;
    }
  | { readonly circuit: "transfer-ring"; readonly nInputs: number; readonly nOutputs: number }
  | {
      readonly circuit: "transfer-ring-authority";
      readonly nInputs: number;
      readonly nOutputs: number;
    }
  | { readonly circuit: "merge"; readonly nInputs: number }
  | { readonly circuit: "merge-ring"; readonly nInputs: number }
  | { readonly circuit: "custom-ring-base" }
  | { readonly circuit: "custom-ring-policy" }
  | { readonly circuit: "custom-ring-compressed-policy" }
  | { readonly circuit: "custom-ring-delegate-policy" }
  | { readonly circuit: "custom-ring-deposit" }
  | { readonly circuit: "custom-ring-register-key" };

/** The proving key a proof must come from. */
export type ExpectedProvingKey = Readonly<{ name: string; sha256: string }>;

/**
 * The key file the prover proves `request` with and the sha256 its verifying
 * key pins, mirroring the prover's `determineTransferKeyPath`, `mergeKeyPath`
 * and `determineRingKeyPath`. A shape without a committed verifying key throws
 * `INTERFACE_INVALID_SHAPE`: the program could not verify its proof.
 */
export function expectedProvingKey(request: ProvingKeyCircuit): ExpectedProvingKey {
  const name = provingKeyName(request);
  const sha256 = Object.hasOwn(PROVING_KEY_SHA256S, name) ? PROVING_KEY_SHA256S[name] : undefined;
  if (sha256 === undefined) {
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", { circuit: request.circuit });
  }
  return Object.freeze({ name, sha256 });
}

function provingKeyName(request: ProvingKeyCircuit): string {
  switch (request.circuit) {
    case "transfer-confidential":
      return `transfer_confidential_${request.nInputs}_${request.nOutputs}.key`;
    case "transfer-ring":
      return `transfer_ring_${request.nInputs}_${request.nOutputs}.key`;
    case "transfer-ring-authority":
      return `transfer_ring_authority_${request.nInputs}_${request.nOutputs}.key`;
    case "merge":
      return `merge_${request.nInputs}_1.key`;
    case "merge-ring":
      return `merge_ring_${request.nInputs}_1.key`;
    case "custom-ring-base":
    case "custom-ring-policy":
    case "custom-ring-compressed-policy":
    case "custom-ring-delegate-policy":
    case "custom-ring-deposit":
    case "custom-ring-register-key":
      // The prover's `RingKeyFiles`: custom-ring-<x> is custom_ring_<x>.key.
      return `${request.circuit.replaceAll("-", "_")}.key`;
  }
}
