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
    "632fd1c05ce6e89e58aba2c96054323ed24a1d99d1c148fdeccd837cdb3ffe2f",
  "custom_ring_delegate_policy.key":
    "296e64861dc2565b85a3567bd1c9ebba2757eefd08bfd10160d9fe248b86ac76",
  "custom_ring_deposit.key": "3a385a554a49c25d1eea8e3f5368874347ccb7c457512b5f0fe42ec519c498ad",
  "custom_ring_policy.key": "1ebc92edebf9f7e6e4c53194a8035e21b6785bee0e8c4e2f7422b1e44d1a72a1",
  "custom_ring_register_key.key":
    "926bc02fe4d70f3d8163e190a572be82f8a0506e4ce734525fd3f92cf40c3357",
  "merge_36_1.key": "dfa17449cc5a15d155ff788523bdb90d107d1bbb8a3ec2afccf6604aa96c76aa",
  "merge_8_1.key": "b82548555e44e5e825210feef0ac5951095c7827e95d6ab9e356223e9987d6cd",
  "merge_ring_36_1.key": "b292090e3e190c2cae8333fc5dabaa2c0f276e774da02217ee2aed5dfe99ddd8",
  "merge_ring_8_1.key": "6f9b09a1ca522c4ca89c75df569695b8204f4a5c08f4ff387721431986af120a",
  "transfer_confidential_1_1.key":
    "3f7f1ad4afc1d8a8172eb04ee56493be8a6a05f6d89c212ccbc9d42c799de994",
  "transfer_confidential_1_2.key":
    "48200e966af55ac370128e9e79d6a5b422be048d9bec2dc3f0f91d2092013c99",
  "transfer_confidential_1_8.key":
    "35564a323f154743f58d71ff40315d7504dbf55be4cc60d060d0bec2bf4eb8cc",
  "transfer_confidential_2_2.key":
    "e95ea566da49db5ffa4996a7ad044fa27eb2490f4b7a6290c9511ff991fd9b90",
  "transfer_confidential_2_3.key":
    "5deb467c5101c60341f2041762774c19d96da2984472ac9c5461ef5686881838",
  "transfer_confidential_36_2.key":
    "7c144baeab0a95ddf997bddaef9ba490d11e04c9fa0fa39eb5466d3a771adc92",
  "transfer_confidential_3_3.key":
    "deefea4760b4330520e00f8babebb9539883ac85f8cc3eba53373d0098f7aaf4",
  "transfer_confidential_4_3.key":
    "cb7118fbda360e3b5f7377626619a4f560f9cf25c97b8de69675968321a5b336",
  "transfer_confidential_4_4.key":
    "e71eed09c5d349e68553f065051ca479ff22f523f01176bfb0d24db7706aacc7",
  "transfer_confidential_5_3.key":
    "7fca62e7d512b3d128f0d39f366116056b689b42781ab00365e4c1ac84d4c80a",
  "transfer_confidential_5_4.key":
    "a9bfb2414951a7fe20a86e0cc040e131a6d088d1f181f3186cd37c1bedbddcd7",
  "transfer_p256_ring_1_1.key": "17cff01e615492feb8ad9f993f914b4391e1063a42f09ea6d983aeceb8cd4378",
  "transfer_p256_ring_1_2.key": "758cdf47d86c1b0027494fdd8b75609d75b09474a19fe7924dea7a9cdd3a85fe",
  "transfer_p256_ring_1_8.key": "cd9153cea4d5b292284c23761167b7f95d7c43cc9f4afffb7616bb8041f11500",
  "transfer_p256_ring_2_2.key": "270a1f4c94f1ea3f3b5f18e9a093cb6aaac346f39a600feb5ca848d17aca0fbe",
  "transfer_p256_ring_2_3.key": "f2cdab193e8bd5593439dfe537f06a857e17ae31b1a5f7ed316f2a337b698915",
  "transfer_p256_ring_36_2.key": "86c295d36ad58ef0352d47ee7119af4ba89e8581dd610604e7712ca912bbc334",
  "transfer_p256_ring_3_3.key": "1a4d13b95d9e1ae8988f91599680bfaa0cad3b94a56bd964df74c0c56c991a5f",
  "transfer_p256_ring_4_3.key": "22dda5a1c782b2bc45ad1b6beb3ff5337d68e2df8cf38f82fe50806c2be6355d",
  "transfer_p256_ring_4_4.key": "448f1827f463cf2e14009b5f420de4da46fe5c10d4097ef268f3d97f166e0b10",
  "transfer_p256_ring_5_3.key": "76e61116810353db8950a3923a51bc34a206ba8610e30f12f2a86b04a6c2a040",
  "transfer_p256_ring_5_4.key": "90678dfe1f38fa329261c567605aad3ea525e75a07b2c8ee074d9264f1719365",
  "transfer_ring_1_1.key": "09009322531ca9380b174ae82c324ffcf1f3692f8efda822ee85da302bc1df3c",
  "transfer_ring_1_2.key": "bb1da6113ce4f20cfc062703a7c86e78a5dacc7123a8e3f39deb3f0a19fd69fc",
  "transfer_ring_1_8.key": "2adef2103706bc1c6077df9e2313271eff3075c52b1cb544b77072edbc62ad7c",
  "transfer_ring_2_2.key": "b6d58e31a03abb044032e844177c3804e6d8729970543e2583094720c136ae6f",
  "transfer_ring_2_3.key": "ee3a8b30a90454f1db40eb5d70458f9db05628eb0bf04259909a9dedf0cf1b9d",
  "transfer_ring_36_2.key": "4e4decd490528df1ef4fe3fdb4bb55d7c13e8c348eb20350e0ffe3ce40634574",
  "transfer_ring_3_3.key": "8515fe347cd41cd5428b1f64653747353848f996e2b44ccb93fdb7921246e17c",
  "transfer_ring_4_3.key": "e9a9b0ec39efb9aac72186843ee5ac6410434f2714d38f3c5ef6f58c899dcfab",
  "transfer_ring_4_4.key": "b984211480a0547ec38626fcd1f09f9fde0ed9a5d61a62b3f3880443540bdf24",
  "transfer_ring_5_3.key": "11e505a662b7cefca9db757049c32044096b2bf28d2cecfeab42e82e73b142ae",
  "transfer_ring_5_4.key": "e173ec1d7220c837ac0f55616f09d0bcf05e7266aa8f1833b1c0dfaa6133e1bc",
  "transfer_ring_authority_1_1.key":
    "c036435a11d56b856c18c2377caef97a41d6a18321df3b132cef0b58127dac51",
  "transfer_ring_authority_2_2.key":
    "8f17f191c50329c2912fa9b575fe6eee4bd885aba88a374a257becae4a7edf0a",
  "transfer_ring_authority_3_3.key":
    "54fd75fe9058267173e2952c6435adc3b24347f79409ec79cd7cf4bff3f19daa",
  "transfer_ring_authority_4_4.key":
    "b6872c00c1c1557ca54d2976d1c49ccbbb5456763726493a543df53c2a07cdad",
});

/** A prove request's circuit, as the prover names its key file. */
export type ProvingKeyCircuit =
  | {
      readonly circuit: "transfer-confidential";
      readonly nInputs: number;
      readonly nOutputs: number;
    }
  | {
      readonly circuit: "transfer-ring";
      readonly nInputs: number;
      readonly nOutputs: number;
    }
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
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", {
      circuit: request.circuit,
    });
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
