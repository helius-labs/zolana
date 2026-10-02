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
    "cf83a6b9a79cda54a8b1ca86ea8d24a4a234357fb612cfa75c19d83b98bbe91b",
  "batch_address-append_40_250.key":
    "f3da078cb8f73adc958a44e1f173d72ac6b998ffa0bc469774f527aca7a46e1a",
  "custom_ring_base.key": "5d521d3506f9c2774528f26aa1fd9b88206f029f3fea3b64949fd257799e968a",
  "custom_ring_compressed_policy.key":
    "8e34626c634980d159687e9c1d8d249680afd3f58e72d7e6af298735e655b8fe",
  "custom_ring_delegate_policy.key":
    "30c6b7bd43baf611618a117f758318f31f90221ade95f23aca71b61617d8fdb5",
  "custom_ring_deposit.key": "2bec7dafdd796d6d3b2b7f8c9b54bf946e6fa6457ca43edc034d4b420f331e8f",
  "custom_ring_policy.key": "0fe940ce0536637b8a7e2c59b262b9533355922399df60915004f8d921143e11",
  "custom_ring_register_key.key":
    "9510913e52977b592718cca5ed568ed4fe33688efb2905cf360334ec42a6684d",
  "merge_36_1.key": "f5c6a061d80325bccb0e60d9c5754ca4c0f9a0970b1eda84343636947ec0fcde",
  "merge_8_1.key": "1967c04328d4635698842ddd920042a8969cecf1dd807cade1907ca5f1de50ce",
  "merge_ring_36_1.key": "0f56a965f19958ed1d69b257d8df95b043aca8e79b496543cb28639a99cea44a",
  "merge_ring_8_1.key": "ce4e13c1108e6ad67a2c628e9bf571dcf66f6363d18a5d7733eaa4f72368cfdf",
  "transfer_confidential_1_1.key":
    "93a6fb3329a7fccd89671be50abed487d21099850cdceaa7f19eba515824271e",
  "transfer_confidential_1_2.key":
    "a45ac0683aa04c4840b1466d5eb1a1495eda9f7a5f6cc1c89f2bb73c81a2635f",
  "transfer_confidential_1_8.key":
    "937c6a05b051f91d0b7ea80f802800dbd7ca2bfd6a8b52ea8688827eea8fce96",
  "transfer_confidential_2_2.key":
    "039a6e6e96da804fdddf7c61061f6e919e2f4fddd2338e3b0546f30bec7977b1",
  "transfer_confidential_2_3.key":
    "eecf18a22bfde054a660197e44cf2f6eb405db75789d70fb8c662e09bf7a09a5",
  "transfer_confidential_36_2.key":
    "796d60a0710272ce19c4e15f8b00dc5d5f007f107c116e03d0c46a4d732eb2cd",
  "transfer_confidential_3_3.key":
    "617373459a5ae22982758cc6fc99f1a0b289f09491b1c3fb74cbbcfd55e9cf7d",
  "transfer_confidential_4_3.key":
    "01a813ceec48bce0b06276143e3c54502346e26eb7fd74162ec7efb61e62c6f8",
  "transfer_confidential_4_4.key":
    "6a1d1132e91851b68d0a2f9e7f4c049bb7d8f9769f065ea96d0f89a3654a6bad",
  "transfer_confidential_5_3.key":
    "591cf4efaf9beffdc3cd8aeaae47538cacbc8051fa3694fcb0973056cb80a236",
  "transfer_confidential_5_4.key":
    "61edec2c236d97e4ecac7496b7c3fe2d12b7f4b3405ac051d20542a899866f7c",
  "transfer_p256_ring_1_1.key": "908ed01bbfb39715230ccb84f618b797dae87793a463522aa8da161189f92594",
  "transfer_p256_ring_1_2.key": "b9b4b131d8b84ecb54f1b0b959c8442eed0804ff523c537c256fe2f340bf350c",
  "transfer_p256_ring_1_8.key": "5b8183d57b52e75377ac67db4bcf7e7570e962b0003fef07000e175593e2c2a1",
  "transfer_p256_ring_2_2.key": "3bc2f29e44d813fc112c8229304f92434b14f5f4692f29b1bca0fca578e92523",
  "transfer_p256_ring_2_3.key": "379e8ee46fd4706df8eba0e4e61d2fdee0476db10c14e6bef1da935171820bb3",
  "transfer_p256_ring_36_2.key": "560ca70625c2745369c644f37760ce3d72423a3e5bc3079f097d330d033f6709",
  "transfer_p256_ring_3_3.key": "bd80d7066ebe1f7011477761993aead41c31b653477aa2ace1147ef4c21f8abc",
  "transfer_p256_ring_4_3.key": "94319d5119cd06db9e40add3391d8f4a39e19260977d012260cec9507f976e16",
  "transfer_p256_ring_4_4.key": "a2f9b441b2fc9ba7e8ba484989820e597e3da5eb3d4cb0f4c5e6c2e0eadb044a",
  "transfer_p256_ring_5_3.key": "e1e37f842978ebccbcd5dd9196894727afd4b815ae67253178da05b2162dadfc",
  "transfer_p256_ring_5_4.key": "1b4bb5b707c05379027179b5da8d27a16fb784446486b8b8f06ef1a77f6edf6b",
  "transfer_ring_1_1.key": "afd16ade539877040d16e5170069c141fede3253a0372b563925c13dafbbb19f",
  "transfer_ring_1_2.key": "500f2bbb976e9e2bac3fcb439329c0db1d5f9b8101d2abfe1cc478e2e99ca0f6",
  "transfer_ring_1_8.key": "b2b72962030be117bb5c5ce84929d16330937a26377f2bf964a2771177322dc7",
  "transfer_ring_2_2.key": "ef66471f900bf32e851721f9e1ad26249fd082f31e8bddb78e8c01971941ef87",
  "transfer_ring_2_3.key": "bf8d698aa335145aadf8da71c722597d2ba173b76c52c8d2a1bd7d06f2b993dc",
  "transfer_ring_36_2.key": "4a322cf47e137d5f04912e9038d4c545dede874050e493b2fe3ac7959cef36c4",
  "transfer_ring_3_3.key": "650204cf115e284a91c26a245fbb870c6db5e1c635c3037841e55776f37df670",
  "transfer_ring_4_3.key": "b375fbc9f914c80cc644ca6463bb922b0ac785d6ad567b831ed9450f7948840e",
  "transfer_ring_4_4.key": "3611ffbc30826b2fd67247d650b7938390b49d34edee66a0a8abe800e0ebdecc",
  "transfer_ring_5_3.key": "05b335d3a302bde3b9beca35baf25a9e7193322c51826aa0ceef9306763b0e3b",
  "transfer_ring_5_4.key": "bce3e1a6588d761235c63ab120b9ac17cff1505edb67c1681810d21694cce9be",
  "transfer_ring_authority_1_1.key":
    "290fa1b8eb99d01853ed626e8b117aa8407ba9d8da781317c9d721267325380b",
  "transfer_ring_authority_2_2.key":
    "8b1c85557acf1bb408ceb25e814a59dce70f1a3955a9b5b01f525eb9c7766d9e",
  "transfer_ring_authority_3_3.key":
    "9c3e7dc75038a85df0aa9d5cd313f1124925ba5e90dd641f93d420d1fe645661",
  "transfer_ring_authority_4_4.key":
    "8b3d96e8b5ffafa2449e0d2e60e1047ab3bc18b862e7dcdfeb660e03a2718d62",
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
