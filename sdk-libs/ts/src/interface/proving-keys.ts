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
  "merge_36_1.key": "60c357e8513b9e5d354900929980d1e8d3e132d6db67c50f68b5616630cf58a0",
  "merge_8_1.key": "3df1cc825e4c949aaa605c283fd232f7a2d2901b73d480f36289c96207a39277",
  "merge_ring_36_1.key": "d7cf47f5465f1f266d9532029cd03da75ba84883b3ad60c721d94f8d106467b0",
  "merge_ring_8_1.key": "68b11bc4da54b9655837a50adde4e5ea59737b273bdf605cbde0e7fb7e6eea9e",
  "transfer_confidential_1_1.key":
    "73218c4b3c0c037c759045e1d869bb6c03a2ec0bd42b7484a89f201218fb2894",
  "transfer_confidential_1_2.key":
    "df4638482f6f9f1f6a4093a8db26954422dd2458ddc07e22035b304304425cff",
  "transfer_confidential_1_8.key":
    "a24cec1f0311ecf51446f334ed30e6867a35ec38a175ff55cdd1221ae469d3df",
  "transfer_confidential_2_2.key":
    "a1c9e85be75d229e7b53fbd734a036275e0c5f2077ffb2a78c43fc7d27e9d973",
  "transfer_confidential_2_3.key":
    "55bc6b864955505d443f69a6c7ccde982ac4df75a2a48989611f41cd4475f9ed",
  "transfer_confidential_36_2.key":
    "7a71b3229aa0eb02a86715139ddd2e32a0c72f0937a5f505b89a3559e8be24f4",
  "transfer_confidential_3_3.key":
    "28ed75cfd3251203438400b5e4b699299d1b73f5d72ae7c83a826626b5b9d1da",
  "transfer_confidential_4_3.key":
    "b3ebc584080de36c04a22a2d063e519aafb36215eb8da9d3a80310d041b856e8",
  "transfer_confidential_4_4.key":
    "bc743e88a2379248ec969843ee01ebb13067d1c906cbeb50e1d42b30708cb30f",
  "transfer_confidential_5_3.key":
    "739071e10e0f4221b3a2de617415c928f70c0ababebd9c022169bfb8beaf9a49",
  "transfer_confidential_5_4.key":
    "3af6b0370c06f0979987256b80e171a1a45a0dfbbca687a30187f2052191ff13",
  "transfer_p256_ring_1_1.key": "599382ec7d10219c4b09c0f37547002270f7f462426434035adfa120d5299e45",
  "transfer_p256_ring_1_2.key": "6cf2b03cedeeef9584e8c6ddca1858196473304bf1c5914f128a40e54ce2ed41",
  "transfer_p256_ring_1_8.key": "0693e9a9d7668de5b27b734425ee7a23646f1a76c2e5dfea3e4aa7801a496475",
  "transfer_p256_ring_2_2.key": "a42906b64c5bc9e7f043dd431aee2368c35d27c4e79aebd06485ba805a203971",
  "transfer_p256_ring_2_3.key": "9e25a3725fe9d03afd49c1660f464090d5b650d4c70cf50e2199c295cabbff68",
  "transfer_p256_ring_36_2.key": "0d5894638f3adf147a05cdc835b9e01684f4b1dc376e29f883b0122acdf8fb66",
  "transfer_p256_ring_3_3.key": "6bd53d7b955d5c443d2984325b342cb29b50396f94d0e08204b5468a6157b351",
  "transfer_p256_ring_4_3.key": "4d31320fdb3736aca19bb55aab79a4ba1105375571c698dd20c24911b0573028",
  "transfer_p256_ring_4_4.key": "746c17e021085beb1bc16adf26eacc41cd2dc849911bc206d83126a71a176c04",
  "transfer_p256_ring_5_3.key": "7563ab7dd50282b873da3a40b69df023bd141f625ffaf588d08900a048383c00",
  "transfer_p256_ring_5_4.key": "cb0db062416b11a55329c9de4028af952901f47595d7c5287ed6a42e80e6286b",
  "transfer_ring_1_1.key": "e459a85334d751b4b8783e1d948289825ac610d301673826dd4e56f8489de334",
  "transfer_ring_1_2.key": "7f8f51f3d81b0bc799486c426cbb119b821a47dfe408ac5c7b268d9a6ef54931",
  "transfer_ring_1_8.key": "11546caa62f2a49381e9035e4e841e14acd3a977627fd6e3e44081d281856b67",
  "transfer_ring_2_2.key": "a4e61869d9682f2113a92d731e3058fec140d1759f8907aaf6bbbe4aee326216",
  "transfer_ring_2_3.key": "456b9084b3c4ad3daf946bed738103363299e0c4bcbb739ac998c3ab99a0eaf1",
  "transfer_ring_36_2.key": "22a3baab6a4896538cc1e2528c7e30e5b3ac6bcbe9474fa86401be2f75e0ad16",
  "transfer_ring_3_3.key": "d8d62501a3dc8ee22564a673de9f88862eb3c2e254151be097c5895da986041f",
  "transfer_ring_4_3.key": "7e6e5ae3bac2bb5f09e61e283717479c34a27b66fe3bdc4e0fa112f61997461a",
  "transfer_ring_4_4.key": "d397ffeccd4004315a5a669ab590781ddbc2b74efd9029251a6bbaf042e354ef",
  "transfer_ring_5_3.key": "87efa4b173667ddff52693c5373d6402f4c654b9096ea506552bc601505e2412",
  "transfer_ring_5_4.key": "966958961f066b81d461848fa8f9c4a21a8a86a9a6b52240da514a14a7c12c4e",
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
