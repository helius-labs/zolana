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
  "merge_36_1.key": "a723d84f44981d4e61cadfc2be431ebd2b487b7980124c87e1f194745fd6d2bf",
  "merge_8_1.key": "4d04e43f10b51af3f817be138c151c521ea53958bc93ca7a4cf632dfc1189fbe",
  "merge_ring_36_1.key": "95421b7a08f97c32289a1cb754f6faa3e2ce64021d34a61ab7f9e82393299d61",
  "merge_ring_8_1.key": "fd286b0f39bd9da4b6a76297fa1aab291b6edb7dfdecc3d9c7a83505cd57057f",
  "transfer_confidential_1_1.key":
    "329c4f7d4a7e68b06c49876bd6c3f22ab89c7679c978c866c4a6cdfb92d9a998",
  "transfer_confidential_1_2.key":
    "542d4eff2a8826bcbe6088dd10ac2da0d11e606d70ccb27610e483a372d1cbc9",
  "transfer_confidential_1_8.key":
    "e7fd7c2866d2335038497bb24d91a88a6ecf760731efb0befce91ab4174e79ce",
  "transfer_confidential_2_2.key":
    "1e76d991cad1c33444a9d7c18b855861abb3f5b03451a0e9386c8d86c061b73b",
  "transfer_confidential_2_3.key":
    "e7c41dfcbfd8cd9367860e866e95632cb64b7bedd9a4c6cb56af81f1c39cb84a",
  "transfer_confidential_36_2.key":
    "f957d9d4e0f0e724ebe3553f35baea43f45f2544e1d15f4957752a4139dfaaba",
  "transfer_confidential_3_3.key":
    "40bd74eff9865e53be3eeaebaee8d81c04b8a3b6d1607a6968b24284805e7dcc",
  "transfer_confidential_4_3.key":
    "f4af25c73d0c4b40b52b82cbe1f390030f034bf01adf33050a317c9fc1bc6f79",
  "transfer_confidential_4_4.key":
    "f427fa6c6d70d50a5c206bbe1ae5430d5210e03c299d1896cb318ae2e94f499c",
  "transfer_confidential_5_3.key":
    "b543b4bd6f428d582875c1e0eb3ecf2f954b0b2ed39609cbff69cbd77a46a2f8",
  "transfer_confidential_5_4.key":
    "7c16743714e757447470956aa2017261e836ad2711bca63a230c92aaea949f7e",
  "transfer_p256_ring_1_1.key": "e6a59ecfb0c09c1fc3af7a8b6783012bdec9e153f6af2cf31c276eea5082c13a",
  "transfer_p256_ring_1_2.key": "e3a5c3182017b3d02c5a3a4fdc023d210616586e26bc753771343f15f16b78f1",
  "transfer_p256_ring_1_8.key": "87eb080c65036b0d5d2bd22c37e4f318d15bec75f9abe6178ffeaa01b5997c00",
  "transfer_p256_ring_2_2.key": "03006e7bd8591c0c9446cc77517797239bbd437cc3f3204e18ba40a693af7e8d",
  "transfer_p256_ring_2_3.key": "697ca72692d82042743915ff032e9110ebe6528a110db2e25cb9d5ce388d41fd",
  "transfer_p256_ring_36_2.key": "8e3d929f8700ceac799b0235cf831b6db42a436461e213da84b2f53aff9d687e",
  "transfer_p256_ring_3_3.key": "ca824818029bf25c3cd954e300db4176d84556908788eee951b95b55228756db",
  "transfer_p256_ring_4_3.key": "0ac7f0b6de9a46c8a92d6c6396e5ed3fa79d7e85d7f248c1d1255ca9e0c5db2b",
  "transfer_p256_ring_4_4.key": "8b1c2269a01b7b18b7b8af78d6503b988090bf96fe674ab99fed761423c61f97",
  "transfer_p256_ring_5_3.key": "fdd5ca4c35c3415bf7a09c8788143773f020427a490d7f2b0a28c84c2b3b2197",
  "transfer_p256_ring_5_4.key": "4cf9770d0a3e26f05cd5602bfe40408d10cef1752ad72526b02a72ceeea1d688",
  "transfer_ring_1_1.key": "c29831966e1d395526c50704ab2184382688a8aa8a1a2dbf0751e69f3e117347",
  "transfer_ring_1_2.key": "acfba67724c5dd61706db0ce19332be1209d9ac9fa81189522f47cef76aa60a4",
  "transfer_ring_1_8.key": "7e3ffc229050a1d6d6a9e4348b6bd11604108c53599c319a3dd59f5158059ba3",
  "transfer_ring_2_2.key": "e7330afca55fee5cda6e02412d30d5191359d0528460790a215d90bb01c7a333",
  "transfer_ring_2_3.key": "919951294d38d80400254aa6d349bfb2fd910c70aaee458e52d5d77f62ce4def",
  "transfer_ring_36_2.key": "fe77128789e649ad0ac461262e4282c2887d6ac34b44622c913d4b58226b4467",
  "transfer_ring_3_3.key": "5b551fd7f43ec513d09bfba09e00e47842ac70ebd3abff2e8fc47a9f7f80d777",
  "transfer_ring_4_3.key": "3a4d687eacf434144195dd5e8d197aae2ccf6a2ff01ee38c23d4c5de10c79128",
  "transfer_ring_4_4.key": "b823647102dd91acd90facb5eeb50803eb745b146ea0ba3ac059d10c90fe5257",
  "transfer_ring_5_3.key": "5e0c0dfc352592aa52c6f6f5b81b1cd585c661c9f3492258332e0ec2621445cd",
  "transfer_ring_5_4.key": "847519de8b1bad0d4f715faa6a982026590c114f3a9906a0e1e56d1537cfa988",
  "transfer_ring_authority_1_1.key":
    "b86ed2842d8e3b6f522fc40ac9a0d69e9f880ff042a6b7f606533406d06302f4",
  "transfer_ring_authority_2_2.key":
    "6c6ed93af4dd604a24005873907167bf71b867163b6b3725089426aa22143d7d",
  "transfer_ring_authority_3_3.key":
    "af9c9ba90015efeb0d14e8760587a052d72539dfdc0b85a984aa10e52ead306a",
  "transfer_ring_authority_4_4.key":
    "1b274be694d93ff29eba85b756fd7c2c0bcc74e4299b0407fee58a6ff00cf76a",
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
