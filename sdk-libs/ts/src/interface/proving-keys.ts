import { RING_PROVING_KEY_SHA256S } from "./ring-proving-keys.js";
import { isAnonymousRingShape, validateRingPolicyShape, type Shape } from "./shape.js";
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
  ...RING_PROVING_KEY_SHA256S,
  "merge_52_1.key": "f84505118f01094c89cbb3d14e59df3af309374140ba31a0d8262ccba94c83a0",
  "merge_ring_52_1.key": "0b73061a902ee63bcbd8964715258ff7d830a9e439a6020811bfcf21889b7dd0",
  "batch_address-append_40_10.key":
    "589c90ea00bc771e7b61c28c20290c4dfaa9a33790d7231261d7bbe621459843",
  "batch_address-append_40_4999.key":
    "367fd7d2f534810ec684b7dbbadfd90dc65550d26989a2f2945d4719702001de",
  "merge_24_1.key": "fdcc01acdc72e7b472641ac8782af5261a82729bd31af869ac9cba5950efc67c",
  "merge_8_1.key": "77008892dbd5b902f9fa2a42cfe8957966a96227fa6b1de11d88f215dd44e9bb",
  "merge_ring_24_1.key": "7b364816db34c03d1e5411df575662b1951f31a9c2b240d2ac0dfca6035b5873",
  "merge_ring_8_1.key": "cd6109e8a401d35f94830b5e2a624dca7421ac708116dabd639cc98f040fe9f4",
  "transfer_confidential_12_2.key":
    "f97bd750648a767ea2f660f713f1e9139d7355f41f26dce274f50ac9bc3a1b9c",
  "transfer_confidential_12_4.key":
    "79625237ff8d673999cf3c78b5998d53ca9acc838d3d7bccbbb288ba3a0947af",
  "transfer_confidential_12_8.key":
    "a6caf80326c6fc3ea4f987aa37c76e9dd9532e82cdf65f1bef50c14abc5a2dda",
  "transfer_confidential_16_2.key":
    "c1567923bb8195606eb66cda4ddcff0ab7145de1b89c0f8c926d41e7e41fda12",
  "transfer_confidential_16_4.key":
    "7b0c7f94baff6297bb3158359eec1b4489b28e4eda20347c1ed24b06847a8e44",
  "transfer_confidential_16_8.key":
    "60269cff6c59500a50cb5b6539a3aab3fc6c102a6f216e5ff4bafcb8c7a9fcfd",
  "transfer_confidential_1_16.key":
    "6b3d6d3a0cf6d3befa4fab316d3190e4c4ee1867c6d9de71a2de8cbb1bc2c383",
  "transfer_confidential_1_2.key":
    "63fec3e6284bf47f0095803859efffd5a948629501622c3227042c6718ba19d5",
  "transfer_confidential_1_4.key":
    "36f94d0133e555e3860e045580dcc2f0d7b5c8968946b14c5be7d01adb0e0055",
  "transfer_confidential_1_8.key":
    "6910a9621bb9452e5925d0e790b74e6d27f3b3a1fe1d288305cde48171957522",
  "transfer_confidential_24_2.key":
    "b5b33814223d17e9b1db4a24268b5eda24af36a9af8062dfb08e6a1391346ac4",
  "transfer_confidential_24_4.key":
    "97d6b9a29667cf9388a964fdc2e81da09a8dffc50a7da7d1910a79393c6bd470",
  "transfer_confidential_2_16.key":
    "e284fc565ad50220159af043b3ef4395d00704dff4f4585eed46a0b540b1fcf5",
  "transfer_confidential_2_2.key":
    "5c6d38f60464c7d3704b2b1edd93ac6c826d0df8827293884d7b30690fc204f8",
  "transfer_confidential_2_4.key":
    "1fc6a07b1e968dec87592dbf58ecbe92c0c5d7dd0e5e589c08dbf80796224f2b",
  "transfer_confidential_2_8.key":
    "c33f83f029f46e0d1f977eea479aa62d475985db2ffda509297d4b297430fac3",
  "transfer_confidential_32_2.key":
    "785153ba7ad8cc3a8a16e54ebbbbb6d001635f2e81bc5b4785803b860ce03a87",
  "transfer_confidential_3_2.key":
    "1da53f2a56462417253b26cb0effd9d4fbb8a11bda720e7921c49cda7e5e6316",
  "transfer_confidential_3_4.key":
    "35cfb48e07cd38f3c1b49e81f20ee4c74940f6f6c7fc7230ece1c17ac56f45ea",
  "transfer_confidential_3_8.key":
    "01f87529ca7ffd1d7d91fb74e5eb7c6222a3a7ad62dfa479dc7e07bd96af01ce",
  "transfer_confidential_40_2.key":
    "e5ba9e619453c669848c111607665b610d7b924826ce5580848dddf2a31da9de",
  "transfer_confidential_48_2.key":
    "644482bbb1fab113ee9a9c1b91f884ebfe6a5864e004e641ff200a4b170afcc6",
  "transfer_confidential_49_2.key":
    "53cbbd93ac9c53a87d5883b15b3b81c88afc1e9f45a86c1e63e24193c75b2774",
  "transfer_confidential_4_16.key":
    "c186822727ca00edbd96ba4db248d8629f08cc2281a9d3805d270ee2f6fb3098",
  "transfer_confidential_4_2.key":
    "967d32c97e0a1e1150cd3f5e3a69bf86f1beb44a1f1143563f42e4ee98ce7c6f",
  "transfer_confidential_4_4.key":
    "049cf9701bec7a414bcd064351acd3f10a2f4c69aaa10953d355c0513a302070",
  "transfer_confidential_4_8.key":
    "7df8bf5e2e8baf9bf4b8340c21c852707c45ee07cf0bef064f24d7a90857910b",
  "transfer_confidential_5_16.key":
    "be93ae4e719a890e8f5e68348ec891a691e9b44127271972dd1a30ea93487e54",
  "transfer_confidential_5_2.key":
    "eb62fdaf21552d00292ba6513d0b5aa49b93db1975b909eecbe92d2625e09aa5",
  "transfer_confidential_5_4.key":
    "ef1729f5d24b5a7d0cf0f906e71e3e63ab31ae02491ef2140c7e3b7e7b68f1fc",
  "transfer_confidential_5_8.key":
    "04cde7cd928e58001b5ad3bb1213aa789eec2da7bc0215c9bb445a17321f2bea",
  "transfer_confidential_6_2.key":
    "d86a46274b6558c4bb13bce72a8f511f6b8f3c399125449ac67731e2bdcebfee",
  "transfer_confidential_6_4.key":
    "2b523a9575c6e3263898a9afa2f3a3ee24f9f74b27baa76e8f6676cf988a0861",
  "transfer_confidential_6_8.key":
    "90011b7811805a1fe784a99062088fb5a04c4169b9c1a59f30e8b40fee864dd7",
  "transfer_confidential_8_16.key":
    "6b03e0b636de7a4722a1829aa103919ed6ce67defe47c32d432eb09d73a4a188",
  "transfer_confidential_8_2.key":
    "c10606362880adb6747617f127aaffa08a2df314146d7f996f5c9de659edfb7b",
  "transfer_confidential_8_4.key":
    "d44b087de72260f6149e14098ba458ab44e565ca4c9e3ed575f3d4b5bd476b47",
  "transfer_confidential_8_8.key":
    "3fce685c5cfe6bc4ed1c11a74c4b9168c8d99e5b0cd2229a1217c3918c791a94",
  "transfer_eddsa_ring_12_2.key":
    "934a2824f7b653beef769864f258a3a87438f7afabded6ebce5aee90ef792527",
  "transfer_eddsa_ring_12_4.key":
    "4ad8e1d1aea650c4fa42205664a18668b4ebbda439b30bdf3b271a60c14a9db0",
  "transfer_eddsa_ring_12_8.key":
    "bcde0d39453e14babadcbee209d5c21315bec38daa9f61d0deab2637dea54837",
  "transfer_eddsa_ring_16_2.key":
    "9268655d5400cb4e223f6813b2b4d18a9bb820bab91b9d204c9d0e93e11708a3",
  "transfer_eddsa_ring_16_4.key":
    "803325d8276b93ccbf99395caa2cdf68abb1861933dd9811f98db69c6b17693c",
  "transfer_eddsa_ring_16_8.key":
    "a5f209577d2a18eb8aa3db8d939765307fd4b9799c0ff21c05d06afb75e51020",
  "transfer_eddsa_ring_1_16.key":
    "e3ee0a411cf667451d537732a51200b965915b827c43ce008958d4c870e538e2",
  "transfer_eddsa_ring_1_2.key": "9899f877c820279eaf3a2e1a32a5152d6aee7b46fd791973067774068da3de67",
  "transfer_eddsa_ring_1_4.key": "0bea48ab7511f45bc7cee78d66f170a600c652c49273672b60577b07edad59e7",
  "transfer_eddsa_ring_1_8.key": "8193b9c4d80bb7d3e1975eb63457878829c587d9e6dfcc2aea9dc9ed6296b372",
  "transfer_eddsa_ring_24_2.key":
    "66dc65efc1eb9262dbc42780c5bc880910ee59e3ec874b017bd2a49d21170a3b",
  "transfer_eddsa_ring_24_4.key":
    "7613ad8dc6b5133702209fe8c4dad552c3169fef463f9bc48aacadf0997a6182",
  "transfer_eddsa_ring_2_16.key":
    "700bc65783979490f3395c6790e2092ec45cc9cf250d1c5d4ea4b12179deee41",
  "transfer_eddsa_ring_2_2.key": "9830534e53026545388cc22650ce4265a805fb5938139d484f85ca2f6e91e5b9",
  "transfer_eddsa_ring_2_4.key": "735c48da4900f6ff98d0228d8a900d7b81f738780103e8686c03d07090150e80",
  "transfer_eddsa_ring_2_8.key": "f5ed26bed75eb2ad7922d7d7890001bb0a84af3efee94f254905d0adc1f1dcaa",
  "transfer_eddsa_ring_32_2.key":
    "7149f7ce4957a61e833153ad5366800759e9452399d271f6a02923e2c7c56d6e",
  "transfer_eddsa_ring_3_2.key": "d6d969e4858e267c5e7da2ea1137d41bcb9804a2a2248acb9a17ad4dd2d6079e",
  "transfer_eddsa_ring_3_4.key": "f3826eefdd2695cc890068dd074696bbc067c77b6cb56dc7e05d79d24fc6bb0f",
  "transfer_eddsa_ring_3_8.key": "26d1aa66749845b90af87d746ac8611f5e3f43f640283865299054b67b643b43",
  "transfer_eddsa_ring_40_2.key":
    "4f8f335bd5af058f5e0ef1d732f6396929a4869f74bab5b02c169e40d144c237",
  "transfer_eddsa_ring_48_2.key":
    "27dcbd7d163cdca576b3efe1d6c5f137d1a621b3304a1560124647000e3e52da",
  "transfer_eddsa_ring_49_2.key":
    "4ecfd7e262b16128271fe6be468700e055fd665d2b6cb93d6923a1329a535a65",
  "transfer_eddsa_ring_4_16.key":
    "a0adfd19e7beabba971d08fb18d22c3a1b0ac557a07a303ce1a62973b2fe29aa",
  "transfer_eddsa_ring_4_2.key": "eef06196c7570d1e8b7f0ca00e24f7a5ed43d1562aa8a97e8274f1cf82592a1b",
  "transfer_eddsa_ring_4_4.key": "1874e3b3ae4da2d976dab35117c563f039ea365c76c2bcbe1a6da3cedee0cbb0",
  "transfer_eddsa_ring_4_8.key": "cbf167a96902002e9e7d818aff062361cc60da25ca0c88f222c264405e51650d",
  "transfer_eddsa_ring_5_16.key":
    "75fe3d20f490d3a5cc801ca03eb5b4a32ca08398a3baf35b253371f4649ff2e2",
  "transfer_eddsa_ring_5_2.key": "3cc7fb3992117163f9d36b80813f43673d1e082844f9ecc15f567b403443b565",
  "transfer_eddsa_ring_5_4.key": "08b483779cb40afd71c82e8cb0cdf18e242ce3edee24bc944d4e5b5c3972f12d",
  "transfer_eddsa_ring_5_8.key": "71cbef3d7562de450a62ebc7adc6ee271bbca2d923dacf65192d6f0c57445f58",
  "transfer_eddsa_ring_6_2.key": "80296c67b2823790e9e64b6f766f743ef0e217bfa61fca2848ceffe5aa6b2fd4",
  "transfer_eddsa_ring_6_4.key": "88fcc5748b8149238920c34bf675412abee6fe3e7c4cec81964b692d6654ebe3",
  "transfer_eddsa_ring_6_8.key": "1624b5508647fdcbaa3a98b1b75c3443a8dde93027e3a320107940127e404f30",
  "transfer_eddsa_ring_8_16.key":
    "d1e27b07e32ff07fc665d06af314deb3a3108134798f9645228af008687b55c3",
  "transfer_eddsa_ring_8_2.key": "884b172638991cf4223c9b80404a8a82f90faa9b5a165562f16a142d1b318cc7",
  "transfer_eddsa_ring_8_4.key": "f8b9ca000988b80780091d3bf8b4dee00352b244e1d16c5c4095dad8df7015a4",
  "transfer_eddsa_ring_8_8.key": "75254597e1c9989f89b8222c451cbc606142a4e1337b4c23c503cfd9a921686a",
  "transfer_ring_12_2.key": "db36589a4702ca6ccee83d95604f829a11b903d48469f1c0e7d717391fc70b16",
  "transfer_ring_12_4.key": "f1310febfde6b69bd1c58a4871f617220bf00334f3ac6acd86c269e8b71e2398",
  "transfer_ring_12_8.key": "80613ecde7437780dd80babf172f910b49331d39f92b82d9bfeabdb51a14c1dc",
  "transfer_ring_16_2.key": "283aef239ef8dc746fc4f3ed40ef10bb2e1484d0be70b51ba9d7f4cbc2b50a9d",
  "transfer_ring_16_4.key": "b979c8efaeb6fd215aed6cf235906c3155da29fcfb30026130bb5dae7f3d3d90",
  "transfer_ring_16_8.key": "0518d797867daca5a8fd85ff15ba9c95cca984fd2f76f5d2d3f5e5165234633a",
  "transfer_ring_1_16.key": "a7f007a74436d5345fa5565b24f7282ba3a6c2969ad72b87cd63f830f6697299",
  "transfer_ring_1_2.key": "22437f8f22194cb10bf8938a4c66c634d75f6d2abf4c8ed0b1f4c4e3ba9a09fe",
  "transfer_ring_1_4.key": "208fe4afd0ab11c3f8696a09a0255719d1c2764726482c50e2a4ae854b35c8ea",
  "transfer_ring_1_8.key": "4f48768adf1be01550affcab6e8fc6b8eead4ac6813d00fce6eab64e0a7bc349",
  "transfer_ring_24_2.key": "efd24cbe90a21d4d47a6cec042702d4c6f0003727c356a779e18d7a0c613dcbd",
  "transfer_ring_24_4.key": "a5f06cad8cca72c89794eafe69e27002db6ce223aa36a96323bc94d8163fdc5f",
  "transfer_ring_2_16.key": "8bdc7bcbbfebb797b0c98982be63013bb7f29d5621b5851cb791b07ee634a9d4",
  "transfer_ring_2_2.key": "b5438902ead95e7dae05eb98d22592ba67698d99ff855e4d3b4f5bf7c4ead0a7",
  "transfer_ring_2_4.key": "4695b1c2e454fd05c6a50f1deb35bb93df2951caa948a8ce187379d149892b21",
  "transfer_ring_2_8.key": "ea482fb098ad920f46c53b5ee4f5e0b875534c06d5f34c4f607e3dc0a280f0de",
  "transfer_ring_32_2.key": "2f7b52c05883401cb819ee7eaf35013ee010fccd62647c490273f845716debf5",
  "transfer_ring_3_2.key": "ae1ff4941c1e9578a1122d73e94943eed06cb39bbc2c25a07658006c6055cd87",
  "transfer_ring_3_4.key": "f24e44410cb5d321676da222f7c29d3d2f018f89ad8f94fc0ae4a678930574dd",
  "transfer_ring_3_8.key": "2e0ffb3ee0d99d633e6d7dbb312e19e0948745b1e68d5f2d646ba5cbd526c3e3",
  "transfer_ring_40_2.key": "28e25224904195b7f711a0ccade36e0d98a539b828f139d3788d19b3abfb836c",
  "transfer_ring_48_2.key": "2783990a71d504de6573bc8a37bf1393d42effee14fbf757cfca8221e00c0821",
  "transfer_ring_49_2.key": "32aeddd4596cd58e808046cff47bad34309d6ce1cbb2952d1a037909a4c6d36b",
  "transfer_ring_4_16.key": "80d7ced5b7df7950839757d5bf974cf696021de5e99d46b39f3a3ad76f02060d",
  "transfer_ring_4_2.key": "f33700a456582cceab8a3f49fbfdaa53a953db368074731af792b0e3ca9b3784",
  "transfer_ring_4_4.key": "5819cd8a63b136b8029096b1ed76778ac44dc5af50e8840e6d1f00dff2422804",
  "transfer_ring_4_8.key": "59fcd01209369ba62d2b98b0a334022657fd7e7d2ed236fc235f6b681ca8506b",
  "transfer_ring_5_16.key": "c6c95531be74b4a65cb02ad9e559ec413ae85ff91d63760008f20367b7db056a",
  "transfer_ring_5_2.key": "b6145189b34ba27d4ea53b6a13675d523fcb719da0b56c275f16508923bc9ea1",
  "transfer_ring_5_4.key": "f72f50265ec06744feef22cb58f6319b70102f743afeada7f590d2b557623fe8",
  "transfer_ring_5_8.key": "75b2de289206aec025aee39056e565c6f7073d4c15cc6d5b2359ac7f62dc763f",
  "transfer_ring_6_2.key": "8ee39e2104ce3edc77108fff13dcc1a79378d5dee80c553848eb53c1689b3576",
  "transfer_ring_6_4.key": "fa4b9fff17626034f0e0620693e344dec868d167bb9441b7939eb3007c4fd9f8",
  "transfer_ring_6_8.key": "2d09542c90e9dbc23c73c62871e957401103ec0a8b68b803e2428e165496c886",
  "transfer_ring_8_16.key": "8a5651ca439c96dfa370c89fa982a5c03efc5c30f5225d43795627f7521ccb9f",
  "transfer_ring_8_2.key": "6e7cb77b482137dc96be34ad88827120822945bf9ae76601c43665885b68652f",
  "transfer_ring_8_4.key": "ab2bec775401189443e789a119070ad836594cc7aae40ae8c50226746f40d00e",
  "transfer_ring_8_8.key": "e5698569cea4b432b07c3441311f660ee9a4427444094e0ec7278837c56efc10",
  "transfer_ring_authority_2_2.key":
    "bfe4f5d6652bd66430db96ab906a44456fa9223fcf775ab7e77e8dadb419cc4a",
  "transfer_ring_authority_4_4.key":
    "cdf6888df14ca4311ca203a73bc46a1b123cfaa5280e1f42cd421faf4822fa2a",
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
  | {
      readonly circuit: "transfer-eddsa-ring";
      readonly nInputs: number;
      readonly nOutputs: number;
    }
  | { readonly circuit: "merge"; readonly nInputs: number }
  | { readonly circuit: "merge-ring"; readonly nInputs: number }
  | { readonly circuit: "custom-ring-merge-anonymous"; readonly nInputs: number }
  | {
      readonly circuit:
        | "custom-ring-policy-shaped"
        | "custom-ring-delegate-policy-shaped"
        | "custom-ring-policy-anonymous-shaped";
      readonly shape: Shape;
      readonly registrySubtree?: boolean;
    }
  | { readonly circuit: "custom-ring-base" }
  | { readonly circuit: "custom-ring-base-anonymous-wide" }
  | { readonly circuit: "custom-ring-base-confidential" }
  | { readonly circuit: "custom-ring-base-confidential-compact" }
  | { readonly circuit: "custom-ring-policy" }
  | { readonly circuit: "custom-ring-policy-2x3" }
  | { readonly circuit: "custom-ring-policy-2x3-anonymous" }
  | { readonly circuit: "custom-ring-delegate-policy-2x3" }
  | { readonly circuit: "custom-ring-compressed-policy" }
  | { readonly circuit: "custom-ring-delegate-policy" }
  | { readonly circuit: "custom-ring-deposit" }
  | { readonly circuit: "custom-ring-register-key" }
  | { readonly circuit: "custom-ring-update-members" };

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
    case "transfer-eddsa-ring":
      return `transfer_eddsa_ring_${request.nInputs}_${request.nOutputs}.key`;
    case "merge":
      return `merge_${request.nInputs}_1.key`;
    case "merge-ring":
      return `merge_ring_${request.nInputs}_1.key`;
    case "custom-ring-merge-anonymous":
      return `custom_ring_merge_anonymous_${request.nInputs}.key`;
    case "custom-ring-policy-shaped":
    case "custom-ring-delegate-policy-shaped":
    case "custom-ring-policy-anonymous-shaped":
      if (request.registrySubtree !== undefined && typeof request.registrySubtree !== "boolean")
        throw new InterfaceError("INTERFACE_INVALID_SHAPE");
      return `${shapedPolicyCircuit(request.shape, request.registrySubtree === true, request.circuit === "custom-ring-delegate-policy-shaped", request.circuit === "custom-ring-policy-anonymous-shaped").replaceAll("-", "_")}.key`;
    case "custom-ring-base":
    case "custom-ring-base-anonymous-wide":
    case "custom-ring-base-confidential":
    case "custom-ring-base-confidential-compact":
    case "custom-ring-policy":
    case "custom-ring-policy-2x3":
    case "custom-ring-policy-2x3-anonymous":
    case "custom-ring-delegate-policy-2x3":
    case "custom-ring-compressed-policy":
    case "custom-ring-delegate-policy":
    case "custom-ring-deposit":
    case "custom-ring-update-members":
    case "custom-ring-register-key":
      // The prover's `RingKeyFiles`: custom-ring-<x> is custom_ring_<x>.key.
      return `${request.circuit.replaceAll("-", "_")}.key`;
  }
}

/** The program selects a shaped policy key from the settlement capacities and registry proof mode. */
export function shapedPolicyCircuit(
  shape: Shape,
  subtree = false,
  delegate = false,
  anonymous = false,
): string {
  validateRingPolicyShape(shape.inputs, shape.outputs, shape);
  if (
    typeof subtree !== "boolean" ||
    typeof delegate !== "boolean" ||
    typeof anonymous !== "boolean" ||
    (delegate && anonymous)
  )
    throw new InterfaceError("INTERFACE_INVALID_SHAPE");
  if (
    (delegate &&
      ![
        [2, 2],
        [4, 4],
      ].some(([n, m]) => shape.inputs === n && shape.outputs === m)) ||
    (anonymous && !isAnonymousRingShape(shape))
  )
    throw new InterfaceError("INTERFACE_INVALID_SHAPE");
  const prefix = delegate ? "custom-ring-delegate-policy" : "custom-ring-policy";
  return `${prefix}-${shape.inputs}-${shape.outputs}${anonymous ? "-anonymous" : ""}${subtree ? "-subtree" : ""}`;
}
