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
  "batch_address-append_40_4999.key":
    "367fd7d2f534810ec684b7dbbadfd90dc65550d26989a2f2945d4719702001de",
  "custom_ring_base.key": "c4a6e3b31546317cf2448b9392dab5a3172caf5c90542230e70a7e17901d9f1f",
  "custom_ring_compressed_policy.key":
    "632fd1c05ce6e89e58aba2c96054323ed24a1d99d1c148fdeccd837cdb3ffe2f",
  "custom_ring_delegate_policy.key":
    "296e64861dc2565b85a3567bd1c9ebba2757eefd08bfd10160d9fe248b86ac76",
  "custom_ring_deposit.key": "3a385a554a49c25d1eea8e3f5368874347ccb7c457512b5f0fe42ec519c498ad",
  "custom_ring_policy.key": "1ebc92edebf9f7e6e4c53194a8035e21b6785bee0e8c4e2f7422b1e44d1a72a1",
  "custom_ring_register_key.key":
    "926bc02fe4d70f3d8163e190a572be82f8a0506e4ce734525fd3f92cf40c3357",
  "merge_24_1.key": "1e0720495e3051cf56f6466b933965e910c18437e8cca853c75af637f3908d48",
  "merge_52_1.key": "641f97f7129b5068847665f7911f570a75b4f89d70733aabe2aa979b22d66225",
  "merge_8_1.key": "6a4cca6281710632dfd440e6eefd1bbf36bbf911301ccf2b4d17b8c0df5cb5e0",
  "merge_ring_24_1.key": "125479fe72fbb91795905848ec44520edcdf340ab1aa172c959128d35ec92a2f",
  "merge_ring_52_1.key": "8814eb2e4610ec8a90e0a7122f759ecbe504453f28450845c8fd8d4f481e333c",
  "merge_ring_8_1.key": "3221d58369423771a3e37578de239b691d72ff2bfcf59e225b0bfe2ffb08072e",
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
  "transfer_p256_ring_12_2.key": "b314aa933a0a684202e0752e8ca7076736b7b15cbdee6fa774ae5702672d3064",
  "transfer_p256_ring_12_4.key": "8f0e1d2e339dc63263147f27016a79d0cf4ce3b45a57cfe378039223baa01322",
  "transfer_p256_ring_12_8.key": "4b20ca0d0bd865009147ed2e4f2e801e225e87d421fa5cef08b6011a4c545215",
  "transfer_p256_ring_16_2.key": "241cd6a99e32f2ec0a45355857a4b1551b0b8b3ea8ea4f60798296cb8f1ce66d",
  "transfer_p256_ring_16_4.key": "4b7ecf61249df252f7821035581537a803834f3e780032ed50c70fd743ef8b02",
  "transfer_p256_ring_16_8.key": "57cc6ee6870e7e27935bf1e471f8ad91b882471d0a7384ee616fbd62a1dc7f4e",
  "transfer_p256_ring_1_16.key": "ddc9e658a79c3cef6f33cbaa40e09cdc037200c321f7e1f407f3040f8e4d7e92",
  "transfer_p256_ring_1_2.key": "24cba7072e991844312bdd4a5e055887bcc31481e62f6134315ad7b7146af2ba",
  "transfer_p256_ring_1_4.key": "80a5b13672fcc3df29139bb6ed8631e0f6484d88cf3f20d93a77f764f72295e5",
  "transfer_p256_ring_1_8.key": "0fccda4881928be15f4d23a41c0641f2f9903f2315881b26ddc91aa9898daf9d",
  "transfer_p256_ring_24_2.key": "453d0e4caa88cb9ca9012b7d6dbed804c19ebf7aff7973acbda388cfd82aa39f",
  "transfer_p256_ring_24_4.key": "3704ebe8eb5511120e1656117a6d0c0daa6fdf5130c25fe139fe235f3f7b7d18",
  "transfer_p256_ring_2_16.key": "784e51421fb1382589357acbe5e6f8c423a64c47312905f81daca3aab7b3cb5b",
  "transfer_p256_ring_2_2.key": "4350b9db2a6da7d5d81c976e38236666b7331ccf5c7838dc5dd2f7e60e878218",
  "transfer_p256_ring_2_4.key": "687516b8cd5b7bd2c1a88fe2c0c46eecb3ce81f847cb67dc1ccde16b94d300f9",
  "transfer_p256_ring_2_8.key": "dfc34467901e3760660c2d380059b573fdb7d81940e7794c58d4b1230db13eca",
  "transfer_p256_ring_32_2.key": "4884694811fe3cceb7a17c0e6972ede8c9b6611f353c16364f365168a79c8d40",
  "transfer_p256_ring_3_2.key": "418d108d497e14602c0d8fad1bcf573e360bbea8cb22d6c20db12aeae7e165d8",
  "transfer_p256_ring_3_4.key": "471c588f44637e11ec4a386c82954db91565a3a5aa5209f0d6392d4642dca88e",
  "transfer_p256_ring_3_8.key": "ef76d381bb0ec85f5e841d60a3d8696dfeb0827f271fb74e7ef02f296256167f",
  "transfer_p256_ring_40_2.key": "88ce76771afb8cd817a9108f4cc4ab1b62d25d7206d5b2c1d15d508caf150b89",
  "transfer_p256_ring_48_2.key": "56c222360e4923e39ee6c16a6ed8c46032cc8bc03fd549cff8a0ec8f419f9302",
  "transfer_p256_ring_49_2.key": "bc83993c4664fd04ad48bc14e29ea9220cea492235ee7082717fed5ce19a6c4b",
  "transfer_p256_ring_4_16.key": "7ceae62a73a55909f9ae14077ca0bc07318c017ff0f5bcaa64eee8afc9927116",
  "transfer_p256_ring_4_2.key": "8f0a38dde77d7534d0d9510427a42ffdd097397cde91f20d8b339c7a36702116",
  "transfer_p256_ring_4_4.key": "5965975a843c110416f1605a0a79ffb75610309703cae97c500de675242beb20",
  "transfer_p256_ring_4_8.key": "1737489613f744dfed11386c51548f02512ee50df0e5b5c07a18eececc40338f",
  "transfer_p256_ring_5_16.key": "cd397193b77f6836712d1aa86c1a564353af85b50f5e2a0086633efbe7669730",
  "transfer_p256_ring_5_2.key": "523d8a647983f71ad12f0343ac6eff0e2cf9cc1b2ee3d207cd5427d3cfd19230",
  "transfer_p256_ring_5_4.key": "4ea8dff8066d344683c3ae77e0702b182920181819018cffba25dbec7c4bdfb1",
  "transfer_p256_ring_5_8.key": "e35f57e7553dae08dd04c9b513ccf3477bc5785432415b88f8a387504bb6ac3e",
  "transfer_p256_ring_6_2.key": "6c05ca17953fe1ad79072a87a4e24d10b77b1220fee499a76561fad7fc3b51d9",
  "transfer_p256_ring_6_4.key": "fccdc00d3518fe3333b7b54076bb20cc29fecb54ae5be6a1befba2b7d715cc6b",
  "transfer_p256_ring_6_8.key": "fe15a8b1aad603a92070f063943d0985c649b69a47ef7a8cdb42f5607dc71177",
  "transfer_p256_ring_8_16.key": "bef98de25380ce34361dd8ed87d4258f78a08543e7aba3a69fc4f681b57e26d1",
  "transfer_p256_ring_8_2.key": "ec1d67165d27ab5235a51983414af42f7a881c59421af2971bd0c195a057d793",
  "transfer_p256_ring_8_4.key": "57f0c7c74eaa111f2e6adcaace4a6bf624c187852ef7c87d44b5aef6176ce793",
  "transfer_p256_ring_8_8.key": "f806241b0019e67396c6df0b9a48d13790e7a3fa5c92933fc6b9333b50ffee06",
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
