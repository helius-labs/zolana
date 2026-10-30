import { InterfaceError } from "./errors.js";

/**
 * The sha256 of every proving key the program's verifying keys were
 * generated from, by key file name as `proving-keys.lock` and the prover's
 * `GET /proving-keys` name them. Mirrors the `PROVING_KEY_SHA256S` tables of
 * the Rust interface and nullifier-tree crates;
 * `test/proving-keys.test.ts` pins it to
 * `prover/server/prover/provingkeys/proving-keys.lock`. A proving-key
 * rotation updates this table in the same change.
 */
export const PROVING_KEY_SHA256S: Readonly<Record<string, string>> = Object.freeze({
  "batch_address-append_40_10.key":
    "589c90ea00bc771e7b61c28c20290c4dfaa9a33790d7231261d7bbe621459843",
  "batch_address-append_40_4999.key":
    "367fd7d2f534810ec684b7dbbadfd90dc65550d26989a2f2945d4719702001de",
  "merge_24_1.key": "459cefcc03b48ecf9629dd494e9b6441ffd05833123b47473338a7e0dc8fa63d",
  "merge_52_1.key": "5c1bc43dc2d84753c40c3c30e4b319d441efdab80440bba16de1e1bbf613fbd4",
  "merge_8_1.key": "babf71dc8da512f9a35c5d9b6f39297c4727b14ab70c9e1e5f5e5822838765c8",
  "merge_ring_24_1.key": "bfe4cd6e25924ed83bb42ad79131fe63fa893f8c4b9585198f0920bc96f99576",
  "merge_ring_52_1.key": "bd2dfceea6f081551a52c21f77cad14fa0656f1a68551a9352d6e607695d51c9",
  "merge_ring_8_1.key": "635f9f6d7d74447f2313264c691b818bc6a5611aedb0dcca3abd24405919d4a4",
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
  "transfer_confidential_eddsa_16_16.key":
    "ae94b617ae3f7ed4c2ba2df7cc4bae3afeda89090f025b2b153dc127e3028e37",
  "transfer_confidential_eddsa_16_8.key":
    "9d82d4be2d0741e53137c73375d8ccf4e1dda51ca33965d363a6cc74ccb40dae",
  "transfer_confidential_eddsa_24_16.key":
    "ed96171728783a85db28323e44fb49e8cd4a72bfa82ff31ab7ae77f5680b52c5",
  "transfer_confidential_eddsa_24_8.key":
    "a4187aa6b90013d01c00e90853ceaca0e1e5a6a5facb339ba216592128f14445",
  "transfer_confidential_eddsa_2_16.key":
    "bd5ee7839c0c3128cbb5489e6acfbfab27d7382bf6c34e9fc49747efd5461566",
  "transfer_confidential_eddsa_2_8.key":
    "67e37b413b0eeb97de0170519a9fe269d39792e8ed3d91c0c9336ac12f06684a",
  "transfer_confidential_eddsa_48_16.key":
    "72b7c5ca256b05ba43e4ecaed7aa3e5d1fbe9ee306bd436a8388a4f713b75db8",
  "transfer_confidential_eddsa_48_8.key":
    "ef92717877e915bc9042d64b5f295a5accb8f5efe1f5512f9b00cc54f90a0d2f",
  "transfer_confidential_eddsa_4_16.key":
    "db6fafd3b53c4d16600b35181d2e0c121e3cb6c992b323997ec52c99ebf61734",
  "transfer_confidential_eddsa_4_8.key":
    "506f40765a75aa56ac9332948fef62dc6d2f7958b9601e964ba6a2e6124fb4df",
  "transfer_confidential_eddsa_8_16.key":
    "e62032b8a510e12a8923fe1f2791985693ab3b5ed6e14a4e9edc46c9f79c70ed",
  "transfer_confidential_eddsa_8_8.key":
    "111004c953760420e3c4570234e88f2db3561cc36f773ec781ec689ff8cbf104",
  "transfer_eddsa_ring_12_2.key":
    "98939bf3992efb290d185d8543de5af307817cd34eb42abf0754261a02ea027b",
  "transfer_eddsa_ring_12_4.key":
    "167a297dddee95e09d05e13edbfe2a0972ce2c523b7578691cd8c8e148a4d051",
  "transfer_eddsa_ring_12_8.key":
    "91a6225b604d8699d51b7a9ea11b4a31bb3f5db18d7cbd34da79a8ae3519e96c",
  "transfer_eddsa_ring_16_2.key":
    "2514d35df5097a0e6c3a849142d60b586a20a03c200f0bd582949ded57c2473b",
  "transfer_eddsa_ring_16_4.key":
    "c3ed2a76de35ba5a7d604084957f768727709f77fe9b61790667b439e1477e7c",
  "transfer_eddsa_ring_16_8.key":
    "3bda4a117806074acaf874f32fda2c6fc48a7fa61e6e11411ff4476ea9b01716",
  "transfer_eddsa_ring_1_16.key":
    "5cdc91659e43cd548f0b785865cfdf5f07f815fb4cb6a23aadd6d37e62d5cbfd",
  "transfer_eddsa_ring_1_2.key": "be870f661af275e750811807628d07117a6ff353d6dd69695e16940bbea4f016",
  "transfer_eddsa_ring_1_4.key": "5ba5de959992a26aeb2f27fcbf408c9f0f6c9d4a2da0ba52e7dee89f2a9d68e8",
  "transfer_eddsa_ring_1_8.key": "8d318093c60c7fbd435c72ab70c0b45fcc3d2caa11acfaa60a3d9a655ef2565a",
  "transfer_eddsa_ring_24_2.key":
    "f0c906a434890eb18e180b64faf259f1e79578fe170d6b4612caf8e1dfcf3b0e",
  "transfer_eddsa_ring_24_4.key":
    "75cd931f48223e6379f46e1b2d96599dda6e26806d475c03f5b9f86cb21a369b",
  "transfer_eddsa_ring_2_16.key":
    "4dc0128126c0f539fb8ae9dc0a5f174bb0590e1accf7d0032939cdb32201c47b",
  "transfer_eddsa_ring_2_2.key": "e8fcba9c9b940ab64d79fe78a79c356967eb54f5f556f79cdbb7ac3edf608a66",
  "transfer_eddsa_ring_2_4.key": "bd312c959bd94cc81b12bea459d567d9f87d294891a123d008b00b3e8d162cf5",
  "transfer_eddsa_ring_2_8.key": "de38a4c5ac9039e0c331b0fb7516572e163060d1f630482f48d4e59878ecf3af",
  "transfer_eddsa_ring_32_2.key":
    "ce6a671e9a40dd2b6fad7a18f01bfb17f3ec74fdde0beb0eb9ed454f3a0bdf16",
  "transfer_eddsa_ring_3_2.key": "cfed9de052edb3b6a657d19a7e95b5e7bd01a85717df6faa91bb4cd8042af2d5",
  "transfer_eddsa_ring_3_4.key": "133f76941c323402161faa270dce2b32fdc4f567d70d5ac77e7111b93b1c681f",
  "transfer_eddsa_ring_3_8.key": "ed96d880376644e0fecbffc42d42b2e08be246f12a36f15cf8db651cb6097a0e",
  "transfer_eddsa_ring_40_2.key":
    "497d71091ead675cd4fab0d6823eaeb937b14662a904303d8c1af6eb5a7224c9",
  "transfer_eddsa_ring_48_2.key":
    "e4e574eae6d4ba3cf0a4e095e86957dbf30acfe43515d5917525d87e1d1af712",
  "transfer_eddsa_ring_49_2.key":
    "c14ad46b86926c78e01769e77e68153eb34651064fc1d1b6fcccf5de7ecf8dc3",
  "transfer_eddsa_ring_4_16.key":
    "61e844fef8496e2f1ffcaa6e8660ccc1cbdec839ec63353f3270a65eba9c7119",
  "transfer_eddsa_ring_4_2.key": "3e22a5509675ad6f3c7ebe75fccfe8e0b96b7b135c8cbb3eacb8743e3f9356f8",
  "transfer_eddsa_ring_4_4.key": "706ece593e1ce3b5b9577901cfb601b3a41e464183c2f21869876a3de01a51e3",
  "transfer_eddsa_ring_4_8.key": "c970f2729bdc738d90bdb2b7f11cb6579f567cfb0c672059482c6576ca2f48de",
  "transfer_eddsa_ring_5_16.key":
    "ba89450399a7d04424137554b2d712ccfdc8e406458246cc1a1579b8f266151b",
  "transfer_eddsa_ring_5_2.key": "2b89c5e8a9b1a852d3af822ef9deb5e904a544e84965f720db621719a92b1cf9",
  "transfer_eddsa_ring_5_4.key": "8d9bb62b298ec1d8647c4bc1449ffa681637a2c21463c29e55bed6b1d7b10ec6",
  "transfer_eddsa_ring_5_8.key": "000a008ce348607a9ac70c0416fe2ed940aedf341e3134596a4ae9769cb854ca",
  "transfer_eddsa_ring_6_2.key": "c608eb24e4efdeaf03a7af084dcd31c2e96d41c90cd3b1051e638372f8ef94b8",
  "transfer_eddsa_ring_6_4.key": "693080e5b12fb43f1c9403ab82e19cf316a27df2b36a0bce3302099da71c4dc6",
  "transfer_eddsa_ring_6_8.key": "5a1dde5c39dffd645c38ed6fba95b35cd9b186e84e86e089f449b1d61053cf2c",
  "transfer_eddsa_ring_8_16.key":
    "19e31a557594d02a94f7be2d6da7b9546538c098900878e71cbdda46046f33a2",
  "transfer_eddsa_ring_8_2.key": "645014509a5bbeeeaa5f75150f2ed07ce00ef0812b93dc72398ff1258c56ceaa",
  "transfer_eddsa_ring_8_4.key": "98b8c1d11c631139dc7b17368a0fa98b80c0e969fd84eb88e34d1885b4ef00ae",
  "transfer_eddsa_ring_8_8.key": "0551d391fd9190eadc8cfc7b05de7549223950d7677a4e56f362804bb163bffc",
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
      readonly circuit: "transfer-confidential-eddsa";
      readonly nInputs: number;
      readonly nOutputs: number;
    }
  | {
      readonly circuit: "transfer-eddsa-ring";
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
  | { readonly circuit: "merge-ring"; readonly nInputs: number };

/** The proving key a proof must come from. */
export type ExpectedProvingKey = Readonly<{ name: string; sha256: string }>;

/**
 * The key file the prover proves `request` with and the sha256 its verifying
 * key pins, mirroring the prover's `determineTransferKeyPath` and
 * `mergeKeyPath`. A shape without a committed verifying key throws
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
    case "transfer-confidential-eddsa":
      return `transfer_confidential_eddsa_${request.nInputs}_${request.nOutputs}.key`;
    case "transfer-eddsa-ring":
      return `transfer_eddsa_ring_${request.nInputs}_${request.nOutputs}.key`;
    case "transfer-ring":
      return `transfer_ring_${request.nInputs}_${request.nOutputs}.key`;
    case "transfer-ring-authority":
      return `transfer_ring_authority_${request.nInputs}_${request.nOutputs}.key`;
    case "merge":
      return `merge_${request.nInputs}_1.key`;
    case "merge-ring":
      return `merge_ring_${request.nInputs}_1.key`;
  }
}
