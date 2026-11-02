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
  "merge_24_1.key": "be917f00eb2f0436e8083ff5b32ffab5f4d6d360c189e84e6022bdad4658167d",
  "merge_52_1.key": "2b0a595827d9e4a0c9f643e8b197e964a772c69ae50ba3e02109f0b372ecbebd",
  "merge_8_1.key": "cb59ca915a79b1abf49b9f9fa997835e7da185c8b6293f5a4a977cf603a4d380",
  "merge_ring_24_1.key": "bfe4cd6e25924ed83bb42ad79131fe63fa893f8c4b9585198f0920bc96f99576",
  "merge_ring_52_1.key": "bd2dfceea6f081551a52c21f77cad14fa0656f1a68551a9352d6e607695d51c9",
  "merge_ring_8_1.key": "635f9f6d7d74447f2313264c691b818bc6a5611aedb0dcca3abd24405919d4a4",
  "transfer_confidential_12_2.key":
    "663d0de50bc0e6947492cad785ea5d34db51bfddeb59a5ed22d4722cf16a9190",
  "transfer_confidential_12_4.key":
    "cecc67b4395dd1476d6a1c9d59d42c43b3f22ddb93f329892d4e8f8ebcebc7ed",
  "transfer_confidential_12_8.key":
    "6637d73f12bb2255019a487910e9804bab103b4324e108bc520dd6c0b6ba09fc",
  "transfer_confidential_16_2.key":
    "11951e7ef3f79f163a2c8aa9555651d9fba23424150da4701b7cc56f5b45d83f",
  "transfer_confidential_16_4.key":
    "841988d4b2fc5f7366b7b823ec8abb58bf0b051b30319040935a5597f1681bce",
  "transfer_confidential_16_8.key":
    "f8420af31bfb34ea029c5646769065ffc261c499b517f868542af0e0577c2676",
  "transfer_confidential_1_16.key":
    "17c0f2a1d4494a3db56b332b2adc6a989a798c59f4683b649c4dac412bc82e26",
  "transfer_confidential_1_2.key":
    "c0b5c1a1081136911a6ad5496fb989ed26d85b09e983a4d5048cff96e0833d85",
  "transfer_confidential_1_4.key":
    "4dea477eb3accc708975c4f258a9a58b8d5e21d2cc0dfa28ad47ba46b0fe7bff",
  "transfer_confidential_1_8.key":
    "8bbdb200e1d6147ad03ef55e13e8271eca2973bf2ae59fe2f10f9e21b1def490",
  "transfer_confidential_24_2.key":
    "07d52d5f44e69013a47da95507c99dc2c4d0d1a3b16cd5d988bdacce069f6332",
  "transfer_confidential_24_4.key":
    "694d6414fcc0392512eb7e071a3b28f30c8bb82adcb56962ccbf79807dc22c83",
  "transfer_confidential_2_16.key":
    "cebe6bb76188f3989dc011f7839f04867a8e8d448b6faa2a15a5f5f6e6a23901",
  "transfer_confidential_2_2.key":
    "51380b1264737ebd4d31f40ebf6874db039078ce998d4fa187c049ace99798bb",
  "transfer_confidential_2_4.key":
    "835d0d4c5ff4d4be96902faa4cb2fe2ee2e413afe678729e853351e6c31c156b",
  "transfer_confidential_2_8.key":
    "0b38f1f375024c6109c6b9027da8778c1140fc499ae45f52d5997f3d7e3f7529",
  "transfer_confidential_32_2.key":
    "7cb3a9c9662eee23effcfa495e0346fc30f383968ec1f3b7f330926f753dcd44",
  "transfer_confidential_3_2.key":
    "72379691c3b515ff939a9e57fa52204489bdae376642a4e675c0b8830118b097",
  "transfer_confidential_3_4.key":
    "e6ed1362e59289b59bc11b93c85df9ebfbe7dfc8ba5f99a254273320ca07e7c9",
  "transfer_confidential_3_8.key":
    "c41930ae5c21f8c582eb6c0c597e13b3bb249efcb85a756e4289cbb5c70e5a0b",
  "transfer_confidential_40_2.key":
    "1c307ca4ff52000e4e85f06e93437de826a2796b77233d5728d84216fdf6b2d4",
  "transfer_confidential_48_2.key":
    "f429ba983f78510004cdbba9eeb8d26c494d1f1e13a943408ff6badf78025218",
  "transfer_confidential_49_2.key":
    "3534fc22d19956fe1f1f897f316cf37310350a1678e58dc84a2cfce6989f449c",
  "transfer_confidential_4_16.key":
    "8fbd730435bc5a5467b2184254f7080a7f75e135c5bcc5c633d76b0744e75bb4",
  "transfer_confidential_4_2.key":
    "d9298a68c83261700a4d3eab6a1922aab19e625a843d9df50628c3ec86e43aee",
  "transfer_confidential_4_4.key":
    "99e9a089100e820d8b539e45e24e48d61b113a43ea0e86ecbe979167b92d6a2b",
  "transfer_confidential_4_8.key":
    "900598583206f654dd29cbe26d973cd258775b9c9c7413d061fa0616c1dbb3e3",
  "transfer_confidential_5_16.key":
    "086961ca937381318413976c4e9b508541d2ab2bc758e1b28d9d9a99d66f27a4",
  "transfer_confidential_5_2.key":
    "c5dfa2067fec93936aef24b748378516c40ef0a4f6987118e36285893864d45a",
  "transfer_confidential_5_4.key":
    "9cb1497158d00e87dec62de29886f5d91fd0359ce15e77a9b3e0e26008e724cb",
  "transfer_confidential_5_8.key":
    "54e80daa5cfda22be5f1e82541fa0b798c83ccd34591e3b8b90104c8cb372577",
  "transfer_confidential_6_2.key":
    "226387d770058209d40029988d6f3ab154c42a0802ee066284db4c8db886ca40",
  "transfer_confidential_6_4.key":
    "c5ada6e9644e4853fc91a56cef7318fec9026c08475b8794a0e8026c80310171",
  "transfer_confidential_6_8.key":
    "801717d5356cc171cb2b560562c292b21ccdef00c8e7deda6e827235d4cd8a6d",
  "transfer_confidential_8_16.key":
    "88a98eee4be2853492e70dbbfb17a1e80bdedbe4d33b5cea9fe9ece97c945d19",
  "transfer_confidential_8_2.key":
    "b64dcce8e5a55ae0f120bd32118f5bfdaf88f48bb3a3860e9cae9bac1611135e",
  "transfer_confidential_8_4.key":
    "74638c0bdf583defcf094fb7188e1fec98bedc2451680a850495e8015bb4384b",
  "transfer_confidential_8_8.key":
    "501577f4062fe597a80ed22831c5b0e65e0a7a524283ce5e2f98c5868f7e8296",
  "transfer_confidential_eddsa_16_16.key":
    "75ff87cdc1450e1aa9ff50c18c9ff6d59fb0f6c84722ef637c7ed55007e39995",
  "transfer_confidential_eddsa_16_8.key":
    "ab4a7d6fe3598ca5f13f840d9a9be505151e94e167ca6d271255b8a4e0f84ff6",
  "transfer_confidential_eddsa_24_16.key":
    "6229ae94ed13b8016cc78e66c1b328e102620cb76401aa125e68ec71994faebe",
  "transfer_confidential_eddsa_24_8.key":
    "e6e3bb46a2f16c836f5c447ef2f3cadeeb45c383613d2afbba0a926511b3fd86",
  "transfer_confidential_eddsa_2_16.key":
    "8071311fda67e2b53c9e59cb222bc9c31750f64871f3f4e5414cb827d872867c",
  "transfer_confidential_eddsa_2_8.key":
    "acf50178fb2fda05f2d1624635ae2083b34466b42b5f0e0e33628226cf678da9",
  "transfer_confidential_eddsa_48_16.key":
    "68d52d5a40d213f4cfdc4597730e227cad873f52323ecbb8870a0e228df0f638",
  "transfer_confidential_eddsa_48_8.key":
    "ab5781a1f20bed52f6c8a0e6ac97977ecb8d0f2cb4b4a66dca117cc0aaac00a3",
  "transfer_confidential_eddsa_4_16.key":
    "3d8c513d8c3507c0fdf6d21ea7733bc225eddc5100e36022ddedb2fa02eb380c",
  "transfer_confidential_eddsa_4_8.key":
    "99a3f72c361fb9a13d24f39448c00c40a816ee97ccde0fdb519d5b6c0255e0bf",
  "transfer_confidential_eddsa_8_16.key":
    "21720e0fd44203409bc34b3a55eff6c2228b8836b927fabda0a8e914ac1df7a2",
  "transfer_confidential_eddsa_8_8.key":
    "f1bb487e8997bce94360bbb4fc8fee0ebe3e7489547c03afea7556fdcdfdca1a",
  "transfer_eddsa_ring_12_2.key":
    "5e4f03f07f5961b7a6fd60275010ddd854cfc8fc470138ba0aa7d7817eda6187",
  "transfer_eddsa_ring_12_4.key":
    "50770c37c5b2cd2deebe4118d5515f998a5d294e67a42451aa50e6d5b82e1722",
  "transfer_eddsa_ring_12_8.key":
    "41979f55f105ee328c97a74408f38b511fcb815453452a58a2d9877339366208",
  "transfer_eddsa_ring_16_2.key":
    "190bd9f38f5c6e32cdc0ef7ffbd5c6546c385e0b872b57a268a78408c8dfc974",
  "transfer_eddsa_ring_16_4.key":
    "87a8a264735e7e0542a25802084576c4cabd177ffe78a7d9cce34a7c4e8804bd",
  "transfer_eddsa_ring_16_8.key":
    "03083fb054761fa3a21b9e0b0a65f3656c42c9169cc8a5fd088695bac60fa61f",
  "transfer_eddsa_ring_1_16.key":
    "1a86d4d2f54a82b6ae03239c27c0ce0f276693e27b03a0dba301c41c1f6f3fc5",
  "transfer_eddsa_ring_1_2.key": "6cd9fece05b23e9d1d7d43b552b1e4c26b1c9d48e14cac7629fd32eff39f9712",
  "transfer_eddsa_ring_1_4.key": "057570efd4dc599b0c8a9771f690c3b8214a2514ef84c8aa3c9c300822518dc8",
  "transfer_eddsa_ring_1_8.key": "b727498981348703bc4ad30678765664e2bc787f68b144f8281a1eb3d01a206a",
  "transfer_eddsa_ring_24_2.key":
    "6d359b837d09f3f4861b676c779494f361b71fccb0c3b0850b106192e80dc66b",
  "transfer_eddsa_ring_24_4.key":
    "3ed1932c6b8b16a31f00d89679c6817f53553fb6aefa609ea0cd45c171159eff",
  "transfer_eddsa_ring_2_16.key":
    "40ce8ad589734d403279817db6fc83a6d5a15d43edb5e8c7b098bea196d1b568",
  "transfer_eddsa_ring_2_2.key": "7a0f9b1b41e750db41a170c3faef634a17ff3a7fb3da1dacc76eeee044946b16",
  "transfer_eddsa_ring_2_4.key": "31d2d55e2bf1066cd1ff386f65f69f35c4d0ac662eb4df9e77ce054f7a8095bb",
  "transfer_eddsa_ring_2_8.key": "f804b42ab9c829bbd9f71d9e6a1a7f9c337e194fa864868d8e3d593d7c98e1d8",
  "transfer_eddsa_ring_32_2.key":
    "49e7fa6f477ea6dbf391c1ba85d22fb6d0e3ce134f0fc6745d130e214a90477c",
  "transfer_eddsa_ring_3_2.key": "fb180b988cfc84a638bc790c176e76fe1522515454a3b770c143b070d1169fe4",
  "transfer_eddsa_ring_3_4.key": "e1e688ab16b3d883efef96a79b43a16e5664a5b4e04e510229d6884f0f6cbabb",
  "transfer_eddsa_ring_3_8.key": "f39eb2cb24723c091d75172e80f3bd705d36d779b7ebffcbdf780a096e53410c",
  "transfer_eddsa_ring_40_2.key":
    "15072b7bb5fc68b2131708b25f1b47d57b31ea06b99537d3f95e0a40132598cd",
  "transfer_eddsa_ring_48_2.key":
    "3c35acc79bd6afcbcae25f46921dbf109743e2d66b7cef88844a5d6c05531ce4",
  "transfer_eddsa_ring_49_2.key":
    "37eced6395c26b9d555153e2a3e80bac4f60168b6db914810334cd75fb2b33a7",
  "transfer_eddsa_ring_4_16.key":
    "649315d70308257048f59f09a8e8b255b5cccb2652852d9a8a77ecc43a65b465",
  "transfer_eddsa_ring_4_2.key": "dc1f840b2618492e1d316d9d5dbd96ad4fc733a6da325b057d152cf011001be0",
  "transfer_eddsa_ring_4_4.key": "af945c5aacd006a60a1756bac6fad7200d6a2527b75840f5a25263cbb37e75e9",
  "transfer_eddsa_ring_4_8.key": "9ba801efd06164a99d0292a0b04b11d01051446cf5380bfb22150e8b7b358776",
  "transfer_eddsa_ring_5_16.key":
    "c7c10302e17dd7a2bd42e44c42db3e59ae76f221cf7b7588669d7679969de59e",
  "transfer_eddsa_ring_5_2.key": "8e171a1977957b6a24356007c27e17ad509661999bad75d045b9b7b3e4fdcb4d",
  "transfer_eddsa_ring_5_4.key": "ed859a28870d5ae9fe540934116751c987bde76d59ffcbc1e03d1d9bf2576ed6",
  "transfer_eddsa_ring_5_8.key": "f64e16a851dc5f31d62d9d86c930498834f2665b6a81a816451292c9bcbbd26e",
  "transfer_eddsa_ring_6_2.key": "05090cb02f7a72c943949c9d1bbefc6f378c88fe4a44db13a1e1b708b2baceb5",
  "transfer_eddsa_ring_6_4.key": "137b2a572988d970c614a90db906c4a7c03f11727f091350d60cb945ed971ef4",
  "transfer_eddsa_ring_6_8.key": "a489466866831fc61eb89383d66ae84c8fb53c3bd4503794bf6d697e76933743",
  "transfer_eddsa_ring_8_16.key":
    "253197ba2e5863bddad5db6069d01b67bef09089a329e10871eb0eed04336ffd",
  "transfer_eddsa_ring_8_2.key": "4018a6c1ec6c20906951fb29213650df64dd282a61022fe6bf8119b01729d022",
  "transfer_eddsa_ring_8_4.key": "5873b9f2b33be773d81e3f19ec8730c15658419c6eecd70d6c4fd454be0625f3",
  "transfer_eddsa_ring_8_8.key": "a9eb86386ad52c1995d0dae7118bce9ad13c882b3f7548f667c708aa3cfe44a2",
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
