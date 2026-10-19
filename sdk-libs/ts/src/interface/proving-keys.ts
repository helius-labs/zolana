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
  "custom_ring_base.key": "b0048fbd5f26aa196f451d592c5a79ac3cc481e5beb91f039388def9601b2b83",
  "custom_ring_compressed_policy.key":
    "ea1b8477ddd1a526263fa1cadec42c502b9b5b0e3f8ca1d07e7d4fc9581d07a9",
  "custom_ring_delegate_policy.key":
    "8bddafa9c3ae331e19ab869e9ea696cec43372e07c74413e1a5b137bd0a58eab",
  "custom_ring_deposit.key": "cedd55fb3a3dab3e38d16490eb0ec3c69ad15b422e6959249be4bd00f5521407",
  "custom_ring_policy.key": "361d0f5d494767359d0ef4ad744377155af3ef9aa914319258a05263e365a3e6",
  "custom_ring_register_key.key":
    "57fef09e313c3ed6389e49d7f5cf913fa81e18cb6d93dad96662920427c19c49",
  "merge_24_1.key": "a0dfaa1e73d2d9e1159d2ebab82baa6d0602482d75f24dcbff596322dc389c88",
  "merge_54_1.key": "951ec83dc53d112a46a1eb9cd308e6abd933291eb3109647a479e2321fce7423",
  "merge_8_1.key": "f59571876452541eaf20cfc583a082b9b6cc788bf85719bd337398b2d962ad23",
  "merge_ring_24_1.key": "7c06a947e2fbd84264d3b2e0afedb44922ad871a64289c9fbcada04d91fce588",
  "merge_ring_54_1.key": "554e5ffdfb7abb903bfc06610c7ef470c89340cca2bd4ab8eb104680dd8855ea",
  "merge_ring_8_1.key": "9a191ebe9f60c8006b03f9c45850b252246d1767e100f4510b0d271767d41ad4",
  "transfer_confidential_12_2.key":
    "3415363ec3ae33b730c7445aeb7850aa1bc044443e6ef8a7731e2c56fd1df6e7",
  "transfer_confidential_12_4.key":
    "36519896a5e5b4d1ef008d6883548944027eb21ea3e6bc72ba00fde9ea9efa4a",
  "transfer_confidential_12_8.key":
    "131973e42165b1222ecfd2692796cfb035d5aa4a08ce7bf5e545795283ee344d",
  "transfer_confidential_16_2.key":
    "27370f44f8b9c0c05f9d2c6738ab5294582fd40c869114baf0d7fb15e6d08e2a",
  "transfer_confidential_16_4.key":
    "7cdef518b59307d578c2eecb71e811945ee56b1906283e8c70fe0924343dfb2a",
  "transfer_confidential_16_8.key":
    "d8052824a163d41ddf8540bc72dbfe94b5c52be21b6a0f3039b2f01f7380641f",
  "transfer_confidential_1_16.key":
    "aecae052aeb709ef4656d6da110bd1403d21bc5891e60691ee9cbc0ebb46dcb9",
  "transfer_confidential_1_2.key":
    "7ef987966b0dfba5d86eab7c67068be00dbe581d823d45cdbbf6d338bfacb640",
  "transfer_confidential_1_4.key":
    "94bddced9e46a0e0c4fbf6bc59c6d083e1d577a60bf4d8520129f41505f4f1dd",
  "transfer_confidential_1_8.key":
    "3471ab2908cbe15b757164db5bb7c7f82a89036c557fc26fe66a7148a4338f58",
  "transfer_confidential_24_2.key":
    "7b98beac6e0f89d568a30f569c690267bc37fcb8472ad88c292b89433c2f91d9",
  "transfer_confidential_24_4.key":
    "4e3c664a197a7b2cc5616b7c01dc463e92fa666f2990ee42ceb2d7ae81f1ece4",
  "transfer_confidential_2_16.key":
    "27ef8be4d400bb9c724f79a4928f7f6ff4dc95a970f17c365b38430267986bfd",
  "transfer_confidential_2_2.key":
    "e810d52962f4558b0bd50b768a89490759e15a0623d4c2c43318f541b8cc61ff",
  "transfer_confidential_2_4.key":
    "c93338402cdc8fd8ec2f70f2de9fa29ee3e35b064ca803f8ad4d18070e4861fe",
  "transfer_confidential_2_8.key":
    "a38085e7a38b725909e7fe81be544c6e5a1b4ec3561cc07f941eac15825c578a",
  "transfer_confidential_32_2.key":
    "70f4a61a248d240ca6b20730e6ab8a88acb9f4153c1e4688f6861bf6339a5a0b",
  "transfer_confidential_3_2.key":
    "0537e6669e6dae3304648bd427bf3f9ec3e5aaa66134d15e0ff142794f2e966b",
  "transfer_confidential_3_4.key":
    "4710053ed9a08908c419ede4c9a3138d9f78e6d185c6846a2a9c2f4f846c0d4d",
  "transfer_confidential_3_8.key":
    "e559f7256c67be5dc857f601b22c0e929ba615f91032da09db32c00cd98255d1",
  "transfer_confidential_40_2.key":
    "530779155340a05cbd90dedc5e94c5960cf5105f2866bdb041e3a56d06c9bb8b",
  "transfer_confidential_48_2.key":
    "4738674f40f19233f1963954ae4f96a763d11f1adcd82b4828ca8c420cc5b049",
  "transfer_confidential_49_2.key":
    "e39b30ba966198a03158276989d91f1b2fb05f695e56550fec6452d8a3110b6b",
  "transfer_confidential_4_16.key":
    "917cf5f0976d245b08756b1147e04a1f0924c5f5b800d57bd57d305b43e8f432",
  "transfer_confidential_4_2.key":
    "aea0c474e4c67499c45f11f30d2d03e53ee5dd7c6b7940a0f61cfefa2e61e38e",
  "transfer_confidential_4_4.key":
    "6d83eef0b16f03b8f2b2a469441d67264bc34932d8b261f344f5bb39f29a1fbe",
  "transfer_confidential_4_8.key":
    "27fe418512ee0be5cb2f82290eab4ab20ed2d32549e1d8d7bfa1fa5b45df62e9",
  "transfer_confidential_5_16.key":
    "1faf95183f53bd29610ebda52703244ef63f45a2d26706e88bfd3197132bc20e",
  "transfer_confidential_5_2.key":
    "ae6699a19d810a7e0ef663dff3fc32e0b8e4bdeae9089c583746f95ae3b0e1e9",
  "transfer_confidential_5_4.key":
    "6779a069f3abc85f853b754ff2b58021532d26fe9642eb9ba42744da91733517",
  "transfer_confidential_5_8.key":
    "2806aff6bc7bd34233a2ff42a42e5524c680930944c3fc84d6d58e773c033cb5",
  "transfer_confidential_6_2.key":
    "fe62dff0397662cb25d89ac9de976cc3d23adfd2b7a72f5f8ad8671d677da605",
  "transfer_confidential_6_4.key":
    "116a3d4030047d182eedcc9effa66dd9c66ed9bd3ad9d82c2242dc47eef1f244",
  "transfer_confidential_6_8.key":
    "79281967e4aac47dc187d3a6555ab54800cef3928e5696969dcf4afb69b339da",
  "transfer_confidential_8_16.key":
    "8adc64d3886619e3b8e65b3b0c98eaac61bfdfbc8a51aa6ba05166b853feb328",
  "transfer_confidential_8_2.key":
    "24250fd74a86f1a07847e9dbb769cf9b2bebf20d29f18018186ea7900f69bbe4",
  "transfer_confidential_8_4.key":
    "82975fe1145c827a76f8b76e229bb9c8501f993b1a4f7709446b7717f30bd07a",
  "transfer_confidential_8_8.key":
    "f8972d03f57baef87702aaddb87a3b831d2377723e930fb25675fe3e473d8aec",
  "transfer_eddsa_ring_12_2.key":
    "548165847541d40fedaa3fcf958cf7103b999c840875b5f8b234f6649ce11002",
  "transfer_eddsa_ring_12_4.key":
    "7f2c515bab24cd1caa9dae48c329d36df63243403bf694464a3ee9d43c36135f",
  "transfer_eddsa_ring_12_8.key":
    "6f78b87504306cee4472fe3fa64e8be1a5309b32f76da2830b4289a71c6c5c36",
  "transfer_eddsa_ring_16_2.key":
    "3336eaf3862743cf9f18c10685b9d57b6b6c4b88221c89eecb7468d50a30d76e",
  "transfer_eddsa_ring_16_4.key":
    "678f778b10672cb182f380777e6d8e1dbeebbc22a65bf67e0c6de8f16cf271a0",
  "transfer_eddsa_ring_16_8.key":
    "0418193497c8537c0089d9d00f95844bd770601133d441c1d0b4687c4a60518f",
  "transfer_eddsa_ring_1_16.key":
    "9131b75cbcd1b45e0e68f0b333381e801c66dd40a96b5a2772867080ddae41bc",
  "transfer_eddsa_ring_1_2.key": "57257a9e11d81eebc19614048e2fca61612559b92fe66619a59619456fafec83",
  "transfer_eddsa_ring_1_4.key": "cb8f3acb9f436be1219522115517791bdf232bb87ce40a1259d0856f04d67b9c",
  "transfer_eddsa_ring_1_8.key": "dfa27a72f68e54d46b61f57a7868795470697a246bdc886fe3531a094e2921fb",
  "transfer_eddsa_ring_24_2.key":
    "cd948893a6ab87cb5f1a664dd74623f2bb9c60e8c41ca7bca9f1bea07eeb22f3",
  "transfer_eddsa_ring_24_4.key":
    "cef2fb99260f875a54ce75190de21fc5d8b3962233b267e451d60bf5d6b61042",
  "transfer_eddsa_ring_2_16.key":
    "811746d8827e90fdabd8a6dcea4fc2267a6ee3e17092863848c7af647f8e4067",
  "transfer_eddsa_ring_2_2.key": "e2caf1b32ccc0a3ea71f5c43b84202371226b07f45878c5e5283cb5612deb851",
  "transfer_eddsa_ring_2_4.key": "81333b3a71d4a4d30547e34b117f9184464685cf399b70daa2b885f4a755a5eb",
  "transfer_eddsa_ring_2_8.key": "3bd0a5708f734d26637a34283a81b38f21618f8e4c4377ee3f9b102d3f738d50",
  "transfer_eddsa_ring_32_2.key":
    "5507c046d040e1ab437594f5dc8905a76b9f5a82737b627b360384f4d682aa3e",
  "transfer_eddsa_ring_3_2.key": "d8103145686ee2ff94422c0975c8015e215bc018eb8edc8923c71ca3dc1fd01d",
  "transfer_eddsa_ring_3_4.key": "285873e8aec76afb10280f92a707593cd24b363d75276d02b8a640d533284cc8",
  "transfer_eddsa_ring_3_8.key": "abd2cf94e8a5be043f5df073bf863a56d6517eb87dab438950c84ec77f417b28",
  "transfer_eddsa_ring_40_2.key":
    "a9b85045282ae9645bd11c8703086ce7b166e21b9a24c7f5fe948b995fe04b0c",
  "transfer_eddsa_ring_48_2.key":
    "ef341593fc4cd6765a862e417fc1a2d9feba13eeeb366fb41b563375da1f339d",
  "transfer_eddsa_ring_49_2.key":
    "c22abf342ab5809bfabcdfb5c991286e13c2d5576342a772fed1a68938b3303c",
  "transfer_eddsa_ring_4_16.key":
    "400631ced91cfd474a26d1607ff1df034715d5f4d57a2ec4c6d371829e33fea5",
  "transfer_eddsa_ring_4_2.key": "1552e9cef67ac61da1880dea07a95461f993207942a6b0345c91dd2c10c4deb5",
  "transfer_eddsa_ring_4_4.key": "6a4a5df9ae3452c33f13ce064e6d5e71b5a7da7c27239ff4b930d5a6fe4abc15",
  "transfer_eddsa_ring_4_8.key": "59d03b7caf57a6c1dbe27823a592dfd239fb7493cf6b1fe8448eef5312eb2caa",
  "transfer_eddsa_ring_5_16.key":
    "07c3726150075ca180f7a5e8f81e281454264db5f647518ce9f552b59ac4d4f8",
  "transfer_eddsa_ring_5_2.key": "663dc687371f9b0cf6db7271843cce589ee4db10f4758e8ed70c807bf46f446f",
  "transfer_eddsa_ring_5_4.key": "bf39603444ad825a2cb8e7da9692072f8921b1a90dc869ab45970f29f8750fb9",
  "transfer_eddsa_ring_5_8.key": "163329f4c19b43ff964423ac3652e98cf62739d79751f1cb2968191aef30f30b",
  "transfer_eddsa_ring_6_2.key": "1f90ee4146400aefa436d839107692990b8b8d5a9ec4b5778e43d238ded1c328",
  "transfer_eddsa_ring_6_4.key": "0cb043e896ef357213dff3e60d00cd46a1cac132cbac91b2bc28de310751bd15",
  "transfer_eddsa_ring_6_8.key": "573b6ccc6083f2f2b3ef660d756a7c8966293bc5ef72d13beaabca9bc3dec200",
  "transfer_eddsa_ring_8_16.key":
    "b63b887b94a095e072fe8d6578c4bf1fe48f39e45fd03f25263e64a32e89b670",
  "transfer_eddsa_ring_8_2.key": "5edc08bb1ae7c7952bedc11b78d27c22843609eef191ac050905cbbfb9509e14",
  "transfer_eddsa_ring_8_4.key": "ef657aa4db7bf05386d909bd811af291d7edeb3e4b0fc326b4339725eb1f73a5",
  "transfer_eddsa_ring_8_8.key": "ab59ebd50d20f50b684f141c6c97dd86bcd30e8a5158784ee19bf86b9a056376",
  "transfer_ring_12_2.key": "ae1eb3360e044991b1b42ccecc27e86d9bb3a2976f68513be5f094282767d0c8",
  "transfer_ring_12_4.key": "c1b972bec7b2173eb5e565430694807488c296497b1c42f22a49d49fb4056979",
  "transfer_ring_12_8.key": "be949247eda7334bbf8fce2a970d85619b0335cb5810fb01a9095ad33815fd05",
  "transfer_ring_16_2.key": "091d245e16e35c489186e936620364f3f0a289586680724a9c3a0876f5f4298c",
  "transfer_ring_16_4.key": "32adc74fc7e259398982652aa7412318d849e33d6ead24b501189ff2d3b9efc4",
  "transfer_ring_16_8.key": "c45c3fe6cbcdbb635e996bcf693aabc7066c992cdb4556f3fbae882a9f3101a5",
  "transfer_ring_1_16.key": "29a30d08c93866fb2424c74b80e1d1be931117f8f8987985b69332c325e9658d",
  "transfer_ring_1_2.key": "26927410464dd31f8125f533306994eacecf624ad2e99828694a3d8b4776f3b6",
  "transfer_ring_1_4.key": "46e13a5328f9009f9c4f1361cbe748b5f7ec501f4b9320063e79dfa78ad23935",
  "transfer_ring_1_8.key": "f214331059bff13c61e87d6901e8f64a9839ff27d3a9ee3c70352b61fbe63872",
  "transfer_ring_24_2.key": "5e08a486239521ce34da62fd1886e5cfef00548ce56aa6f5a4fb5a4377fc1662",
  "transfer_ring_24_4.key": "0936c2c302253f8eb2271052c873a5b4cf80583e3b311f49caaf4ad862482a44",
  "transfer_ring_2_16.key": "546f3005851483bac41b52b0799d2523ab1a13bdf0e1c84c51f7a2ae4931bb48",
  "transfer_ring_2_2.key": "86f9f78fefaedd0157594c16212558ca1e0a8f9623b1e924b76899a8256763e0",
  "transfer_ring_2_4.key": "54e9c1282cccfa808a437779031c93b5b24fa18b8428705d771f8f7e80bcbb95",
  "transfer_ring_2_8.key": "a80eb136ab8acaf1540aa0ce4e44db7c7a06606cd7108b9e03d7e61e6adec09a",
  "transfer_ring_32_2.key": "544b0475134f4d434bedde20fef7d1d00b3402622a27afb9cef725fca1c2a6f0",
  "transfer_ring_3_2.key": "681b986bdc6b51599a89d9ac10bb116b3dcd5dca0d89e6253f6e3de4d11e7bb0",
  "transfer_ring_3_4.key": "895b55931d83d691c4003c5a358b85acf29688e96ee95699306613e379523dd6",
  "transfer_ring_3_8.key": "2a2f4941c7eb9ede177d6f1a25da21ec70f34ed51998f1a1764f43e99f201902",
  "transfer_ring_40_2.key": "a06dc5d1ecfd428173f125caf8410a5fbb26a81861a578b54b681f503442bec8",
  "transfer_ring_48_2.key": "a87040178e05042c7d70b981f3b044b3c22e5c83d23649376ea079e7dd5a8b86",
  "transfer_ring_49_2.key": "599262efda105b0760acbbc7ff0c7d8f5fd430cb2db643630ffd3f368a7b5ff6",
  "transfer_ring_4_16.key": "b5e68935c95866d90632fdbd60dfbd84a61a5abb420ea0b6e433ae821db51398",
  "transfer_ring_4_2.key": "c49484d014c46fc07aa89ca23945818914d018ffbda5f588b20d907015388d11",
  "transfer_ring_4_4.key": "3a8f3b9782d25a1433c49b9ba0d716fadfa1aaf5bcfadc18ca21cb0c5ee34b49",
  "transfer_ring_4_8.key": "3a136dda18b50e2297c73a69fb588a65c3dd457ac112b1fd3d046a8af15ed8f4",
  "transfer_ring_5_16.key": "f17510859f68664f08027ba59466a5a9e9079dc9cdf1ff5cf808a6e0e7842fd6",
  "transfer_ring_5_2.key": "d855517552582ddaf32fc72029321313aa55b626140f00756e623829e68b4240",
  "transfer_ring_5_4.key": "01c10ca4131e0d0f41526d05b91a4ee951582a6a73142d2d50a5de928260fc16",
  "transfer_ring_5_8.key": "18a7358ebb4cbf738fe4ee9d4f676ba04f56bbf2cf8d5b4f217eca181ec241df",
  "transfer_ring_6_2.key": "67b05471220bb3d1fbdc5ecadac8baaa8a868d391df51e0515ce7f7e0afd81e3",
  "transfer_ring_6_4.key": "e7b3860dcbd244289bdef11b05e314984cbee32af398d9aa929bec0abc2eb640",
  "transfer_ring_6_8.key": "6429382dcd75708b017d96351c2a447a450de55ea80b461963fbb57faf5f82bc",
  "transfer_ring_8_16.key": "7967af9c5840809b6988162a8f831b5f8356defbab91b2f79b4a1cec93790683",
  "transfer_ring_8_2.key": "a2e6d3f15b9ad44c10e6c95b1c8cffee4929c8a20812b6087d59d6e38463085b",
  "transfer_ring_8_4.key": "34ca045c3fa9b6d453ad71c1e5ddf2fb53c53c6833c644ccc5c1ec5a58c24edc",
  "transfer_ring_8_8.key": "dc8fe1ce95e1931814189ddcbcb561f3be96e71bcd7aa3dcc7b3f4940df057be",
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
