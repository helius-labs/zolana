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
  "custom_ring_base.key": "b2082a82cfa6cad4ef71f0161f3046bcaab092bacbd72148f18f6c480004c1c7",
  "custom_ring_compressed_policy.key":
    "2d8039e34527d79411de8562a9ad6faa7bcf8261ae3b313661c916c740545776",
  "custom_ring_delegate_policy.key":
    "d9149726b2043a4c1fa91abef93ff4fe642bf0c67edfa4c7381c9f6277a1c7b4",
  "custom_ring_deposit.key": "2ac09c9b96d6276cc59f4b609e235a607ee16bfe6d34520790abc7d9e9cc2756",
  "custom_ring_policy.key": "a1de1315df9990346ae3a3dc318e4e38a2c54acba2ffd70f0acb079a18583a82",
  "custom_ring_register_key.key":
    "5e11b7a1e6c269491e464bdcecafa7c373ec06b787418b43d3e6f8df4e0a3386",
  "merge_24_1.key": "52635cb0fd6322fe2643eb418bf6efda8240092c88c3732250ec818d8659b577",
  "merge_54_1.key": "91ce9dba4bc395415a90fe40b54c059e4241b583face61400c296e3ec414624a",
  "merge_8_1.key": "6eb7d9f21c0a849b8d974287a53518fceefada02df5fafbc340aab40b73e01f1",
  "merge_ring_24_1.key": "ea8333355dac9e997be3a66d79f8f8456a1510c363dcb664521444d13b202937",
  "merge_ring_54_1.key": "8e5bad48b57f87dbc836fa1c14937040cfbd71e0e630d9cef4264ee5f2564a6a",
  "merge_ring_8_1.key": "1b4b8b8debefe87934bc2b4814f10f35f906b3f18927f4a808ba2a1e1615c1bf",
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
  "transfer_p256_ring_12_2.key": "549faea59c83f97d6b0fc00e006a61d634c4040bb29964fe0ff2aa73971cbda9",
  "transfer_p256_ring_12_4.key": "9fdc33a79cd540dc4dc1de259d6bfd5d2cccf4f689ea5954bc8632dc8e45428b",
  "transfer_p256_ring_12_8.key": "bb8364e844e505328e0466af5523fa103170d660599c07ef4dafda168b5549ab",
  "transfer_p256_ring_16_2.key": "85ebe9715cce518b3e71e4fbf1c06c841a9a39e16187cc7030b34ce8ca5acfe9",
  "transfer_p256_ring_16_4.key": "99005c1ef2ce782ad7ab80f32b6b2c0f1a26fedd2a48634718684259a82363fd",
  "transfer_p256_ring_16_8.key": "1f396e61cc0301cc4aa7be647a4f3cb2ced94f3ad93c73b6621c475aaf7de977",
  "transfer_p256_ring_1_16.key": "a5c7390bfe8130cfb5a195d5d2df479082dfdecf50ea48a06a995f259bd279da",
  "transfer_p256_ring_1_2.key": "59adee98a3231ad37224c5f12f59cf3d3eaa01d9ff8dcfced34ee2de3b61d51a",
  "transfer_p256_ring_1_4.key": "33d0367c499b0739afb8145d8647b6cea5b0d8b9331d3e0dec397ca09714f29c",
  "transfer_p256_ring_1_8.key": "3fb3ea85bd97cd545e251caeec4adce77b93189ac726f194c811f25077271c8d",
  "transfer_p256_ring_24_2.key": "dd6160e9ea385bea226ef6aa6b4a662710e1b2688cc195c39a616f48af8a9093",
  "transfer_p256_ring_24_4.key": "c4ef53b38b3235cd723d90ba62c7a91845e9abf22fc4a2845988abb4c9d7510a",
  "transfer_p256_ring_2_16.key": "99eaf4a33da7f28e319405ad3290eca0cf2c5c28c8384245e801ad17325e40bf",
  "transfer_p256_ring_2_2.key": "ce738040fa1bf4fbf706024bd97229036cd11fe4ac1aeb45e738462b20a29bc0",
  "transfer_p256_ring_2_4.key": "72e3c540a704129d60d43270b8c3e801f94414b3e8e2f29eb961ef126dc5c48d",
  "transfer_p256_ring_2_8.key": "ff9009325e88c36c6f3f6ddab6ce0a1d61ed2b96e8212a9c22726157eeebb491",
  "transfer_p256_ring_32_2.key": "547554c854213a613bd749b12d1b044bfb156af2f9be583862eb56912fcdbe74",
  "transfer_p256_ring_3_2.key": "9b3c791d0ccc588c5ba17925ad3c6c3472fcb3c1ec58129dfe336d07ea209965",
  "transfer_p256_ring_3_4.key": "0cc50cdf9b95ebc330da3bab925baf9af09773135b44a381bc1dc22381b22ba0",
  "transfer_p256_ring_3_8.key": "52251c04323bb5c3bf773310ae62a9e772f6adea11dff66090a736837b3a99e9",
  "transfer_p256_ring_40_2.key": "feb1a928325c86cb76a47acc26bf7981008245887ce97af6cff204fbee082bd7",
  "transfer_p256_ring_48_2.key": "316afacb380b746b2aee16286b5485bd19739f90a3cf9a0fe839048d37ca4c3a",
  "transfer_p256_ring_49_2.key": "8d332a55798003c0f45cd072b6b4348350d9f2876e510e10d29dacc21875ca05",
  "transfer_p256_ring_4_16.key": "b1d91286b758389c8381bdf2bb8e5faaa5a9262d78c8e0fa95c071b4870d89b5",
  "transfer_p256_ring_4_2.key": "1842469e6678c286e54ce66f99fec041de429e181a34e22d99a57201f6fe9eac",
  "transfer_p256_ring_4_4.key": "c370c8ed94efd64b709b788f4ba4773fe2688f23548ffe5ce7eb1beda8857064",
  "transfer_p256_ring_4_8.key": "cef062cb2d98488405c092add352591030f15eb7912b01ec0469ed130842f161",
  "transfer_p256_ring_5_16.key": "75bb898afe5d3723862caa76b6bbf15cd9496d27d8ec9e758118e785ce704eec",
  "transfer_p256_ring_5_2.key": "6821eb2cbc81d420401a7baf50f48b158f32aed17f0f5cac594868aa709af826",
  "transfer_p256_ring_5_4.key": "edd68a98b02a7f260a34d0f8f1d24cc67c2510ca1a8acd80a0be7eb48b44b0e3",
  "transfer_p256_ring_5_8.key": "ad516e9dbd6a568caa3fe0863d874dd15c14528227ccf926141652935966331d",
  "transfer_p256_ring_6_2.key": "0bc2b31f1bd0cdabb06106ee1ecb6b30ab009ee0249cb6477c870e856627e732",
  "transfer_p256_ring_6_4.key": "ea188a5013d48bfd74cb2bb8a7c6e0cc05f0cdf022202b7f01714ef3397c19a5",
  "transfer_p256_ring_6_8.key": "a36bbeb799e92b9c1da2329fecab57ecb654e1273ef7d1db6a69b2e4b19d6097",
  "transfer_p256_ring_8_16.key": "d94eb64135dbddce2fc4450e013b9404578d77a5e1f676d672e48aeab1447ff5",
  "transfer_p256_ring_8_2.key": "28804a77c59eb3e4daa348104dfc4b07429c4f0d6a0b4eb704c3c1a5a1dbe5eb",
  "transfer_p256_ring_8_4.key": "ba4e1cbfc96f1c9abd210de4274cc2c4f0a61ae2b80bbd7915f5855d04ca5f57",
  "transfer_p256_ring_8_8.key": "b684102d31244cb8fe109b3b4f0bb04a0ae245f9c5e32719ba09a1e7f0ba6f28",
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
