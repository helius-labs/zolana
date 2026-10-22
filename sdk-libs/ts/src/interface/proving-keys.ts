import { RING_PROVING_KEY_SHA256S } from "./ring-proving-keys.js";
import {
  ANONYMOUS_AUDIT_CLASSES,
  ANONYMOUS_ENTRY_CLASS,
  ANONYMOUS_ENTRY_OUTPUTS,
  DELIVERED_AUDIT_CAPACITIES,
  PACKED_AUDIT_CAPACITIES,
} from "./ring-disclosure-layout.js";
import { RING_AUTHORITY_SHAPES } from "./shape.js";
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
  "merge_52_1.key": "d3d3cc6485f33f7dd08d1b8640aecff9ecbdb3cbf2e464d5b25a2a2f10da65ec",
  "merge_ring_52_1.key": "84e7fec3398abf7bce45ab7932bc73b8e50879d451f8e63d4e92d4bb20ffce14",
  "batch_address-append_40_10.key":
    "589c90ea00bc771e7b61c28c20290c4dfaa9a33790d7231261d7bbe621459843",
  "batch_address-append_40_4999.key":
    "367fd7d2f534810ec684b7dbbadfd90dc65550d26989a2f2945d4719702001de",
  "merge_24_1.key": "9accef7fb9950a550948a6e5f0f415f29266af9720e5085c40416e3c589c488a",
  "merge_8_1.key": "9adcc4b534b7e0a56fc1012401fde6d418fb15638be4e697c9718b114e56e5cc",
  "merge_ring_24_1.key": "3c0d8c8e63c126de90352900e0d3023562448c6e2bd7110f042a98cf5542f81a",
  "merge_ring_8_1.key": "b210449113a5104c2062d056000bb57e5c8f2c0d08d4c8d41441b90762092a8a",
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
    "0a549974b51cea61a1f25d1c4f2f6f5d6ac606deec854ead3b507fb5efac852a",
  "transfer_eddsa_ring_12_4.key":
    "da995978928035cfcc5064f7c399324340f3034c09a796e7897a3aca99bb3cb1",
  "transfer_eddsa_ring_12_8.key":
    "4f01debd84e033f8e89d3a454942e9fbfcd3f0265a57dc0a422dc10138e6322b",
  "transfer_eddsa_ring_16_2.key":
    "0ed682651e02fc7a31e62ee088e8d7caa09a73dc6114776e8fd57a0f7da1b096",
  "transfer_eddsa_ring_16_4.key":
    "59dc4edd1eb7d67282ebb1da9f09fd842bc3e7cda69b46b6f1aab68045920bb0",
  "transfer_eddsa_ring_16_8.key":
    "dc3e2e719ae5d9521960ec9b5237ea72c9e6715302214763056c4d816c27ff0e",
  "transfer_eddsa_ring_1_16.key":
    "c7eabc67b008a141268655c3e40891e08f0689bf59fec1b2cb7a177368154d57",
  "transfer_eddsa_ring_1_2.key": "6c75b8f7bf42579b35be28bb035b7e9fd85200c5191a432f25b007647af09bb3",
  "transfer_eddsa_ring_1_4.key": "828a66325edd168a7fcc83816651f245fa44396fe9d9258cec019500cf2a9398",
  "transfer_eddsa_ring_1_8.key": "91f26e16fbadcf435d001db4f783ae1c87f28d01803124627feba57c05b20fd8",
  "transfer_eddsa_ring_24_2.key":
    "b2ac7d320a8db3c821d836f0ea9e2703bb0e0fdbf51fea9fc98143f36ebafe54",
  "transfer_eddsa_ring_24_4.key":
    "1f17a66dc2e47c2cd1a53648b73f2af6fda7f3bba4f3232ef502d1830cde35ff",
  "transfer_eddsa_ring_2_16.key":
    "c911f7d1af3e2bc37d3ad768a0acb9bca1eda39634e38f2d9fc14ffa8939889b",
  "transfer_eddsa_ring_2_2.key": "c1820e51ff946182553385fc255ec348d935aff2eef335bc2e647d3790d4c18b",
  "transfer_eddsa_ring_2_4.key": "8732da9753bdc5bf14ad0d3c0d1ff9b71d6a16b671283a59ef8980134167bc7f",
  "transfer_eddsa_ring_2_8.key": "c6c92a44f2f8fedd6fd636b14e90fb7f4ddd43e41e5fa109a2f3748a9dc7f451",
  "transfer_eddsa_ring_32_2.key":
    "61bd99cb1809784ff8af83cfa3148f1813f87055efa3ac3f9cfb966b5266af43",
  "transfer_eddsa_ring_3_2.key": "81c14b8004a2cc904a248b26aa7073e83c9848762ff5001c4667470ef9fe1ff9",
  "transfer_eddsa_ring_3_4.key": "54c9103bb7c4a9f65cf782ff73ae719001ed6ab9c3082f89dcef6e0a9c5c65f5",
  "transfer_eddsa_ring_3_8.key": "56b1da8814f1581258b3046964d0736f767cc9a97941148eaf0591dc23fdf9f5",
  "transfer_eddsa_ring_40_2.key":
    "cf2ae86808348256ec2e6d73bcb5fff7a805eab2877d722614639970c57d4e0e",
  "transfer_eddsa_ring_48_2.key":
    "c754aea246c75a41e837eca01792bde27244adb376fc1256369c1a81fd9f585a",
  "transfer_eddsa_ring_49_2.key":
    "b4053421e7b430cf37773a5be03cc1624b6a2808c79aa7270b41dd642f5fa521",
  "transfer_eddsa_ring_4_16.key":
    "c74ee52f8b07cca84b2fd6c8b346abae0ddb4fce731c399871902ba6e18909f9",
  "transfer_eddsa_ring_4_2.key": "90d772e91320b9fbdadb03446c2fdee19fae99c0165c4eb5e3c9613d3bcb4787",
  "transfer_eddsa_ring_4_4.key": "de4ae7b9325f440b7429c7d20a84234e561dc2dfe5b1e6f5c745f98b75d92d84",
  "transfer_eddsa_ring_4_8.key": "685a4c10d69b7a7b266187a11a76524fa89e0ae2776f3a9a0104d29b09263599",
  "transfer_eddsa_ring_5_16.key":
    "cee6951b7064581aa90d6d70c657d98e05bbd021814ca683317653dded9f5c0c",
  "transfer_eddsa_ring_5_2.key": "91b94b16cb619189d42a16c04e1cd8ce2bc3153103167053c760477ebd95b352",
  "transfer_eddsa_ring_5_4.key": "6b3e70ddea00bb6b06242e52276dd74b02bd667c58926c120e88034205293e11",
  "transfer_eddsa_ring_5_8.key": "ec18339768e6b8d6bea692238e2a79c9bee415925866d5371c794da90f040d19",
  "transfer_eddsa_ring_6_2.key": "7ad2accceba78e4894e2da5b67f5d71a33ed89747510f4a94ad575b24ee9d7e5",
  "transfer_eddsa_ring_6_4.key": "4f9c2b06f1731a3988e95e4435022778eaffb2b87c214f666b3b25b1dcfb4329",
  "transfer_eddsa_ring_6_8.key": "ea8264d175804ab05a6115d0eaddcd7f3038ed0da8686823d8926de2f839e839",
  "transfer_eddsa_ring_8_16.key":
    "cde78f1c8a21a16d446b9beb02646461048b4610596619a61332fe22108d4b8e",
  "transfer_eddsa_ring_8_2.key": "7657b6499c1c513b0a0cbc2812b09790471434c2741167def7b49120925ed87e",
  "transfer_eddsa_ring_8_4.key": "1400e196dfbe9f6a7b70619c2a2dc1bae624fe41e8456d1960f0a49c57bb9757",
  "transfer_eddsa_ring_8_8.key": "023cce41bdc917ae1877bdd3663160b25cd0ee91ddf37d213ca0cf0999866c92",
  "transfer_ring_12_2.key": "7972cddd8f2fe2e2c98f233f5fc0a2472f127e8d91fb12fb898549c556cbecad",
  "transfer_ring_12_4.key": "dadf4889eb86421a026fc2501040febb7680715811a5d41253501eca62f631e8",
  "transfer_ring_12_8.key": "93be7baf5a07fdcf3f6b15302e70d1be80891848ddb2f896e491d31bf7008c72",
  "transfer_ring_16_2.key": "470ddd0588c60ca5e192b86d551462adef0cb0e49a776b18e76d22c5cbc777aa",
  "transfer_ring_16_4.key": "686d44033780f39ca294f945e2d69f93e2a7cdb2c7c58f985dcf843b1a20b1f4",
  "transfer_ring_16_8.key": "777890f4d8e5db59874589e7998dcce56dc3505df2c23a1a3d00a901a742382a",
  "transfer_ring_1_16.key": "2d99fbd08642244ffdc9e76431c2ce5b7e6820b4fc1174021061e8a2f2a3e737",
  "transfer_ring_1_2.key": "e6494f4d039a8000e95d65b489e3b1dd52b63287039b637a984269f9d3cff68a",
  "transfer_ring_1_4.key": "dfbb696609fb387fa24a8a94de4b765ce10369be168f788eb115a1e3ab9c7ee6",
  "transfer_ring_1_8.key": "7c1a3447f59caf4e1301feced66e88a5963f0211b50ad6970e4bcdd98d6a36af",
  "transfer_ring_24_2.key": "fa252bbe78a4bba2a65b6ac84f8c5a25868213d9a1c45aa467fda56b0b174ca7",
  "transfer_ring_24_4.key": "77d393fa3e20fcc1b4e9212de12ea41addecf794f62191c4be30db48e4746679",
  "transfer_ring_2_16.key": "33045cd52ae42c09ed40c7ee12989854816483a8166f8c035420d7e6d91ddbda",
  "transfer_ring_2_2.key": "26f8d34c8ecda0ca59e94bcdd0a12f4f06ab8d1c9fc49beb12c6ccd03a799f9f",
  "transfer_ring_2_4.key": "7632938dd0e7dfbc0c3518773b88d7f1af336b767dcfca40252833e339739ead",
  "transfer_ring_2_8.key": "459fe01778114fcbdebab5ba26075efbfaf78b4687183e3bc4fe2907bcba1076",
  "transfer_ring_32_2.key": "421ed32f01849b8a464109d1b52f3f6e3b7fa5876de00a6e8ff1dea0c8e8b713",
  "transfer_ring_3_2.key": "287d79d9d243a5f8c970b5ef27763de6ee0a2b731a24837e0476e9b5c498df8a",
  "transfer_ring_3_4.key": "ea71558b8b8bd8b4e88d55797224e24964056cfea4b548a717e775ba17236652",
  "transfer_ring_3_8.key": "fd4c8db6d8eb839fb295ecdfff7db206549f3bbd3ec05cd1d5da8e0fcd383fd0",
  "transfer_ring_40_2.key": "3d438a562cc49eb1f1844e4d49233b80a74490b00a95ad81aae32dc7b8830677",
  "transfer_ring_48_2.key": "cea28ebcf7d1bf2d6e19493bff3cfd5b71bc1c508b73ea0f3b06498f04a6cdd4",
  "transfer_ring_49_2.key": "cb94149bbe749a49a7c884ee8830be2b9c7649ac75452cb8bb1927c4a522dc97",
  "transfer_ring_4_16.key": "7d2d350c64fd9d29fe92b306448b4ea95ea0c1028455884bc0d3ca0367aab575",
  "transfer_ring_4_2.key": "451a8a65ecd5bcea8e2b882cf7882b2b9c5a6e7c09e44a6640764ecd0f18f71d",
  "transfer_ring_4_4.key": "902b2498f921fd9ed412179303c48ccf417b689d9c6b4a9f0d6d3dc539da713b",
  "transfer_ring_4_8.key": "6c167da0363e96299dd1a15cb11c95bd12b2afaab719b036eb561a904ca48baa",
  "transfer_ring_5_16.key": "ecbbbb6f9d7fb493cbd323d0fa9b8b483ff2be18463223410ab3adcf21ad0c8c",
  "transfer_ring_5_2.key": "abe82f9b260f1ebac6cbee06e4401a14479539d84c977cad533511dba927640a",
  "transfer_ring_5_4.key": "9bb402460b26b7032aa241b30d1042f740477d9f036bd688da8ef9969ad6c2b4",
  "transfer_ring_5_8.key": "aaf51fcd769ef9ed57696fc53d550aefcf1eab8b5b9e7454ef579a59701e7ae5",
  "transfer_ring_6_2.key": "e699cbace42cbc13ddbef2211bccad2c8c5e35b1907aaf54f2bcf345f9ae13bd",
  "transfer_ring_6_4.key": "adb74521cc9d2519bdd76be5109e361c77d394fbd091a1ae0f85ade598481fdd",
  "transfer_ring_6_8.key": "24911491d353f4f96f4148558c1b8588be3fc0b13d441abf9ccb15b0db2056ac",
  "transfer_ring_8_16.key": "bad877f1c6a2487e446ba51b107a3c88e39e384290f9c21bc864c3c9a9967ed6",
  "transfer_ring_8_2.key": "c90611c80ee39a4f8506def5551ad189e52c9a72b1ed3f16bd167ce8cc6197c7",
  "transfer_ring_8_4.key": "a6a013191ccea8c5d77ccf28d75c6122d4481a278826b5aa35a14cfbc2c56374",
  "transfer_ring_8_8.key": "8ae3d3334e5628b3cfe99b0791ae1eb9b1d5eaa0d9e60e6ddf11f259091197dd",
  "transfer_ring_authority_12_2.key":
    "3b1e0563aebf68e4f6b7a7d4285e823ce6da0c7d5142a2d99a33614608665514",
  "transfer_ring_authority_12_4.key":
    "99b5cf5234b690e8c354f850d2ce6b370bd3446cc0f8eff186f1e73083b482f6",
  "transfer_ring_authority_12_8.key":
    "58f86bacafc0143b073f4420044fd8954ece379956e7f1f81e28ce2b82836e34",
  "transfer_ring_authority_16_2.key":
    "821feedf2c162520d4c0367dd91e68cecfe632c317cb15307b93168beab70edf",
  "transfer_ring_authority_16_4.key":
    "d11a07643a700610e4780c29af414968cc8e459cbf4b6d2d7428202d27a9a374",
  "transfer_ring_authority_16_8.key":
    "e1add9dfca24b59f6ef8a6c7d2eaf6a515ad17c323ef95474ff24eb404baa2e1",
  "transfer_ring_authority_1_16.key":
    "7ee5af9c5fdc785984a52576ce870997db273c800c08ce0839455666d9704fe7",
  "transfer_ring_authority_1_2.key":
    "703253790f5d193d1005672c5d24d5b95920af4724a3413784ae6bf53bec9b5f",
  "transfer_ring_authority_1_4.key":
    "8bbaa1df0f2096bd41b26659d890262a69d4e69fc9c4422b7d93db1afdc376ad",
  "transfer_ring_authority_1_8.key":
    "3db6540415b310f8dcdeee48b0ea41c72df12cf9baa8fd03ad047e3824f099db",
  "transfer_ring_authority_24_2.key":
    "8505271e77b99b2d8fc9b1054e4b55f78010962e24f834559dadd0b6a0f2496d",
  "transfer_ring_authority_24_4.key":
    "af3b9bb32e3122f4e514e5640feb026ad42f53dabe687cbd20273aaa6d4a0568",
  "transfer_ring_authority_2_16.key":
    "af60a59a5d8e108853d1faf903cb040c79a481f9be36d0341506de804beab7b5",
  "transfer_ring_authority_2_2.key":
    "95b387a60b7051faf736ca7b3434637819fdf1ff9ea88aa6710d8b6ceb997d61",
  "transfer_ring_authority_2_4.key":
    "f075088c9e42b4197824b8ba407081977794401ca40f4f67c8c42ec66b1b8603",
  "transfer_ring_authority_2_8.key":
    "aa7f89b3475759745599d4c9a9ad46036badf9f58886ba14b2f1d98ca67aec00",
  "transfer_ring_authority_32_2.key":
    "714dd1796a4e5544f627d4b4fe5a1c9ba21bb1cfa6d59a7dc1de166fb0104a97",
  "transfer_ring_authority_3_2.key":
    "f84ff947ad36452fc5e5c9f4e1a991025dc3e6e33590aa261515e291c9ad1dd0",
  "transfer_ring_authority_3_4.key":
    "7156e30cd6a887f8e5d4349147ad85ab7d2293686448128fe58993e8fb1e1e66",
  "transfer_ring_authority_3_8.key":
    "09c4342ba27d6a8948acd5755f1c73bb6ede55365bf798f5b596ed63a5978576",
  "transfer_ring_authority_40_2.key":
    "fa9d6f5838cf543a046896da63e4effdf0a70c18ede15a48bd73559ac56d8861",
  "transfer_ring_authority_4_16.key":
    "673255824c3c2a8e59e82c338424ddddf064e76e4243daf7aa45065d1c68f617",
  "transfer_ring_authority_4_2.key":
    "3ba66524fadf57f6f67b7bd5f79da594cf251a055f015af863499a4a0fda65d0",
  "transfer_ring_authority_4_4.key":
    "082189c1a0960a9ba85f19440db8ceae92ee6c9339eb79077ab8f84e171432ea",
  "transfer_ring_authority_4_8.key":
    "1462ec5a34259abf37b486cc87b201b2d17c1a301a712144cc986e86b99018c2",
  "transfer_ring_authority_5_16.key":
    "093d3cd709e142e3b4305eac7ad57518c69bcd53acfe00d825ba5fb17186e8b3",
  "transfer_ring_authority_5_2.key":
    "980b8717ba3c2a3853e5931fbf514d5eae72b141bc0a222991ab356136b600b6",
  "transfer_ring_authority_5_4.key":
    "de45c5fa7f8c2f4c698d624a50e29a4aa9114d472c104ec971f6570d8ce1e170",
  "transfer_ring_authority_5_8.key":
    "ac57058de1164451cb1366634e1cfc9656a88bea6dca74f5f6c969ed714afd13",
  "transfer_ring_authority_6_2.key":
    "10574fcf593ef1713ca71a7b6798689ab20faa54dfabb4a3a25fd9830f42157e",
  "transfer_ring_authority_6_4.key":
    "be91e0cd62fecba05da8e5fb0a10c80414e0347d89af40aebe255fc78e9d86eb",
  "transfer_ring_authority_6_8.key":
    "2b79daaab4348af909f2838f1117106945c0207e8ca8615389b5afcb9bd0dd5e",
  "transfer_ring_authority_8_16.key":
    "7aa9c3e59433a58217db4615764e1b6119f8b9ff4aab761100da49bc07b84f61",
  "transfer_ring_authority_8_2.key":
    "42122c6ae0983a7f0fa2327a76e63638955c613dc3e8584e9715dcd923671e83",
  "transfer_ring_authority_8_4.key":
    "0c818c948dd1bb466d91e21f124eb93866c1394c52e1175ec0232dfe7fdf565c",
  "transfer_ring_authority_8_8.key":
    "7260d944101f9291523cec422dea4da8b1837c997bddbaa42b55e04b929b90f9",
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
  return pinnedProvingKey(provingKeyName(request), request.circuit);
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
  }
}

/** A ring circuit by the shape its key serves, Rust `RingCircuit`. */
export type RingKeyCircuit =
  | Readonly<{ family: "packedAudit"; outputs: number }>
  | Readonly<{ family: "deliveredAudit"; outputs: number }>
  | Readonly<{ family: "anonymousAudit"; inputClass: number; outputs: number }>
  /** Opens every spent UTXO, the key of a transfer spending a default-ring note. */
  | Readonly<{ family: "anonymousEntryAudit"; inputClass: number; outputs: number }>
  | Readonly<{ family: "memberPolicy"; outputs: number }>
  | Readonly<{ family: "delegatePolicy"; inputs: number; outputs: number }>
  | Readonly<{ family: "applyRecords"; writes: number }>
  | Readonly<{ family: "registerKey" }>
  | Readonly<{ family: "deposit" }>
  | Readonly<{ family: "anonymousMerge"; width: number }>;

/** Rust `RING_KEYS`, every ring key in its order, `name` the circuit type the prover serves. */
export const RING_KEYS: readonly Readonly<{
  circuit: RingKeyCircuit;
  name: string;
}>[] = Object.freeze(
  (
    [
      ...PACKED_AUDIT_CAPACITIES.map(
        (outputs) =>
          [{ family: "packedAudit", outputs }, `custom-ring-audit-packed-${outputs}`] as const,
      ),
      ...DELIVERED_AUDIT_CAPACITIES.map(
        (outputs) =>
          [
            { family: "deliveredAudit", outputs },
            `custom-ring-audit-delivered-${outputs}`,
          ] as const,
      ),
      ...ANONYMOUS_AUDIT_CLASSES.flatMap(({ outputs, classes }) =>
        classes.map(
          (inputClass) =>
            [
              { family: "anonymousAudit", inputClass, outputs },
              `custom-ring-audit-anonymous-${inputClass}-${outputs}`,
            ] as const,
        ),
      ),
      ...ANONYMOUS_ENTRY_OUTPUTS.map(
        (outputs) =>
          [
            { family: "anonymousEntryAudit", inputClass: ANONYMOUS_ENTRY_CLASS, outputs },
            `custom-ring-audit-anonymous-entry-${ANONYMOUS_ENTRY_CLASS}-${outputs}`,
          ] as const,
      ),
      [{ family: "memberPolicy", outputs: 2 }, "custom-ring-policy-member-2"],
      [{ family: "memberPolicy", outputs: 4 }, "custom-ring-policy-member-4"],
      [{ family: "memberPolicy", outputs: 8 }, "custom-ring-policy-member-8"],
      [{ family: "memberPolicy", outputs: 16 }, "custom-ring-policy-member-16"],
      // Go `ringKeys` sizes the delegate keys by the SPP ring authority rule.
      ...RING_AUTHORITY_SHAPES.map(
        ({ inputs, outputs }) =>
          [
            { family: "delegatePolicy", inputs, outputs },
            `custom-ring-policy-delegate-${inputs}x${outputs}`,
          ] as const,
      ),
      [{ family: "applyRecords", writes: 1 }, "custom-ring-apply-records-1"],
      [{ family: "applyRecords", writes: 16 }, "custom-ring-apply-records-16"],
      [{ family: "registerKey" }, "custom-ring-register-key"],
      [{ family: "deposit" }, "custom-ring-deposit"],
      [{ family: "anonymousMerge", width: 8 }, "custom-ring-merge-anonymous-8"],
      [{ family: "anonymousMerge", width: 24 }, "custom-ring-merge-anonymous-24"],
    ] as const
  ).map(([circuit, name]) =>
    Object.freeze({ circuit: Object.freeze<RingKeyCircuit>(circuit), name }),
  ),
);

/** The circuit type the prover serves `circuit` under, refused for a shape no ring key serves. */
export function ringCircuitType(circuit: RingKeyCircuit): string {
  const key = RING_KEYS.find((entry) => sameRingCircuit(entry.circuit, circuit));
  if (key === undefined)
    throw new InterfaceError("INTERFACE_INVALID_SHAPE", {
      circuit: circuit.family,
    });
  return key.name;
}

/** The ring key a proof must come from, the file name Go `RingKeyFile` derives from the circuit type. */
export function ringProvingKey(circuit: RingKeyCircuit): ExpectedProvingKey {
  return pinnedProvingKey(`${ringCircuitType(circuit).replaceAll("-", "_")}.key`, circuit.family);
}

/** A key without a pin has no committed verifying key, the program refuses its proofs. */
function pinnedProvingKey(name: string, circuit: string): ExpectedProvingKey {
  const sha256 = Object.hasOwn(PROVING_KEY_SHA256S, name) ? PROVING_KEY_SHA256S[name] : undefined;
  if (sha256 === undefined) throw new InterfaceError("INTERFACE_INVALID_SHAPE", { circuit });
  return Object.freeze({ name, sha256 });
}

function sameRingCircuit(left: RingKeyCircuit, right: RingKeyCircuit): boolean {
  switch (left.family) {
    case "packedAudit":
    case "deliveredAudit":
    case "memberPolicy":
      return right.family === left.family && right.outputs === left.outputs;
    case "anonymousAudit":
    case "anonymousEntryAudit":
      return (
        right.family === left.family &&
        right.inputClass === left.inputClass &&
        right.outputs === left.outputs
      );
    case "delegatePolicy":
      return (
        right.family === left.family &&
        right.inputs === left.inputs &&
        right.outputs === left.outputs
      );
    case "applyRecords":
      return right.family === left.family && right.writes === left.writes;
    case "anonymousMerge":
      return right.family === left.family && right.width === left.width;
    case "registerKey":
    case "deposit":
      return right.family === left.family;
  }
}
