import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import * as n from "@codama/nodes";
import { getValidationItemsVisitor } from "@codama/validators";
import { visit } from "@codama/visitors-core";
import { format } from "oxfmt";

const root = new URL("../../../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");
const rotationSource = await read(
  "programs/shielded-pool/src/instructions/protocol_config/update.rs",
);
const rotationRequiresSigner = rotationSource.includes('iter.next_signer("new_authority")');
if (!rotationRequiresSigner && !rotationSource.includes('iter.next_account("new_authority")'))
  throw new Error("Unknown authority-rotation account semantics");
const check = process.argv.includes("--check");
const num = (format) => n.numberTypeNode(format);
const bytes = (size) => n.fixedSizeTypeNode(n.bytesTypeNode(), size);
const vector = (item, width = "u8") => n.arrayTypeNode(item, n.prefixedCountNode(num(width)));
const blob = (width = "u16") => n.sizePrefixTypeNode(n.bytesTypeNode(), num(width));
const option = (item) => n.optionTypeNode(item);
const address = n.publicKeyTypeNode();
const bool = n.booleanTypeNode();
const struct = (fields) =>
  n.structTypeNode(
    Object.entries(fields).map(([name, type]) => n.structFieldTypeNode({ name, type })),
  );
const variant = (name, fields, tag) => n.enumStructVariantTypeNode(name, struct(fields), tag);
const enumeration = (entries, width = "u8") =>
  n.enumTypeNode(
    entries.map(([name, fields, tag]) => variant(name, fields, tag)),
    { size: num(width) },
  );
const link = (name) => n.definedTypeLinkNode(name);
const proof = struct({ a: bytes(32), b: bytes(128), c: bytes(32) });
const ownerTag = enumeration([
  ["inline", { value: bytes(32) }],
  ["account", { index: num("u8") }],
]);
const circuitFields = { inputs: num("u8"), outputs: num("u8"), publicAssetSlots: num("u8") };
const circuit = enumeration(
  [
    ["confidentialEddsa", circuitFields],
    ["ringEddsa", circuitFields],
    ["ringAuthority", circuitFields],
    [
      "ringP256",
      {
        ...circuitFields,
        commitment: bytes(32),
        commitmentPok: bytes(32),
        defaultOwnerTag: n.optionTypeNode(bytes(32), { fixed: true }),
      },
    ],
  ],
  "u16",
);
const assetKind = enumeration([
  ["sol", {}],
  ["spl", { splInterfaceBump: num("u8") }],
]);
const interfaceTransfer = enumeration([
  ["solDeposit", { amount: num("u64") }],
  ["solWithdrawal", { amount: num("u64") }],
  ["splDeposit", { amount: num("u64"), splInterfaceBump: num("u8") }],
  ["splWithdrawal", { amount: num("u64"), splInterfaceBump: num("u8") }],
]);
const depositEntry = struct({
  assetIndex: num("u8"),
  viewTag: bytes(32),
  owner: bytes(32),
  amount: num("u64"),
  utxoData: option(struct({ dataHash: bytes(32), data: blob() })),
  memo: option(blob()),
});
const ringDepositEntry = struct({
  assetIndex: num("u8"),
  viewTag: bytes(32),
  ownerUtxoHash: bytes(32),
  amount: num("u64"),
  dataHash: option(bytes(32)),
  ringDataHash: bytes(32),
  encrypted: struct({ txViewingPk: bytes(33), salt: bytes(16), ciphertext: blob() }),
});
const output = struct({ utxoHash: bytes(32), ownerTag, data: option(blob()) });
const transact = struct({
  expiryUnixTs: num("u64"),
  txViewingPk: bytes(33),
  salt: bytes(16),
  interfaceTransfers: vector(interfaceTransfer),
  dataHash: option(bytes(32)),
  ringDataHash: option(bytes(32)),
  outputs: vector(output),
  messages: vector(struct({ viewTag: bytes(32), data: blob() })),
  privateTxHash: bytes(32),
  circuit,
  proof,
  inputs: vector(struct({ nullifierHash: bytes(32), treeIndex: num("u8") })),
  treeContexts: vector(
    struct({ utxoTreeRootIndex: num("u16"), nullifierTreeRootIndex: num("u16") }),
  ),
});
const merge = struct({
  expiryUnixTs: num("u64"),
  proof,
  outputUtxoHash: bytes(32),
  eddsaOwner: bool,
  privateTxHash: bytes(32),
  nullifiers: vector(bytes(32)),
  utxoTreeRootIndex: num("u16"),
  nullifierTreeRootIndex: num("u16"),
});
const generalEvent = struct({
  inputs: vector(
    struct({ tree: bytes(32), inputQueueSeq: num("u64"), nullifier: bytes(32) }),
    "u32",
  ),
  outputs: vector(struct({ viewTag: bytes(32), utxoHash: bytes(32), data: blob("u32") }), "u32"),
  messages: vector(struct({ viewTag: bytes(32), data: blob("u32") }), "u32"),
  txViewingPk: bytes(33),
  salt: bytes(16),
  firstOutputLeafIndex: num("u64"),
  outputTree: bytes(32),
  splTransfers: vector(
    struct({ isDeposit: bool, amount: num("u64"), asset: option(bytes(32)) }),
    "u32",
  ),
});
const batchEvent = struct({
  merkleTreePubkey: bytes(32),
  zkpBatchSize: num("u16"),
  oldNextIndex: num("u64"),
  startSequenceNumber: num("u64"),
  firstRootIndex: num("u32"),
  numUpdate: num("u32"),
  firstZkpBatchIndex: num("u32"),
  newRoot: bytes(32),
});
const inputTreeSequence = struct({ tree: bytes(32), firstInputQueueSeq: num("u64") });
const transactEvent = struct({
  inputTrees: vector(inputTreeSequence, "u32"),
  outputTree: bytes(32),
  firstOutputLeafIndex: num("u64"),
});
const mergeEvent = struct({
  inputTrees: vector(inputTreeSequence, "u32"),
  outputTree: bytes(32),
  outputLeafIndex: num("u64"),
  outputViewTag: bytes(32),
});
const event = enumeration([
  ["deposit", { event: link("generalEvent") }, 1],
  ["transact", { event: link("transactEvent") }, 2],
  ["merge", { event: link("mergeEvent") }, 3],
  ["nullifierTreeUpdate", { event: link("nullifierTreeUpdateEvent") }, 4],
]);
const createConfig = struct({
  protocolAuthority: address,
  treeCreationAuthority: address,
  treeCreationIsPermissionless: num("u8"),
  foresterAuthority: address,
  ringCreationAuthority: address,
  ringActivationIsPermissionless: num("u8"),
  splInterfaceCreationIsPermissionless: num("u8"),
  feeAuthority: address,
});
const updateConfig = enumeration([
  ...[
    "protocolAuthority",
    "treeCreationAuthority",
    "foresterAuthority",
    "ringCreationAuthority",
  ].map((name) => [name, { value: address }]),
  ...[
    "treeCreationPermissionless",
    "ringActivationPermissionless",
    "splInterfaceCreationPermissionless",
  ].map((name) => [name, { value: bool }]),
  ["feeAuthority", { value: address }],
]);
const definitions = {
  proof,
  circuit,
  transact,
  merge,
  generalEvent,
  transactEvent,
  mergeEvent,
  nullifierTreeUpdateEvent: batchEvent,
  deposit: struct({ assets: vector(assetKind), deposits: vector(depositEntry) }),
  ringDeposit: struct({ assets: vector(assetKind), deposits: vector(ringDepositEntry) }),
};
const accountMeta = (name, isWritable = false, isSigner = false) =>
  n.instructionAccountNode({ name, isWritable, isSigner });
const metas = (entries) =>
  entries.map(([name, writable, signer]) => accountMeta(name, writable, signer));
const authorityConfig = [["authority", false, true], ["protocolConfig"]];
const transactPrefix = [
  ["payer", true, true],
  ["outputTree", true],
  ["sppProgram"],
  ["systemProgram"],
];
const depositPrefix = [
  ["tree", true],
  ["depositor", true, true],
];
const fees = struct({
  feePerNullifier: num("u64"),
  appendReimbursement: num("u64"),
  closeReimbursement: num("u64"),
});
const dynamicTransact =
  "Remaining accounts, in order: writable input trees (one per treeContexts entry), writable nullifier PDAs (one per input), owner signers, then settlement groups in interfaceTransfers order. SOL: interface, public account. SPL deposit: mint, interface, authority, user token, token program. SPL withdrawal: CPI authority, mint, interface, user token, token program.";
const dynamicDeposit =
  "Remaining accounts in assets order: SOL = system program, interface; SPL = token program, mint, user token, interface. Owner is a hash; viewTag is not a verified wallet address.";
const dynamicMerge =
  "Remaining accounts: one writable nullifier PDA per nullifier, in nullifiers order.";
const descriptions = [
  [
    "createProtocolConfig",
    createConfig,
    [
      ["payer", true, true],
      ["initializationAuthority", false, true],
      ["protocolConfig", true],
      ["systemProgram"],
      ["program"],
      ["programData"],
    ],
  ],
  [
    "updateProtocolConfig",
    updateConfig,
    [
      ["authority", false, true],
      ["protocolConfig", true],
    ],
  ],
  [
    "createTree",
    struct({
      treeId: num("u16"),
      nullifierParams: struct({
        inputQueueBatchSize: num("u64"),
        inputQueueZkpBatchSize: num("u64"),
        height: num("u32"),
      }),
      fees,
    }),
    [
      ["payer", true, true],
      ["authority", false, true],
      ["protocolConfig", true],
      ["tree", true],
      ["systemProgram"],
    ],
  ],
  [
    "pauseTree",
    struct({ paused: num("u8") }),
    [
      ["authority", false, true],
      ["protocolConfig", true],
      ["tree", true],
    ],
  ],
  ["setTreeFees", fees, [...authorityConfig, ["tree", true]]],
  ["claimTreeLamports", null, [...authorityConfig, ["tree", true], ["recipient", true]]],
  [
    "createAssetCounter",
    null,
    [["authority", true, true], ["protocolConfig"], ["assetCounter", true], ["systemProgram"]],
  ],
  [
    "createSplInterface",
    null,
    [
      ["authority", true, true],
      ["protocolConfig"],
      ["assetCounter", true],
      ["registryEntry", true],
      ["mint"],
      ["splInterface", true],
      ["systemProgram"],
      ["tokenProgram"],
    ],
  ],
  [
    "createRingConfig",
    struct({ programId: address, authority: address }),
    [["payer", true, true], ["protocolConfig"], ["ringConfig", true, true], ["systemProgram"]],
  ],
  [
    "updateRingConfig",
    struct({ paused: bool }),
    [
      ["authority", false, true],
      ["ringConfig", true],
    ],
  ],
  [
    "updateRingConfigOwner",
    null,
    [
      ["authority", false, true],
      ["ringConfig", true],
      ["newAuthority", false, true],
    ],
  ],
  [
    "setRingActivation",
    struct({ activated: num("u8"), ringAuthorityTransactIsEnabled: num("u8") }),
    [...authorityConfig, ["ringConfig", true]],
  ],
  [
    "batchUpdateNullifierTree",
    struct({ newRoot: bytes(32), oldRoot: bytes(32), zkpBatchIndex: num("u16"), proof }),
    [...authorityConfig, ["tree", true], ["reimbursementRecipient", true], ["sppProgram"]],
  ],
  [
    "closeNullifierPdas",
    null,
    [...authorityConfig, ["tree", true], ["reimbursementRecipient", true]],
    "Remaining accounts: writable nullifier PDAs to close.",
  ],
  [
    "emitEvent",
    event,
    [],
    "Unvalidated no-op. These schemas describe recognized event bodies. Decoding alone does not authenticate an event: require a successful state-changing SPP direct parent and the matching event kind.",
  ],
  ["deposit", link("deposit"), [...depositPrefix, ["sppProgram"]], dynamicDeposit],
  ["transact", link("transact"), transactPrefix, dynamicTransact],
  [
    "mergeTransact",
    link("merge"),
    [
      ["inputTree", true],
      ["outputTree", true],
      ["payer", true, true],
      ["userRecord"],
      ["systemProgram"],
      ["sppProgram"],
    ],
    dynamicMerge,
  ],
  [
    "ringDeposit",
    link("ringDeposit"),
    [...depositPrefix, ["ringConfig", false, true], ["sppProgram"]],
    dynamicDeposit,
  ],
  [
    "ringTransact",
    link("transact"),
    [...transactPrefix, ["ringConfig", false, true]],
    dynamicTransact,
  ],
  [
    "ringMergeTransact",
    struct({ outputRingDataHash: bytes(32), merge: link("merge") }),
    [
      ["inputTree", true],
      ["outputTree", true],
      ["ringConfig", false, true],
      ["payer", true, true],
      ["systemProgram"],
      ["sppProgram"],
    ],
    dynamicMerge,
  ],
  [
    "ringAuthorityTransact",
    link("transact"),
    [...transactPrefix, ["ringConfig", false, true]],
    dynamicTransact,
  ],
];
const instruction = ([name, type, accounts, docs = ""], tag) =>
  n.instructionNode({
    name,
    accounts: [
      ...metas(accounts),
      ...(["register", "updateKeys"].includes(name)
        ? [
            n.instructionAccountNode({
              name: "instructionsSysvar",
              isWritable: false,
              isSigner: false,
              isOptional: true,
              docs: ["Required when ownerP256 is present; omitted otherwise."],
            }),
          ]
        : []),
      ...(name === "updateProtocolConfig"
        ? [
            n.instructionAccountNode({
              name: "newAuthority",
              isWritable: false,
              isSigner: rotationRequiresSigner,
              isOptional: true,
              docs: [
                "Required only for ProtocolAuthority (variant 0); address must equal the instruction payload. Omitted for other updates.",
              ],
            }),
          ]
        : []),
    ],
    ...(["updateProtocolConfig", "register", "updateKeys"].includes(name)
      ? { optionalAccountStrategy: "omitted" }
      : {}),
    arguments: [
      n.instructionArgumentNode({
        name: "discriminator",
        type: num("u8"),
        defaultValue: n.numberValueNode(tag),
        defaultValueStrategy: "omitted",
      }),
      ...(type ? [n.instructionArgumentNode({ name: "data", type })] : []),
    ],
    discriminators: [n.fieldDiscriminatorNode("discriminator")],
    docs: [docs],
  });
const account = (name, tag, fields, size) =>
  n.accountNode({
    name,
    data: struct({ discriminator: num("u8"), ...fields }),
    ...(size ? { size } : {}),
    discriminators: [
      n.constantDiscriminatorNode(n.constantValueNode(num("u8"), n.numberValueNode(tag)), 0),
    ],
  });
const sppAccounts = [
  account(
    "protocolConfig",
    3,
    {
      protocolAuthority: address,
      treeCreationAuthority: address,
      foresterAuthority: address,
      ringCreationAuthority: address,
      feeAuthority: address,
      treeCreationIsPermissionless: num("u8"),
      ringActivationIsPermissionless: num("u8"),
      splInterfaceCreationIsPermissionless: num("u8"),
      nextTreeId: num("u16"),
    },
    166,
  ),
  account(
    "ringConfig",
    4,
    {
      authority: address,
      programId: address,
      ringAuthorityTransactIsEnabled: num("u8"),
      paused: num("u8"),
      activated: num("u8"),
      bump: num("u8"),
    },
    69,
  ),
  account("splAssetRegistry", 5, { reserved: bytes(7), mint: address, assetId: num("u64") }, 48),
  account("splAssetCounter", 6, { reserved: bytes(7), nextId: num("u64") }, 16),
];
const registryKeys = struct({
  ownerP256: option(bytes(33)),
  nullifierPubkey: bytes(32),
  viewingPubkey: bytes(33),
});
const registryAccounts = [
  ["userRecord", true],
  ["owner", false, true],
];
const registryInstructions = [
  [
    "register",
    registryKeys,
    [["userRecord", true], ["owner", true, true], ["systemProgram"]],
    "Instructions sysvar is appended when ownerP256 is present.",
  ],
  ["setMergingEnabled", struct({ enabled: bool }), registryAccounts],
  [
    "updateKeys",
    registryKeys,
    registryAccounts,
    "Instructions sysvar is appended when ownerP256 is present.",
  ],
];
const sourcePaths = [
  "program-libs/interface/src/instruction/builders/protocol_config/mod.rs",
  "program-libs/interface/src/instruction/builders/ring_config/mod.rs",
  "program-libs/interface/src/instruction/builders/create_tree.rs",
  "program-libs/interface/src/instruction/builders/create_asset_counter.rs",
  "program-libs/interface/src/instruction/builders/create_spl_interface.rs",
  "program-libs/interface/src/instruction/builders/close_nullifier_pdas.rs",
  "program-libs/interface/src/instruction/builders/batch_update_nullifier_tree.rs",
  "program-libs/interface/src/instruction/builders/transact.rs",
  "program-libs/interface/src/instruction/builders/deposit.rs",
  "program-libs/interface/src/instruction/builders/ring_deposit.rs",
  "program-libs/interface/src/instruction/builders/ring_transact.rs",
  "program-libs/interface/src/instruction/builders/ring_authority_transact.rs",
  "program-libs/interface/src/instruction/builders/merge_transact.rs",
  "program-libs/interface/src/instruction/builders/merge_ring.rs",

  "program-libs/tree/src/fees.rs",
  "program-libs/tree/src/nullifier_tree/init.rs",
  "program-libs/tree/src/nullifier_tree/merkle_tree_update.rs",
  "program-libs/interface/src/instruction/instruction_data/create_tree.rs",
  "program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs",
  "program-libs/event/src/tag.rs",
  "programs/shielded-pool/src/instructions/protocol_config/update.rs",
  "program-libs/event/src/lib.rs",
  "program-libs/event/src/proofless.rs",
  "program-libs/interface/src/instruction/instruction_data/transact.rs",
  "program-libs/interface/src/instruction/instruction_data/deposit.rs",
  "program-libs/interface/src/instruction/instruction_data/merge_transact.rs",
  "program-libs/interface/src/instruction/instruction_data/merge_ring.rs",
  "program-libs/interface/src/instruction/instruction_data/protocol_config.rs",
  "program-libs/interface/src/instruction/instruction_data/ring_config.rs",
  "program-libs/interface/src/verifying_keys/circuit.rs",
  "program-libs/interface/src/error.rs",
  "program-libs/interface/src/state/protocol_config.rs",
  "program-libs/interface/src/state/ring_config.rs",
  "program-libs/interface/src/state/spl_asset_registry.rs",
  "program-libs/interface/src/state/spl_asset_counter.rs",
  "program-libs/user-registry-interface/src/instruction.rs",
  "program-libs/user-registry-interface/src/state.rs",
  "programs/user-registry/src/error.rs",
  "program-libs/interface/src/lib.rs",
  "program-libs/user-registry-interface/src/lib.rs",
  "sdk-libs/ts/src/interface/program.ts",
];
const sources = Object.fromEntries(
  await Promise.all(
    sourcePaths.map(async (path) => [
      path,
      createHash("sha256")
        .update(await read(path))
        .digest("hex"),
    ]),
  ),
);
const idsSource = await read("sdk-libs/ts/src/interface/program.ts");
const ids = Object.fromEntries(
  [
    ...idsSource.matchAll(
      /export const (SHIELDED_POOL_PROGRAM_ID|USER_REGISTRY_PROGRAM_ID) = address\("([^"]+)"\)/g,
    ),
  ].map((m) => [m[1], m[2]]),
);
const tags = [
  ...(await read("program-libs/event/src/tag.rs")).matchAll(/pub const ([A-Z_]+): u8 = (\d+);/g),
];
for (const [constant, path] of [
  ["SHIELDED_POOL_PROGRAM_ID", "program-libs/interface/src/lib.rs"],
  ["USER_REGISTRY_PROGRAM_ID", "program-libs/user-registry-interface/src/lib.rs"],
]) {
  if (!(await read(path)).includes(`pubkey_array!("${ids[constant]}")`))
    throw new Error(`Rust and SDK program ID mismatch: ${constant}`);
}
if (
  tags.length !== descriptions.length ||
  tags.some((m, i) => Number(m[2]) !== i || n.camelCase(m[1].toLowerCase()) !== descriptions[i][0])
)
  throw new Error("Instruction tags drifted; update schema and Rust fixtures.");
const registryTags = [
  ...(await read("program-libs/user-registry-interface/src/instruction.rs")).matchAll(
    /pub const ([A-Z_]+): u8 = (\d+);/g,
  ),
];
if (
  registryTags.length !== registryInstructions.length ||
  registryTags.some(
    (m, i) => Number(m[2]) !== i || n.camelCase(m[1].toLowerCase()) !== registryInstructions[i][0],
  )
)
  throw new Error("Registry tags drifted; update schema and Rust fixtures.");
const sppErrors = [
  ...(await read("program-libs/interface/src/error.rs")).matchAll(
    /#\[error\("([^"]+)"\)\]\s+(\w+) = (\d+),/g,
  ),
].map((m) => n.errorNode({ name: m[2], code: Number(m[3]), message: m[1] }));
const registryErrors = [
  ...(await read("programs/user-registry/src/error.rs")).matchAll(
    /#\[error\("([^"]+)"\)\]\s+(\w+),/g,
  ),
].map((m, code) => n.errorNode({ name: m[2], code, message: m[1] }));
const idls = {
  shieldedPool: n.rootNode(
    n.programNode({
      name: "shieldedPool",
      publicKey: ids.SHIELDED_POOL_PROGRAM_ID,
      version: "0.1.0",
      instructions: descriptions.map(instruction),
      accounts: sppAccounts,
      definedTypes: Object.entries(definitions).map(([name, type]) =>
        n.definedTypeNode({ name, type }),
      ),
      errors: sppErrors,
      docs: [
        "Native Pinocchio program. Custom wincode instructions and Borsh self-CPI events. Tree internals intentionally omitted; configuration and asset accounts are described.",
      ],
    }),
  ),
  userRegistry: n.rootNode(
    n.programNode({
      name: "userRegistry",
      publicKey: ids.USER_REGISTRY_PROGRAM_ID,
      version: "0.1.0",
      instructions: registryInstructions.map(instruction),
      accounts: [
        n.accountNode({
          name: "userRecord",
          size: 134,
          data: n.fixedSizeTypeNode(
            struct({
              discriminator: num("u8"),
              owner: address,
              bump: num("u8"),
              ownerP256: option(bytes(33)),
              nullifierPubkey: bytes(32),
              viewingPubkey: bytes(33),
              mergingEnabled: bool,
            }),
            134,
          ),
          discriminators: [
            n.constantDiscriminatorNode(n.constantValueNode(num("u8"), n.numberValueNode(1)), 0),
          ],
          docs: [
            "Borsh body padded to 134 bytes; ownerP256 None shortens the body, not the allocated account.",
          ],
        }),
      ],
      errors: registryErrors,
    }),
  ),
};
for (const idl of Object.values(idls)) {
  const problems = visit(idl, getValidationItemsVisitor()).filter((item) => item.level === "error");
  if (problems.length) throw new Error(JSON.stringify(problems));
}
const manifest = {
  schemaVersion: "1",
  sourceCommit: JSON.parse(await read("sdk-libs/ts/fixtures/idl/rust.json")).sourceCommit,
  sources,
  programs: Object.fromEntries(
    Object.entries(idls).map(([name, idl]) => [
      name,
      {
        address: idl.program.publicKey,
        sha256: createHash("sha256").update(JSON.stringify(idl)).digest("hex"),
      },
    ]),
  ),
};
const writeOutput = async (path, value) => {
  const formatted = await format(path, value);
  if (formatted.errors.length) throw new Error(JSON.stringify(formatted.errors));
  value = formatted.code;
  if (check) {
    if ((await read(path)) !== value) throw new Error(`Generated artifact drift: ${path}`);
  } else {
    await mkdir(new URL(".", new URL(path, root)), { recursive: true });
    await writeFile(new URL(path, root), value);
  }
};
for (const [name, idl] of Object.entries(idls))
  await writeOutput(`sdk-libs/ts/idl/${name}.json`, `${JSON.stringify(idl, null, 2)}\n`);
await writeOutput("sdk-libs/ts/idl/manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
console.log(
  check ? "IDLs match source and pass Codama validation." : "Generated and validated IDLs.",
);
