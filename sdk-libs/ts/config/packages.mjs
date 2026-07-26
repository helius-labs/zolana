export const packageConfigurations = {
  hasher: {
    entryPoints: [".", "./slim"],
    // The compiled artifact as a file, for consumers who can load one and
    // would rather not download the base64 that expands to it. Not an entry
    // point: nothing imports it, and the browser and packing checks would try
    // to bundle it as JavaScript if it were listed as one.
    assets: { "./poseidon.wasm": "./dist/poseidon.wasm" },
    dependencies: [],
    browser: true,
  },
  interface: {
    entryPoints: [".", "./pda", "./codecs", "./instructions"],
    dependencies: ["@noble/curves", "@zolana/hasher"],
    browserDependencies: ["@noble/curves/abstract/modular.js"],
    browser: true,
  },
  keypair: {
    entryPoints: [".", "./merge", "./hash", "./traits"],
    dependencies: [
      "@noble/ciphers",
      "@noble/curves",
      "@noble/ed25519",
      "@noble/hashes",
      "@zolana/hasher",
      "@zolana/interface",
      "bs58",
    ],
    browserDependencies: [
      "@noble/ciphers/webcrypto.js",
      "@noble/curves/nist.js",
      "@noble/ed25519",
      "@noble/hashes/hkdf.js",
      "@noble/hashes/sha2.js",
      "@zolana/interface",
      "bs58",
    ],
    browser: true,
  },
  transaction: {
    entryPoints: [".", "./serialization", "./instructions", "./transact", "./wallet"],
    dependencies: [
      "@noble/curves",
      "@noble/hashes",
      "@zolana/hasher",
      "@zolana/interface",
      "@zolana/keypair",
    ],
    browser: true,
  },
  "indexer-api": {
    entryPoints: [".", "./methods"],
    dependencies: ["@zolana/interface"],
    browser: true,
  },
  api: {
    entryPoints: ["."],
    dependencies: ["@zolana/indexer-api", "@zolana/interface"],
    browser: true,
  },
  client: {
    entryPoints: [".", "./prover", "./retry"],
    dependencies: [
      "@zolana/api",
      "@zolana/hasher",
      "@zolana/indexer-api",
      "@zolana/interface",
      "@zolana/keypair",
      "@zolana/transaction",
    ],
    browser: true,
  },
  wallet: {
    entryPoints: [".", "./authority", "./registry", "./actions", "./sync"],
    dependencies: [
      "@zolana/client",
      "@zolana/hasher",
      "@zolana/interface",
      "@zolana/keypair",
      "@zolana/transaction",
    ],
    browser: true,
  },
  "merkle-tree": {
    entryPoints: ["."],
    dependencies: ["@noble/curves", "@noble/hashes", "@zolana/hasher", "@zolana/interface"],
    browserDependencies: ["@noble/hashes/sha2.js", "@noble/hashes/sha3.js"],
    browser: true,
  },
  "smart-account-client": {
    entryPoints: ["."],
    dependencies: ["@zolana/interface"],
    browser: true,
  },
  "test-kit": {
    entryPoints: [".", "./node", "./fixtures"],
    dependencies: [
      "@zolana/api",
      "@zolana/client",
      "@zolana/indexer-api",
      "@zolana/interface",
      "@zolana/keypair",
      "@zolana/merkle-tree",
      "@zolana/smart-account-client",
      "@zolana/transaction",
      "@zolana/wallet",
    ],
    browser: false,
  },
};

export const packageNames = Object.keys(packageConfigurations);

export const productionPackageNames = packageNames.filter(
  (packageName) => packageName !== "test-kit",
);

export const browserEntryPoints = Object.fromEntries(
  Object.entries(packageConfigurations)
    .filter(([, configuration]) => configuration.browser)
    .map(([packageName, configuration]) => [packageName, configuration.entryPoints]),
);

export const browserDependencyEntryPoints = [
  ...new Set(
    Object.values(packageConfigurations).flatMap(
      (configuration) => configuration.browserDependencies ?? [],
    ),
  ),
];
