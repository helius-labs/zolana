export const packageConfigurations = {
  interface: {
    entryPoints: [".", "./pda", "./codecs", "./instructions"],
    dependencies: [],
    browser: true,
  },
  keypair: {
    entryPoints: [".", "./merge", "./hash"],
    dependencies: ["@noble/ciphers", "@noble/curves", "@noble/ed25519", "@noble/hashes", "bs58"],
    browserDependencies: [
      "@noble/ciphers/webcrypto.js",
      "@noble/curves/abstract/poseidon.js",
      "@noble/curves/nist.js",
      "@noble/ed25519",
      "@noble/hashes/hkdf.js",
      "@noble/hashes/sha2.js",
      "bs58",
    ],
    browser: true,
  },
  transaction: {
    entryPoints: [".", "./serialization", "./instructions", "./wallet"],
    dependencies: ["@zolana/interface", "@zolana/keypair"],
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
    entryPoints: [".", "./prover"],
    dependencies: [
      "@zolana/api",
      "@zolana/indexer-api",
      "@zolana/interface",
      "@zolana/keypair",
      "@zolana/transaction",
    ],
    browser: true,
  },
  wallet: {
    entryPoints: [".", "./authority", "./registry", "./actions", "./sync"],
    dependencies: ["@zolana/client", "@zolana/interface", "@zolana/keypair", "@zolana/transaction"],
    browser: true,
  },
  "merkle-tree": {
    entryPoints: ["."],
    dependencies: ["@noble/curves", "@noble/hashes", "@zolana/interface"],
    browserDependencies: [
      "@noble/curves/abstract/poseidon.js",
      "@noble/hashes/sha2.js",
      "@noble/hashes/sha3.js",
    ],
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
