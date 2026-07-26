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
    dependencies: ["@zolana/hasher", "bs58"],
    browserDependencies: ["bs58"],
    browser: true,
  },
  keypair: {
    entryPoints: [".", "./merge", "./hash", "./traits"],
    dependencies: [
      "@noble/ciphers",
      "@noble/curves",
      "@noble/hashes",
      "@zolana/hasher",
      "@zolana/interface",
    ],
    browserDependencies: [
      "@noble/ciphers/webcrypto.js",
      "@noble/curves/nist.js",
      "@noble/hashes/hkdf.js",
      "@noble/hashes/sha2.js",
      "@zolana/interface",
    ],
    browser: true,
  },
  transaction: {
    entryPoints: [".", "./serialization", "./instructions", "./transact", "./wallet"],
    dependencies: ["@noble/hashes", "@zolana/hasher", "@zolana/interface", "@zolana/keypair"],
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
      "@noble/hashes",
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
    dependencies: ["@zolana/client", "@zolana/interface", "@zolana/keypair", "@zolana/transaction"],
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
    dependencies: ["@noble/hashes", "@zolana/interface"],
    browserDependencies: ["@noble/hashes/sha2.js"],
    browser: true,
  },
  kit: {
    entryPoints: [".", "./instructions"],
    dependencies: ["@zolana/client", "@zolana/interface"],
    // Optional peer so consumers that skip Kit do not download it.
    peerDependencies: ["@solana/kit"],
    browser: true,
  },
  zolana: {
    entryPoints: [".", "./kit"],
    dependencies: [
      "@zolana/client",
      "@zolana/interface",
      "@zolana/keypair",
      "@zolana/kit",
      "@zolana/transaction",
      "@zolana/wallet",
    ],
    // Published as `@helius/zolana`; Kit stays behind the `./kit` entry.
    publishedName: "@helius/zolana",
    // `./kit` re-exports `@zolana/kit`, so its consumer typecheck needs Kit's
    // optional peer types without declaring those peers on the umbrella root.
    peerBackedEntryPoints: ["./kit"],
    browser: true,
  },
  "test-kit": {
    entryPoints: [".", "./node", "./fixtures"],
    dependencies: [
      "@zolana/api",
      "@zolana/client",
      "@zolana/interface",
      "@zolana/keypair",
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
