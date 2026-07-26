import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import oracle from "../oracles/transaction-parity-v1.json" with { type: "json" };

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src");

async function sourceFiles(directory: string): Promise<readonly string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await sourceFiles(full)));
    else if (entry.name.endsWith(".ts")) files.push(full);
  }
  return files;
}

/** `@zolana/transaction` entry point to the barrel file that defines it. */
const ENTRY_POINT_SOURCES: Readonly<Record<string, string>> = {
  ".": "index.ts",
  "./serialization": "serialization/index.ts",
  "./wallet": "wallet/index.ts",
  "./instructions": "instructions/index.ts",
  "./transact": "transact/index.ts",
};

/**
 * Names this package spells differently from Rust on purpose.
 * `IndexedShieldedTransaction` leaves the unqualified name to
 * `@zolana/indexer-api`, and the rest drop a prefix the SDK vocabulary avoids
 * or trade a Rust `impl` block for a construction function.
 *
 * A rename recorded here asserts the two names denote the same behaviour, so
 * an entry is a claim rather than a spelling note. `decrypt_transactions` sat
 * here while `decryptTransactions` was in fact `Wallet::sync`, which is how a
 * mismatched pair stayed hidden; the two are a genuine pair now and need no
 * entry, because the camel-case rule already maps them.
 */
const RENAMES: Readonly<Record<string, string>> = {
  AnonymousTransferRecipientPlaintext: "AnonymousRecipientPlaintext",
  AnonymousTransferSenderPlaintext: "AnonymousSenderPlaintext",
  DecodeCx: "DecodeContext",
  OwnerCx: "OwnerContext",
  ShieldedTransaction: "IndexedShieldedTransaction",
  SppProofOutputUtxo: "ProofOutputUtxo",
  SyncConfig: "WalletSyncConfig",
  // Rust's `Sync` prefix marks the blocking form of WalletAuthority. TypeScript
  // has no blocking form, and this is the narrower sync-material capability, so
  // the name reads as "authority for wallet sync" instead.
  SyncWalletAuthority: "WalletSyncAuthority",
  asset_field: "assetField",
  derive_blinding: "deriveBlinding",
  owner_utxo_hash: "ownerUtxoHash",
};

function camelCase(name: string): string {
  return name.replace(/_([a-z])/gu, (_, letter: string) => letter.toUpperCase());
}

/** The TypeScript name a Rust name ships under, before any disposition. */
function tsName(rustName: string): string {
  return RENAMES[rustName] ?? (/^[A-Z0-9_]+$/u.test(rustName) ? rustName : camelCase(rustName));
}

/**
 * Rust names an entry point deliberately does not carry, each with the reason.
 * Three kinds appear: a name another `@zolana` package owns, a Rust language
 * mechanic with no TypeScript analogue, and a Rust shape whose TypeScript
 * equivalent is an ordinary parameter, array, or property.
 */
const NOT_CARRIED: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  ".": {
    Address: "@zolana/interface owns Address; re-exporting it would give the type two homes",
    ProofInputUtxo:
      "the Poseidon-field hash preimage; TypeScript folds hashing through SppProofInputUtxo and does not ship the field form",
    UtxoSerialization:
      "a Rust trait has to be in scope for Confidential::decode to resolve, and it is never a bound or a dyn; the per-scheme functions below need no such contract",
    decrypt_transactions_with_config:
      "decryptTransactions takes the config as an optional parameter, so one function covers both Rust entry points",
  },
  "./serialization": {
    Proofless:
      "a unit struct carrying an impl block; its operations ship as the proofless functions pinned below",
    ProoflessEncode:
      "an empty encode context; the TypeScript proofless encoder takes no context argument",
    Split:
      "a unit struct carrying an impl block; its operations ship as the split functions pinned below",
    UtxoSerialization:
      "a Rust trait has to be in scope for Split::decode to resolve, and it is never a bound or a dyn; the per-scheme functions below need no such contract",
  },
  "./wallet": {
    decrypt_transactions_with_config:
      "decryptTransactions takes the config as an optional parameter, so one function covers both Rust entry points",
  },
  "./instructions": {},
  "./transact": {
    ConfidentialSplit: "reached through @zolana/transaction and @zolana/transaction/instructions",
    EncryptedTransactionData:
      "the return shape of encrypt_transaction_data, which LocalWalletAuthority.encryptConfidentialTransfer owns here",
    PreparedSplit: "reached through @zolana/transaction and @zolana/transaction/instructions",
    PrivateTxHash:
      "a struct whose only method is hash(); the function privateTxHash and its PrivateTxHashInput carry it",
    Recipient: "a Rust-internal transfer shape; the send parameters carry it here",
    Withdrawal: "a Rust-internal transfer shape; WithdrawalTarget carries it here",
    encrypt_transaction_data:
      "LocalWalletAuthority.encryptConfidentialTransfer owns slot encryption here",
    first_nullifier: "PreparedTransfer.firstNullifier and PreparedSplit.firstNullifier carry it",
    get_transaction_viewing_key:
      "@zolana/keypair owns it as ViewingKey.transactionViewingKey(firstNullifier)",
    inputs_require_p256: "ConfidentialTransfer.requiresP256Owner() carries it",
  },
};

/**
 * Exports with no Rust counterpart anywhere in the module tree the entry point
 * mirrors, each with the reason it ships.
 */
const TYPESCRIPT_ONLY: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  ".": {
    ExternalDataInit: "the named argument object createExternalData takes",
    PrivateTxHashInput: "the named argument object privateTxHash takes",
    ProofOutputInit: "the named argument object createProofOutput takes",
    TRANSACTION_ERROR_CODES: "the frozen TransactionError code set as a runtime value",
    TransactionErrorCause: "the structured cause Rust models with error enum payloads",
    TransactionErrorCode: "the TransactionError code union",
    TransactionErrorDetails: "the fail-closed allow-listed detail bag",
    TransactionErrorValue: "string | number values admitted into error details",
    UtxoInit: "the named argument object the Utxo constructor takes",
    authorityError: "constructs the authority cause category",
    createEncryptedTransaction: "EncryptedTransaction::new, which has no impl block here",
    createExternalData: "ExternalData::new, which has no impl block here",
    createInputUtxo: "InputUtxo::new, which has no impl block here",
    createProofOutput: "SppProofOutputUtxo::new, which has no impl block here",
    initializePoseidon:
      "loads the compiled Poseidon, which Rust links rather than instantiates at runtime",
    isPoseidonInitialized: "reports whether the compiled Poseidon has been loaded",
    outputDataEncoding: "the OutputDataEncoding discriminant, which zolana_event owns in Rust",
    prepareZoneAuthority: "PreparedZoneAuthority::new, which has no impl block here",
    privateTxHash: "PrivateTxHash::hash as a function",
    syncWalletWithAuthority:
      "Wallet::sync, a free function because Wallet is declared in state.ts, and qualified because @zolana/wallet carries Rust's sync_wallet under the plain name",
    syncWalletWithMaterial: "Wallet::sync_with_material, a free function for the same reason",
    transactionError: "constructs a TransactionError with structured details",
    unknownTransactionError: "wraps a thrown value of unknown shape",
    CounterpartyCounter: "one entry of the HashMap ViewingKeyEntry keeps its counters in",
    OutputDataEncoding: "the OutputDataEncoding discriminant, which zolana_event owns in Rust",
    decodeContextForSlot: "DecodeCx::for_slot, which has no impl block here",
    encryptedSchemeFromByte: "EncryptedScheme::from_byte, which has no impl block here",
    encryptedSchemeToByte: "EncryptedScheme::to_byte, which has no impl block here",
  },
  "./serialization": {
    ProoflessOutput:
      "Rust reuses zolana_event::ProoflessOutput; no @zolana/event package exists, so the shape is defined here",
    encryptedSchemeFromByte: "EncryptedScheme::from_byte, which has no impl block here",
    encryptedSchemeToByte: "EncryptedScheme::to_byte, which has no impl block here",
    outputDataEncoding: "the OutputDataEncoding discriminant, which zolana_event owns in Rust",
    OutputDataEncoding: "the OutputDataEncoding discriminant, which zolana_event owns in Rust",
    decodeData: "Data::deserialize, which has no impl block here",
    encodeData: "Data::serialize, which has no impl block here",
    decodeOutputData: "the borsh OutputDataEncoding reader zolana_event owns in Rust",
    encodeOutputData: "the borsh OutputDataEncoding writer zolana_event owns in Rust",
    decryptConfidentialAsSender:
      "the sender's own view of a slot, which Rust reaches through ViewingKey directly",
    decodeSplitEncrypted: "the split envelope reader Rust folds into Split::decrypt",
    encodeSplitEncrypted: "the split envelope writer Rust folds into Split::encrypt",
    decodeContextForSlot: "DecodeCx::for_slot, which has no impl block here",
  },
  "./wallet": {
    CounterpartyCounter: "one entry of the HashMap ViewingKeyEntry keeps its counters in",
    SplitBundlePlaintext: "the split payload LocalWalletAuthority.encryptSplit takes",
    syncWalletWithAuthority:
      "Wallet::sync, a free function because Wallet is declared in state.ts, and qualified because @zolana/wallet carries Rust's sync_wallet under the plain name",
    syncWalletWithMaterial: "Wallet::sync_with_material, a free function for the same reason",
    syncWalletWorkerEquivalent:
      "the serial stand-in for wallet::parallel that T16 owns, exported so the alias is declared rather than silent",
  },
  "./instructions": {
    PrivateTxHashInput: "the named argument object privateTxHash takes",
    ExternalDataInit: "the named argument object createExternalData takes",
    ProofOutputInit: "the named argument object createProofOutput takes",
    createEncryptedTransaction: "EncryptedTransaction::new, which has no impl block here",
    createExternalData: "ExternalData::new, which has no impl block here",
    createInputUtxo: "InputUtxo::new, which has no impl block here",
    createProofOutput: "SppProofOutputUtxo::new, which has no impl block here",
    prepareZoneAuthority: "PreparedZoneAuthority::new, which has no impl block here",
    privateTxHash: "PrivateTxHash::hash as a function",
  },
  "./transact": {
    ExternalDataInit: "the named argument object createExternalData takes",
    PrivateTxHashInput: "the named argument object privateTxHash takes",
    createEncryptedTransaction: "EncryptedTransaction::new, which has no impl block here",
    createExternalData: "ExternalData::new, which has no impl block here",
    createInputUtxo: "InputUtxo::new, which has no impl block here",
    privateTxHash: "PrivateTxHash::hash as a function",
    InputUtxoContext: "flattened from instructions::types, which ./instructions also carries",
  },
};

/**
 * Every name a barrel or a shipped declaration file publishes, and whether it
 * survives to run time. Both halves matter: a re-export block carries most of
 * the surface, and the root also declares its own constants inline. The kind
 * matters because a name that turns into a type-only export still matches the
 * Rust oracle while breaking every consumer that called it.
 */
function declaredExports(source: string): ReadonlyMap<string, "value" | "type"> {
  const kinds = new Map<string, "value" | "type">();
  for (const [, blockMarker, block] of source.matchAll(/export\s+(type\s+)?\{([^}]*)\}/gu)) {
    for (const specifier of block.split(",")) {
      const trimmed = specifier.trim();
      if (trimmed.length === 0) continue;
      const name = trimmed
        .replace(/^type\s+/u, "")
        .split(/\s+as\s+/u)
        .at(-1);
      if (name === undefined) continue;
      kinds.set(name, blockMarker !== undefined || /^type\s/u.test(trimmed) ? "type" : "value");
    }
  }
  for (const [, keyword, name] of source.matchAll(
    /^export\s+(?:declare\s+)?(?:abstract\s+)?(const|let|var|function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/gmu,
  )) {
    kinds.set(name, keyword === "interface" || keyword === "type" ? "type" : "value");
  }
  return kinds;
}

function valueNames(kinds: ReadonlyMap<string, "value" | "type">): readonly string[] {
  return [...kinds]
    .filter(([, kind]) => kind === "value")
    .map(([name]) => name)
    .sort();
}

interface ModuleSurface {
  readonly entryPoint: string;
  readonly modules: readonly string[];
  readonly names: readonly string[];
  readonly submoduleNames: readonly string[];
}

const surfaces: Readonly<Record<string, ModuleSurface>> = oracle.moduleSurfaces;

const sources = new Map<string, string>();

async function shipped(entryPoint: string): Promise<ReadonlySet<string>> {
  const file = ENTRY_POINT_SOURCES[entryPoint];
  if (file === undefined) throw new Error(`no barrel recorded for ${entryPoint}`);
  let source = sources.get(file);
  if (source === undefined) {
    source = await readFile(path.join(sourceRoot, file), "utf8");
    sources.set(file, source);
  }
  return new Set(declaredExports(source).keys());
}

/**
 * The `UtxoSerialization` operations, per scheme. The trait itself is
 * dispositioned above as a Rust language mechanic, so this is where the
 * capability behind it is pinned: every operation Rust offers for a scheme has
 * to name a shipped function or say why the cell is empty. The trait's
 * `decode`, `encode`, and `encode_plaintext` defaults are compositions of the
 * cells beside them and are listed in COMPOSED_OPERATIONS instead.
 */
const SCHEME_OPERATIONS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  AnonymousRecipient: {
    decrypt: "decryptAnonymous",
    deserialize: "decodeAnonymousRecipient",
    into_utxos: "anonymousRecipientUtxo",
    from_utxos: "anonymousRecipientFromUtxos",
    serialize: "encodeAnonymousRecipient",
    encrypt: "encryptAnonymous",
  },
  AnonymousSenderBundle: {
    decrypt: "decryptAnonymous",
    deserialize: "decodeAnonymousSender",
    into_utxos: "anonymousSenderUtxos",
    from_utxos: "anonymousSenderFromUtxos",
    serialize: "encodeAnonymousSender",
    encrypt: "encryptAnonymous",
  },
  Confidential: {
    decrypt: "decryptConfidential",
    deserialize: "decodeConfidential",
    into_utxos: "confidentialUtxo",
    from_utxos: "confidentialPlaintextFromUtxo",
    serialize: "encodeConfidential",
    encrypt: "encryptConfidential",
  },
  Merge: {
    decrypt: "decryptMerge",
    deserialize: "decodeMerge",
    into_utxos: "mergeUtxo",
    from_utxos: "mergePlaintextFromUtxo",
    serialize: "encodeMerge",
    encrypt: "encryptMerge",
  },
  PlaintextTransfer: {
    decrypt: "",
    deserialize: "decodePlaintextTransfer",
    into_utxos: "plaintextTransferUtxos",
    from_utxos: "plaintextTransferFromUtxos",
    serialize: "encodePlaintextTransfer",
    encrypt: "",
  },
  Proofless: {
    decrypt: "",
    deserialize: "decodeProofless",
    into_utxos: "prooflessUtxo",
    from_utxos: "prooflessFromUtxos",
    serialize: "encodeProofless",
    encrypt: "",
  },
  Split: {
    decrypt: "decryptSplit",
    deserialize: "decodeSplitBundle",
    into_utxos: "splitBundleUtxos",
    from_utxos: "splitBundleFromUtxos",
    serialize: "encodeSplitBundle",
    encrypt: "encryptSplit",
  },
};

/**
 * The two plaintext rails publish their bytes unencrypted, so Rust's `decrypt`
 * and `encrypt` are the identity and no TypeScript function stands for them.
 */
const IDENTITY_CRYPTO: readonly string[] = ["PlaintextTransfer", "Proofless"];

/**
 * Cells this package does not ship yet, each naming the row that owns it. The
 * assertion below inverts for these, so shipping the function without clearing
 * the entry fails: an absence stays declared only while it is true.
 *
 * Empty since the two plaintext-rail read halves were extracted out of wallet
 * sync as `plaintextTransferUtxos` and `prooflessUtxo`. They were recorded
 * absent on the belief that the inline versions skipped Rust's
 * `resolve_zone_program_id`; the inline versions in fact reached the same
 * refusal through a `Utxo` constructor invariant Rust does not have, which
 * diverged on the two inputs Rust treats differently.
 */
const ABSENT_OPERATIONS: Readonly<Record<string, string>> = {};

/** Trait defaults a caller composes here from the two halves beside them. */
const COMPOSED_OPERATIONS: readonly string[] = ["decode", "encode", "encode_plaintext"];

const schemeFunctions = new Set(
  Object.values(SCHEME_OPERATIONS)
    .flatMap((table) => Object.values(table))
    .filter((name) => name !== ""),
);

describe("Rust-generated aggregate module surfaces", () => {
  it("covers exactly the five aggregate modules", () => {
    expect(Object.keys(surfaces).sort()).toEqual([
      "src/instructions/mod.rs",
      "src/instructions/transact/mod.rs",
      "src/lib.rs",
      "src/serialization/mod.rs",
      "src/wallet/mod.rs",
    ]);
    expect(
      Object.values(surfaces)
        .map((surface) => surface.entryPoint)
        .sort(),
    ).toEqual(Object.keys(ENTRY_POINT_SOURCES).sort());
  });

  for (const [rustPath, surface] of Object.entries(surfaces)) {
    const { entryPoint } = surface;

    it(`${entryPoint} carries or dispositions every name ${rustPath} publishes`, async () => {
      const notCarried = NOT_CARRIED[entryPoint] ?? {};
      const exports = await shipped(entryPoint);

      const stale = Object.keys(notCarried).filter((name) => !surface.names.includes(name));
      expect(stale, "a dispositioned name left the Rust module").toEqual([]);

      const missing = surface.names
        .filter((name) => !(name in notCarried))
        .filter((name) => !exports.has(tsName(name)))
        .map((name) => `${name} -> ${tsName(name)}`);
      expect(missing).toEqual([]);

      const contradictory = Object.keys(notCarried).filter((name) => exports.has(tsName(name)));
      expect(contradictory, "a dispositioned name ships anyway").toEqual([]);
    });

    it(`${entryPoint} explains every export ${rustPath} does not publish`, async () => {
      const only = TYPESCRIPT_ONLY[entryPoint] ?? {};
      const exports = await shipped(entryPoint);
      // A barrel flattens what Rust leaves behind a `pub mod`, and the
      // serialization barrel also flattens the trait methods, so a shipped
      // export is accounted for by any of the three.
      const accounted = new Set([
        ...surface.names.map(tsName),
        ...surface.submoduleNames.map(tsName),
        ...(entryPoint === "./serialization" || entryPoint === "." ? schemeFunctions : []),
      ]);

      const unexplained = [...exports].filter((name) => !accounted.has(name) && !(name in only));
      expect(unexplained).toEqual([]);

      const stale = Object.keys(only).filter((name) => !exports.has(name));
      expect(stale, "a recorded TypeScript-only export no longer ships").toEqual([]);
    });
  }
});

describe("UtxoSerialization capability contract", () => {
  it("names a shipped function for every operation of every scheme", async () => {
    const exports = await shipped("./serialization");
    const implementors: readonly { type: string; schemeByte: number }[] =
      oracle.utxoSerialization.implementors;
    const operations: readonly string[] = oracle.utxoSerialization.operations;

    expect(Object.keys(SCHEME_OPERATIONS).sort()).toEqual(
      implementors.map((entry) => entry.type).sort(),
    );

    const direct = [...operations]
      .filter((operation) => !COMPOSED_OPERATIONS.includes(operation))
      .sort();
    for (const implementor of implementors) {
      const table = SCHEME_OPERATIONS[implementor.type] ?? {};
      expect(Object.keys(table).sort(), `${implementor.type} operations`).toEqual(direct);
      for (const [operation, name] of Object.entries(table)) {
        if (name === "") {
          expect(
            IDENTITY_CRYPTO,
            `${implementor.type}.${operation} has no function and no recorded reason`,
          ).toContain(implementor.type);
          continue;
        }
        const absence = ABSENT_OPERATIONS[`${implementor.type}.${operation}`];
        if (absence !== undefined) {
          expect(
            exports,
            `${implementor.type}.${operation} is recorded absent but ${name} ships; drop the ABSENT_OPERATIONS entry`,
          ).not.toContain(name);
          continue;
        }
        expect(exports, `${implementor.type}.${operation} must ship as ${name}`).toContain(name);
      }
    }
  });
});

/** The entry point specifier a consumer resolves, per barrel. */
const ENTRY_POINT_SPECIFIERS: Readonly<Record<string, string>> = {
  ".": "@zolana/transaction",
  "./serialization": "@zolana/transaction/serialization",
  "./wallet": "@zolana/transaction/wallet",
  "./instructions": "@zolana/transaction/instructions",
  "./transact": "@zolana/transaction/transact",
};

/**
 * The two halves of the export allowlist the source checks above cannot reach:
 * what the built package hands a consumer at run time, and what its shipped
 * declarations promise. Both read the build rather than the sources beside it,
 * so they need `npm run build` first, as every suite in this workspace does.
 */
async function builtModule(specifier: string): Promise<Readonly<Record<string, unknown>>> {
  return (await import(specifier)) as Readonly<Record<string, unknown>>;
}

describe("built entry-point surface", () => {
  for (const [entryPoint, specifier] of Object.entries(ENTRY_POINT_SPECIFIERS)) {
    const stem = entryPoint === "." ? "index" : `${entryPoint.slice(2)}/index`;

    it(`${entryPoint} exports exactly its barrel's value names at run time`, async () => {
      const file = ENTRY_POINT_SOURCES[entryPoint];
      if (file === undefined) throw new Error(`no barrel recorded for ${entryPoint}`);
      const barrel = declaredExports(await readFile(path.join(sourceRoot, file), "utf8"));
      expect(Object.keys(await builtModule(specifier)).sort()).toEqual(valueNames(barrel));
    });

    it(`${entryPoint} ships declarations for exactly its barrel's names`, async () => {
      const file = ENTRY_POINT_SOURCES[entryPoint];
      if (file === undefined) throw new Error(`no barrel recorded for ${entryPoint}`);
      const barrel = declaredExports(await readFile(path.join(sourceRoot, file), "utf8"));
      const shipped = declaredExports(
        await readFile(path.resolve(sourceRoot, `../dist/es/${stem}.d.ts`), "utf8"),
      );
      expect([...shipped].sort()).toEqual([...barrel].sort());
    });
  }

  /**
   * The runtime half of "one declaration per exported name". Two barrels may
   * publish one name only by re-exporting the module that declares it, so a
   * name two entry points both carry has to be the same binding: that is what
   * makes `@zolana/transaction` and `@zolana/transaction/serialization`
   * interchangeable for a consumer that imports it from either.
   */
  it("binds a name two entry points share to one value", async () => {
    const modules = await Promise.all(
      Object.entries(ENTRY_POINT_SPECIFIERS).map(
        async ([entryPoint, specifier]) => [entryPoint, await builtModule(specifier)] as const,
      ),
    );
    const owners = new Map<string, readonly [string, unknown]>();
    const conflicts: string[] = [];
    for (const [entryPoint, module] of modules) {
      for (const [name, value] of Object.entries(module)) {
        const owner = owners.get(name);
        if (owner === undefined) owners.set(name, [entryPoint, value]);
        else if (owner[1] !== value) conflicts.push(`${name}: ${owner[0]} and ${entryPoint}`);
      }
    }
    expect(conflicts).toEqual([]);
  });
});

/**
 * A name that two modules declare independently is the defect T10 recorded for
 * `SplitBundlePlaintext`: the barrels agree on the spelling while the two
 * entry points hand out unrelated types. One declaration per name keeps a
 * re-export the only way a second barrel can publish it.
 */
describe("one declaration per exported name", () => {
  it("declares each name in exactly one module", async () => {
    const files = await sourceFiles(sourceRoot);
    const sites = new Map<string, string[]>();
    for (const file of files) {
      const source = await readFile(file, "utf8");
      const relative = path.relative(sourceRoot, file);
      for (const [, name] of source.matchAll(
        /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:const|function|class|interface|enum)\s+([A-Za-z_$][\w$]*)/gmu,
      )) {
        const homes = sites.get(name) ?? [];
        if (!homes.includes(relative)) homes.push(relative);
        sites.set(name, homes);
      }
    }
    const duplicated = [...sites]
      .filter(([, homes]) => homes.length > 1)
      .map(([name, homes]) => `${name}: ${homes.join(", ")}`)
      .sort();
    expect(duplicated).toEqual([]);
  });
});
