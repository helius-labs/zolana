import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import oracle from "../oracles/transaction-parity-v1.json" with { type: "json" };

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src");

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
 */
const RENAMES: Readonly<Record<string, string>> = {
  AnonymousTransferRecipientPlaintext: "AnonymousRecipientPlaintext",
  AnonymousTransferSenderPlaintext: "AnonymousSenderPlaintext",
  DecodeCx: "DecodeContext",
  OwnerCx: "OwnerContext",
  ShieldedTransaction: "IndexedShieldedTransaction",
  SppProofInputUtxo: "ProofInputUtxo",
  SppProofOutputUtxo: "ProofOutputUtxo",
  SyncConfig: "WalletSyncConfig",
  asset_field: "assetField",
  decrypt_transactions: "decryptTransactions",
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
    Balances:
      "a newtype over Vec<AssetBalance> whose only method is a find by mint; Wallet.balances() returns the array and the caller finds",
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
    Balances:
      "a newtype over Vec<AssetBalance> whose only method is a find by mint; Wallet.balances() returns the array and the caller finds",
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
    TransactionErrorDetails: "the structured detail payload per code",
    TransactionErrorValue: "the structured detail payload per code",
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
    decryptTransactionsWorkerEquivalent:
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
 * Names a barrel publishes. Both halves matter: a re-export block carries most
 * of the surface, and the root also declares its own constants inline.
 */
function exportedNames(source: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const [, block] of source.matchAll(/export(?:\s+type)?\s*\{([^}]*)\}/gu)) {
    for (const specifier of block.split(",")) {
      const name = specifier
        .trim()
        .replace(/^type\s+/u, "")
        .split(/\s+as\s+/u)
        .at(-1);
      if (name) names.add(name);
    }
  }
  for (const [, name] of source.matchAll(
    /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:const|let|var|function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/gmu,
  )) {
    names.add(name);
  }
  return names;
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
  return exportedNames(source);
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
 * Both are the read half of a plaintext rail. `decryptCandidate` reconstructs
 * these UTXOs inline while Rust reaches the same result through the trait, and
 * the inline path drops the `resolve_zone_program_id` check Rust applies, so
 * exporting the current logic would publish a divergence rather than close one.
 */
const ABSENT_OPERATIONS: Readonly<Record<string, string>> = {
  "PlaintextTransfer.into_utxos":
    "T10: inlined in wallet sync without Rust's zone-program resolution",
  "Proofless.into_utxos": "T10: inlined in wallet sync without Rust's zone-program resolution",
};

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
