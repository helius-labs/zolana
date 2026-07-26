import { readFileSync, readdirSync } from "node:fs";
import { inspect } from "node:util";

import { describe, expect, it } from "vitest";

import certification from "../../../vectors/keypair-crypto-cert-v1.json" with { type: "json" };
import type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes34 } from "../../src/bytes.js";
import {
  KEYPAIR_ERROR_RUST_VARIANT,
  KeypairError,
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "../../src/index.js";
import { mergeCiphertextHash, symmetricApply } from "../../src/merge/index.js";

/**
 * K10, error and redaction parity, against
 * `sdk-libs/keypair/tests/crypto_certification.rs`.
 *
 * Two halves. The ledger half walks the Rust rows and checks the port refuses
 * at the same boundary with the same variant, including the rows Rust reaches
 * and the port cannot. The redaction half feeds distinctive key material into
 * every reachable failure and looks for it in every rendering a logger or a
 * crash reporter would produce: message, stack, `JSON.stringify`, a spread,
 * `util.inspect`, and the whole `cause` chain, which is where a dependency's
 * own error would carry the input it rejected.
 */

const recorded = certification.errorLedger;

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Distinctive, so a hit in an error rendering cannot be a coincidence. */
function marker(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => 0xc0 + (index % 32));
}

/** A P256 secret above the group order, so it is refused and still distinctive. */
function outOfRangeSecret(): Bytes32 {
  const bytes = marker(32);
  bytes.fill(0xff, 0, 8);
  return bytes as Bytes32;
}

/** The compressed key Rust rejected, without its shielded tag byte. */
function nonPoint(): Bytes33 {
  return fromHex(recorded.badPointBytes).slice(1) as Bytes33;
}

function raise(operation: () => unknown): KeypairError {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(KeypairError);
    return error as KeypairError;
  }
  throw new Error("expected the operation to be refused");
}

const ledgerBoundaries: Readonly<Record<string, () => unknown>> = {
  "SigningKey.fromBytes": () => SigningKey.fromBytes(new Uint8Array(32) as Bytes32),
  "ShieldedPublicKey.fromBytes": () =>
    ShieldedPublicKey.fromBytes(fromHex(recorded.badPointBytes) as Bytes34),
  "ShieldedPublicKey.ed25519": () =>
    SigningKey.fromBytes(fromHex(certification.mergeEncryption.txSecretBytes) as Bytes32)
      .publicKey()
      .ed25519(),
  "NullifierKey.nullifier": () =>
    NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31).nullifier(
      new Uint8Array(32).fill(0xff) as Bytes32,
      new Uint8Array(31).fill(3) as Bytes31,
    ),
  "SigningKey.sign": () =>
    SigningKey.fromBytes(fromHex(certification.mergeEncryption.txSecretBytes) as Bytes32).sign(
      new Uint8Array(31).fill(7),
    ),
  symmetricApply: () =>
    symmetricApply(new Uint8Array(32).fill(1), new Uint8Array(63).fill(0x6c), new Uint8Array(8)),
};

/**
 * The `wrongSignatureType` row needs the badly prefixed input rather than the
 * badly pointed one, so it overrides the boundary's default argument.
 */
const ledgerOverrides: Readonly<Record<string, () => unknown>> = {
  wrongSignatureType: () =>
    ShieldedPublicKey.fromBytes(fromHex(recorded.badPrefixBytes) as Bytes34),
};

interface SourceFile {
  readonly name: string;
  readonly text: string;
}

function sourceFiles(directory: URL, prefix = ""): SourceFile[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? sourceFiles(new URL(`${entry.name}/`, directory), `${prefix}${entry.name}/`)
      : entry.name.endsWith(".ts")
        ? [
            {
              name: `${prefix}${entry.name}`,
              text: readFileSync(new URL(entry.name, directory), "utf8"),
            },
          ]
        : [],
  );
}

/**
 * The rule this suite enforces: a code whose `rustVariant` is null may be
 * raised only where Rust cannot express the failing input. Each entry lists the
 * sources allowed to name it, with the reason Rust has no variant to mirror.
 * `error.ts` declares the ledger and is on every list for that reason alone.
 */
const TYPESCRIPT_ONLY_SITES: Readonly<Record<string, readonly string[]>> = {
  // Rust carries lengths in array types, so a wrong length has no variant.
  KEYPAIR_INVALID_LENGTH: ["error.ts", "viewing-key.ts"],
  // Rust's `pack33` takes `&[u8; 33]` and is infallible.
  KEYPAIR_HASH: ["error.ts", "hash.ts"],
};

/** Every rendering of an error a caller, a logger, or a reporter can reach. */
function renderings(error: KeypairError): string[] {
  const surfaces = [
    error.message,
    String(error),
    error.stack ?? "",
    JSON.stringify(error),
    JSON.stringify(error.toJSON()),
    JSON.stringify({ ...(error as unknown as Record<string, unknown>) }),
    JSON.stringify(error, Object.getOwnPropertyNames(error)),
    inspect(error, { depth: null, showHidden: true }),
  ];
  for (let cause: unknown = error.cause; cause !== undefined && cause !== null;) {
    surfaces.push(
      cause instanceof Error
        ? `${cause.name} ${cause.message} ${cause.stack ?? ""}`
        : inspect(cause),
      JSON.stringify(cause),
      inspect(cause, { depth: null, showHidden: true }),
    );
    cause = cause instanceof Error ? cause.cause : undefined;
  }
  return surfaces;
}

/** The encodings the same bytes could plausibly reach a log line as. */
function encodings(bytes: Uint8Array): string[] {
  const hex = toHex(bytes);
  return [
    hex,
    hex.toUpperCase(),
    Buffer.from(bytes).toString("base64"),
    Buffer.from(bytes).toString("latin1"),
    bytes.join(","),
    JSON.stringify(Array.from(bytes)),
  ];
}

function expectNoLeak(error: KeypairError, ...secrets: readonly Uint8Array[]): void {
  const surfaces = renderings(error);
  for (const secret of secrets) {
    for (const encoded of encodings(secret)) {
      // A short encoding could match by chance; every secret below is at
      // least fifteen bytes of non-repeating material.
      expect(encoded.length).toBeGreaterThanOrEqual(15);
      for (const surface of surfaces) {
        expect(surface, `${error.code} leaked ${encoded.slice(0, 16)}...`).not.toContain(encoded);
      }
    }
  }
}

describe("K10 error ledger and redaction against current Rust", () => {
  it("refuses at the same boundary with the same Rust variant", () => {
    const covered = recorded.raised.filter((row) => row.typescript !== null);
    expect(covered).toHaveLength(7);
    for (const row of covered) {
      const operation = ledgerOverrides[row.case] ?? ledgerBoundaries[row.typescript];
      expect(operation, `no boundary wired for ${row.case}`).toBeDefined();
      const error = raise(operation as () => unknown);
      expect(error.rustVariant, row.case).toBe(row.rustVariant);
    }
  });

  it("declares the one Rust refusal the port cannot reach, and reaches nothing else with it", () => {
    const absent = recorded.raised.filter((row) => row.typescript === null);
    expect(absent.map((row) => row.rustVariant)).toEqual(["NotEd25519"]);
    // `to_solana_keypair` returns a Solana keypair, which the port does not
    // carry, so the code is declared for ledger completeness and never thrown.
    // Scanning the sources is what keeps that claim true as the port grows.
    expect(KEYPAIR_ERROR_RUST_VARIANT.KEYPAIR_NOT_ED25519).toBe("NotEd25519");
    const sources = sourceFiles(new URL("../../src/", import.meta.url));
    const mentions = sources.filter((source) => source.text.includes("KEYPAIR_NOT_ED25519"));
    expect(mentions).toHaveLength(1);
    expect(mentions[0]?.text).toContain("KEYPAIR_ERROR_RUST_VARIANT");
  });

  it("answers an empty merge ciphertext with the variant Rust answers", () => {
    // Rust's `merge_ciphertext_hash(&[])` reaches the hasher and returns
    // `Poseidon`. An empty slice is expressible in both languages, so nothing
    // here justifies a code Rust has no counterpart for.
    expect(certification.mergeEncryption.emptyCiphertextHashVariant).toBe("Poseidon");
    const error = raise(() => mergeCiphertextHash(new Uint8Array()));
    expect(error.code).toBe("KEYPAIR_POSEIDON");
    expect(error.rustVariant).toBe("Poseidon");
  });

  it("raises a code with no Rust variant only where Rust cannot express the input", () => {
    const declared = Object.entries(KEYPAIR_ERROR_RUST_VARIANT)
      .filter(([, variant]) => variant === null)
      .map(([code]) => code);
    expect(declared.sort()).toEqual(Object.keys(TYPESCRIPT_ONLY_SITES).sort());
    const sources = sourceFiles(new URL("../../src/", import.meta.url));
    for (const [code, justified] of Object.entries(TYPESCRIPT_ONLY_SITES)) {
      const naming = sources
        .filter((source) => source.text.includes(`"${code}"`))
        .map((source) => source.name)
        .sort();
      expect(naming, `${code} is named outside the sites that justify it`).toEqual(
        [...justified].sort(),
      );
    }
  });

  it("keeps the variants Rust cannot reach in the mapping rather than dropping them", () => {
    expect(recorded.unreachable.map((row) => row.case)).toEqual(["zeroScalar", "hkdfFailure"]);
    expect(KEYPAIR_ERROR_RUST_VARIANT.KEYPAIR_ZERO_SCALAR).toBe("ZeroScalar");
    expect(KEYPAIR_ERROR_RUST_VARIANT.KEYPAIR_HKDF).toBe("Hkdf");
  });

  it("agrees with Rust on what is not an error at all", () => {
    const sender = ViewingKey.fromBytes(
      fromHex(certification.transferEncryption.senderSecretBytes) as Bytes32,
    );
    const recipient = ViewingKey.fromBytes(
      fromHex(certification.transferEncryption.recipientSecretBytes) as Bytes32,
    );
    const salt = fromHex(certification.transferEncryption.baseSaltBytes) as Bytes16;
    const slot = certification.transferEncryption.baseSlot;
    const plaintext = fromHex(recorded.nonErrors.plaintextBytes);
    const ciphertext = sender.encryptSlot(recipient.publicKey(), plaintext, salt, slot);

    // CTR carries no tag, so integrity comes from the proof-committed UTXO
    // hash. A port that raised here would reject transactions the protocol
    // accepts, which is why the exact garbage is pinned.
    expect(toHex(recipient.decryptUtxo(ciphertext, sender.publicKey(), salt, slot + 1))).toBe(
      recorded.nonErrors.wrongSlotRecoveredBytes,
    );
    const wrongSalt = new Uint8Array(16).fill(0x5b) as Bytes16;
    expect(toHex(recipient.decryptUtxo(ciphertext, sender.publicKey(), wrongSalt, slot))).toBe(
      recorded.nonErrors.wrongSaltRecoveredBytes,
    );
    const tampered = Uint8Array.from(ciphertext);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(toHex(recipient.decryptUtxo(tampered, sender.publicKey(), salt, slot))).toBe(
      recorded.nonErrors.tamperedRecoveredBytes,
    );

    const signing = SigningKey.fromBytes(
      fromHex(certification.mergeEncryption.txSecretBytes) as Bytes32,
    );
    expect(signing.verify(new Uint8Array(32).fill(1), new Uint8Array(64) as never)).toBe(
      recorded.nonErrors.malformedSignatureVerifies,
    );
  });

  it("keeps rejected key material out of every rendering of the error", () => {
    expect(recorded.displaysCarryNoBytes).toBe(true);
    const secret = outOfRangeSecret();
    const point = nonPoint();
    const shortDigest = marker(31);
    const longInfo = marker(63);
    const shortSalt = marker(15);
    const nullifierSecret = marker(31);

    expectNoLeak(
      raise(() => SigningKey.fromBytes(secret)),
      secret,
    );
    expectNoLeak(
      raise(() => ViewingKey.fromBytes(secret)),
      secret,
    );
    expectNoLeak(
      raise(() => P256PublicKey.fromBytes(point)),
      point,
    );
    expectNoLeak(
      raise(() =>
        SigningKey.fromBytes(fromHex(certification.mergeEncryption.txSecretBytes) as Bytes32).sign(
          shortDigest,
        ),
      ),
      shortDigest,
    );
    expectNoLeak(
      raise(() => symmetricApply(secret, longInfo, marker(8))),
      secret,
      longInfo,
    );
    const viewing = ViewingKey.fromBytes(
      fromHex(certification.transferEncryption.senderSecretBytes) as Bytes32,
    );
    expectNoLeak(
      raise(() => viewing.encryptSlot(viewing.publicKey(), marker(32), shortSalt as Bytes16, 0)),
      shortSalt,
      viewing.secretBytes(),
    );
    expectNoLeak(
      raise(() =>
        NullifierKey.fromSecret(nullifierSecret as Bytes31).nullifier(
          new Uint8Array(32).fill(0xff) as Bytes32,
          nullifierSecret as Bytes31,
        ),
      ),
      nullifierSecret,
    );
    expectNoLeak(
      raise(() =>
        ShieldedKeypair.fromSigningAndViewingKeys(
          SigningKey.fromBytes(fromHex(certification.mergeEncryption.txSecretBytes) as Bytes32),
          viewing,
        ).signP256(shortDigest as Bytes32),
      ),
      shortDigest,
      viewing.secretBytes(),
    );
  });

  it("drops any diagnostic that is not a primitive on the allowlist", () => {
    const secret = marker(32);
    const smuggled = new KeypairError("KEYPAIR_HKDF", {
      reason: secret as unknown as string,
      name: "info",
      // Unknown keys never reach the error, so a future caller cannot widen the
      // surface by inventing one.
      plaintext: toHex(secret),
    } as never);
    expect(smuggled.details).toEqual({ name: "info" });
    expectNoLeak(smuggled, secret);
  });

  it("keeps the cause out of enumeration while leaving it reachable", () => {
    const error = raise(() => P256PublicKey.fromBytes(nonPoint()));
    expect(error.cause).toBeInstanceOf(Error);
    expect(Object.keys(error)).not.toContain("cause");
    expect(JSON.stringify(error)).not.toContain("cause");
    expect(Object.keys(error.toJSON())).toEqual(["name", "code"]);
  });
});
