import { address } from "@solana/kit";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../interface/program.js";
import { randomBlinding } from "../keypair/bytes.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import { Data } from "./data.js";
import { TransactionError } from "./error.js";
import { ZERO_32, checkU64, checked, commitmentPoseidon, copy, decodeAddress, hashField, poseidon, rightAlign, sha256Bytes, } from "./internal.js";
/**
 * The zone binding a reconstructed UTXO carries, given the id its reader was
 * configured with. A reader that supplies none cannot bind zone data to a
 * policy nobody can enforce, so a payload carrying zone data is refused; a
 * payload carrying none drops the id rather than committing to a zone the
 * plaintext never mentioned. Mirrors Rust `resolve_zone_program_id`.
 */
export function resolveZoneProgramId(zoneProgramId, data) {
    if (!data.zoneData())
        return undefined;
    if (zoneProgramId === undefined) {
        throw new TransactionError("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
    }
    return zoneProgramId;
}
export function deriveBlinding(seed, position) {
    const checkedSeed = checked(seed, 32, "blinding seed");
    if (!Number.isInteger(position) || position < 0 || position > 0xff) {
        throw new TransactionError("TRANSACTION_INVALID_POSITION", { position });
    }
    const digest = sha256Bytes(Uint8Array.from([...checkedSeed.subarray(1), position]));
    const blinding = new Uint8Array(32);
    blinding.set(digest.subarray(1), 1);
    return blinding;
}
function commitmentFields(input) {
    checkU64(input.amount, "amount");
    const zoneDataHash = input.zoneDataHash
        ? checked(input.zoneDataHash, 32, "zone data hash")
        : ZERO_32;
    if (!input.zoneProgramId && !isZero(zoneDataHash)) {
        throw new TransactionError("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
    }
    const zoneProgramId = input.zoneProgramId
        ? hashField(decodeAddress(input.zoneProgramId))
        : ZERO_32;
    const zoneHash = commitmentPoseidon([zoneDataHash, zoneProgramId]);
    const ownerCommitment = commitmentPoseidon([
        checked(input.owner, 32, "owner hash"),
        checked(input.blinding, 32, "blinding"),
    ]);
    return [
        rightAlign(Uint8Array.of(input.domain ?? UTXO_DOMAIN)),
        hashField(decodeAddress(input.asset)),
        rightAlign(bigintToU64(input.amount)),
        input.dataHash ? checked(input.dataHash, 32, "data hash") : ZERO_32,
        zoneHash,
        ownerCommitment,
    ];
}
/**
 * An all-zero zone data hash reaches the commitment as the same field an absent
 * one does, so the two spellings must not survive as distinct stored values.
 * This normalizes the hash only; the zone address is deliberately left alone,
 * because a zero `zoneProgramId` commits to `pk_field(0)`, a non-zero field the
 * circuit reads as zone-bound.
 */
function normalizeZoneDataHash(zoneDataHash) {
    if (zoneDataHash === undefined)
        return undefined;
    const value = checked(zoneDataHash, 32, "zone data hash");
    return isZero(value) ? undefined : value;
}
function bigintToU64(value) {
    const output = new Uint8Array(8);
    new DataView(output.buffer).setBigUint64(0, checkU64(value, "amount"), false);
    return output;
}
function fullOwnerUtxoHash(input, dummy = false) {
    if (dummy) {
        return commitmentPoseidon([
            rightAlign(Uint8Array.of(DUMMY_DOMAIN)),
            ZERO_32,
            ZERO_32,
            ZERO_32,
            commitmentPoseidon([ZERO_32, ZERO_32]),
            commitmentPoseidon([ZERO_32, checked(input.blinding, 32, "blinding")]),
        ]);
    }
    return commitmentPoseidon(commitmentFields(input));
}
export function ownerUtxoHash(ownerOrInput, blinding) {
    if (ownerOrInput instanceof Uint8Array) {
        if (!blinding)
            throw new TransactionError("TRANSACTION_INVALID_BLINDING");
        return commitmentPoseidon([
            checked(ownerOrInput, 32, "owner hash"),
            checked(blinding, 32, "blinding"),
        ]);
    }
    return fullOwnerUtxoHash(ownerOrInput);
}
export class Utxo {
    owner;
    asset;
    amount;
    blinding;
    data;
    zoneProgramId;
    constructor(input) {
        this.owner = input.owner;
        this.asset = input.asset;
        this.amount = checkU64(input.amount, "amount");
        this.blinding = checked(input.blinding, 32, "blinding");
        this.data = new Data((input.data ?? new Data()).records());
        if (input.zoneProgramId !== undefined)
            this.zoneProgramId = input.zoneProgramId;
    }
    proofInput(nullifierPublicKey, dataHash, zoneDataHash) {
        const owner = poseidon([
            this.owner.ownerPublicKeyField(),
            checked(nullifierPublicKey, 32, "nullifier public key"),
        ]);
        const input = {
            owner,
            asset: this.asset,
            amount: this.amount,
            blinding: this.blinding,
            ...(dataHash === undefined ? {} : { dataHash }),
            ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
            ...(this.zoneProgramId === undefined ? {} : { zoneProgramId: this.zoneProgramId }),
        };
        return Object.freeze({ hash: () => fullOwnerUtxoHash(input) });
    }
    hash(nullifierPublicKey, dataHash, zoneDataHash) {
        return this.proofInput(nullifierPublicKey, dataHash, zoneDataHash).hash();
    }
    nullifier(utxoHash, nullifierKey) {
        return nullifierKey.nullifier(checked(utxoHash, 32, "UTXO hash"), this.blinding);
    }
}
export class ProofInputUtxo {
    utxo;
    nullifierKey;
    dataHash;
    zoneDataHash;
    constructor(input) {
        if (!(input.utxo instanceof Utxo) || !(input.nullifierKey instanceof NullifierKey)) {
            throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "proofInput" });
        }
        this.utxo = new Utxo({
            owner: input.utxo.owner.isZero()
                ? ShieldedPublicKey.zeroed()
                : ShieldedPublicKey.fromBytes(input.utxo.owner.toBytes()),
            asset: input.utxo.asset,
            amount: input.utxo.amount,
            blinding: input.utxo.blinding,
            data: input.utxo.data,
            ...(input.utxo.zoneProgramId === undefined
                ? {}
                : { zoneProgramId: input.utxo.zoneProgramId }),
        });
        this.nullifierKey = cloneNullifierKey(input.nullifierKey);
        if (input.dataHash) {
            this.dataHash = checked(input.dataHash, 32, "data hash");
        }
        const zoneDataHash = normalizeZoneDataHash(input.zoneDataHash);
        if (zoneDataHash !== undefined) {
            this.zoneDataHash = zoneDataHash;
        }
        this.checkCanonicalDummy();
    }
    static dummy(blinding = randomBlinding()) {
        const nullifierKey = NullifierKey.fromSecret(new Uint8Array(31));
        try {
            return new ProofInputUtxo({
                utxo: new Utxo({
                    owner: ShieldedPublicKey.zeroed(),
                    asset: address("11111111111111111111111111111111"),
                    amount: 0n,
                    blinding: checked(blinding, 32, "dummy blinding"),
                }),
                nullifierKey,
            });
        }
        finally {
            nullifierKey.destroy();
        }
    }
    isDummy() {
        return this.utxo.owner.isZero();
    }
    /**
     * A zero owner is not a parseable key, so a zero-owner input can only stand
     * for an unused slot. Every other field must be zero as well: the circuit
     * treats the slot as absent, and anything carried here would be committed
     * under an owner hash no key can reproduce.
     *
     * `zoneProgramId` is checked for presence rather than for a zero value,
     * unlike the two hashes: the zero address commits to `pk_field(0)`, a
     * non-zero field, so it is carried rather than absent.
     */
    checkCanonicalDummy() {
        if (!this.isDummy())
            return;
        const field = noncanonicalDummyField(this);
        if (field !== undefined) {
            throw new TransactionError("TRANSACTION_NONCANONICAL_DUMMY_INPUT", { field });
        }
    }
    hash() {
        this.checkCanonicalDummy();
        const owner = this.isDummy()
            ? ZERO_32
            : poseidon([this.utxo.owner.ownerPublicKeyField(), this.nullifierKey.publicKey()]);
        return fullOwnerUtxoHash({
            owner,
            asset: this.utxo.asset,
            amount: this.utxo.amount,
            blinding: this.utxo.blinding,
            ...(this.dataHash === undefined ? {} : { dataHash: this.dataHash }),
            ...(this.zoneDataHash === undefined ? {} : { zoneDataHash: this.zoneDataHash }),
            ...(this.utxo.zoneProgramId === undefined
                ? {}
                : { zoneProgramId: this.utxo.zoneProgramId }),
        }, this.isDummy());
    }
    nullifier() {
        return this.nullifierKey.nullifier(this.hash(), this.utxo.blinding);
    }
}
const DUMMY_ASSET = address("11111111111111111111111111111111");
/**
 * What the commitment folds in. An absent hash and an explicit zero reach
 * `commitmentFields` as the same field, so a rule reading presence rather than
 * this one tells apart two inputs the commitment cannot. `dataHash` is stored
 * as given, so both spellings are reachable.
 */
function committedHash(hash) {
    return hash ?? ZERO_32;
}
function noncanonicalDummyField(input) {
    if (input.utxo.asset !== DUMMY_ASSET)
        return "asset";
    if (input.utxo.amount !== 0n)
        return "amount";
    if (!input.utxo.data.isEmpty())
        return "data";
    if (input.utxo.zoneProgramId !== undefined)
        return "zone_program_id";
    if (!isZero(committedHash(input.dataHash)))
        return "data_hash";
    if (!isZero(committedHash(input.zoneDataHash)))
        return "zone_data_hash";
    if (!isZeroNullifierKey(input.nullifierKey))
        return "nullifier_key";
    return undefined;
}
const DATA_RECORD_ORDER = Object.freeze({
    zoneData: 0,
    utxoData: 1,
    memo: 2,
});
/** One record per kind, kept in the canonical order `Data.validate` requires. */
function withDataRecord(data, record) {
    return new Data([...data.records().filter((existing) => existing.kind !== record.kind), record].sort((left, right) => DATA_RECORD_ORDER[left.kind] - DATA_RECORD_ORDER[right.kind]));
}
export function createProofOutput(input) {
    const blinding = checked(input.blinding ?? randomBlinding(), 32, "output blinding");
    const amount = checkU64(input.amount, "output amount");
    const data = new Data((input.data ?? new Data()).records());
    const { zoneDataHash: suppliedZoneDataHash, ...rest } = input;
    const zoneDataHash = normalizeZoneDataHash(suppliedZoneDataHash);
    const init = {
        ...rest,
        amount,
        blinding,
        data,
        ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
    };
    const ownerHash = () => input.ownerAddress ? input.ownerAddress.ownerHash() : copy(ZERO_32);
    return Object.freeze({
        ...init,
        amount,
        blinding,
        data,
        ownerHash,
        hash() {
            return fullOwnerUtxoHash({
                owner: ownerHash(),
                asset: input.asset,
                amount,
                blinding,
                ...(input.dataHash === undefined ? {} : { dataHash: input.dataHash }),
                ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
                ...(input.zoneProgramId === undefined ? {} : { zoneProgramId: input.zoneProgramId }),
            }, input.ownerAddress === undefined);
        },
        isDummy() {
            return input.ownerAddress === undefined;
        },
        withUtxoData(utxoData, dataHash) {
            return createProofOutput({
                ...init,
                dataHash,
                data: withDataRecord(data, { kind: "utxoData", bytes: utxoData }),
            });
        },
        withMemo(memo) {
            return createProofOutput({
                ...init,
                data: withDataRecord(data, { kind: "memo", bytes: memo }),
            });
        },
    });
}
function cloneNullifierKey(key) {
    const secret = key.secretBytes();
    try {
        return NullifierKey.fromSecret(secret);
    }
    finally {
        secret.fill(0);
    }
}
function isZero(bytes) {
    return bytes.every((byte) => byte === 0);
}
function isZeroNullifierKey(key) {
    const secret = key.secretBytes();
    try {
        return isZero(secret);
    }
    finally {
        secret.fill(0);
    }
}
