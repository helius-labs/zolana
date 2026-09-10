import type { Address, Bytes32 } from "../interface/types.js";
import { NullifierKey } from "../keypair/nullifier-key.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import type { ShieldedAddress } from "../keypair/shielded.js";
import { Data } from "./data.js";
export type Blinding = Bytes32;
export interface UtxoInit {
    readonly owner: ShieldedPublicKey;
    readonly asset: Address;
    readonly amount: bigint;
    readonly blinding: Blinding;
    readonly data?: Data;
    readonly zoneProgramId?: Address;
}
/**
 * The zone binding a reconstructed UTXO carries, given the id its reader was
 * configured with. A reader that supplies none cannot bind zone data to a
 * policy nobody can enforce, so a payload carrying zone data is refused; a
 * payload carrying none drops the id rather than committing to a zone the
 * plaintext never mentioned. Mirrors Rust `resolve_zone_program_id`.
 */
export declare function resolveZoneProgramId(zoneProgramId: Address | undefined, data: Data): Address | undefined;
export declare function deriveBlinding(seed: Bytes32, position: number): Blinding;
export declare function ownerUtxoHash(ownerHash: Bytes32, blinding: Bytes32): Bytes32;
export declare function ownerUtxoHash(input: Readonly<{
    owner: Bytes32;
    asset: Address;
    amount: bigint;
    blinding: Bytes32;
    dataHash?: Bytes32;
    zoneDataHash?: Bytes32;
    zoneProgramId?: Address;
}>): Bytes32;
export declare class Utxo {
    readonly owner: ShieldedPublicKey;
    readonly asset: Address;
    readonly amount: bigint;
    readonly blinding: Blinding;
    readonly data: Data;
    readonly zoneProgramId?: Address;
    constructor(input: UtxoInit);
    proofInput(nullifierPublicKey: Bytes32, dataHash?: Bytes32, zoneDataHash?: Bytes32): Readonly<{
        hash(): Bytes32;
    }>;
    hash(nullifierPublicKey: Bytes32, dataHash?: Bytes32, zoneDataHash?: Bytes32): Bytes32;
    nullifier(utxoHash: Bytes32, nullifierKey: NullifierKey): Bytes32;
}
export declare class ProofInputUtxo {
    readonly utxo: Utxo;
    readonly nullifierKey: NullifierKey;
    readonly dataHash?: Bytes32;
    readonly zoneDataHash?: Bytes32;
    constructor(input: Readonly<{
        utxo: Utxo;
        nullifierKey: NullifierKey;
        dataHash?: Bytes32;
        zoneDataHash?: Bytes32;
    }>);
    static dummy(blinding?: import("../keypair/bytes.js").Bytes32): ProofInputUtxo;
    isDummy(): boolean;
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
    checkCanonicalDummy(): void;
    hash(): Bytes32;
    nullifier(): Bytes32;
}
export interface ProofOutputUtxo {
    readonly ownerAddress?: ShieldedAddress;
    readonly asset: Address;
    readonly amount: bigint;
    readonly blinding: Bytes32;
    readonly zoneProgramId?: Address;
    readonly zoneDataHash?: Bytes32;
    readonly dataHash?: Bytes32;
    readonly ownerTag?: Bytes32;
    readonly data: Data;
    ownerHash(): Bytes32;
    hash(): Bytes32;
    isDummy(): boolean;
    withUtxoData(utxoData: Uint8Array, dataHash: Bytes32): ProofOutputUtxo;
    /**
     * A memo rides in the recipient's note but no commitment covers it, so unlike
     * the data setter above it leaves `dataHash` alone.
     */
    withMemo(memo: Uint8Array): ProofOutputUtxo;
}
export interface ProofOutputInit {
    readonly ownerAddress?: ShieldedAddress;
    readonly asset: Address;
    readonly amount: bigint;
    readonly blinding?: Bytes32;
    readonly zoneProgramId?: Address;
    readonly zoneDataHash?: Bytes32;
    readonly dataHash?: Bytes32;
    readonly ownerTag?: Bytes32;
    readonly data?: Data;
}
export declare function createProofOutput(input: ProofOutputInit): ProofOutputUtxo;
