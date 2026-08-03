import { AccountRole, address, getAddressDecoder, getAddressEncoder, getProgramDerivedAddress, } from "@solana/kit";
import { buildUnsignedTransaction } from "../client/kit.js";
import { USER_REGISTRY_PROGRAM_ID } from "../interface/program.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import {} from "../interface/types.js";
import { P256PublicKey, ShieldedPublicKey } from "../keypair/public-key.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { WalletError, wrapWalletError } from "./error.js";
import { concat, equalBytes } from "./internal.js";
const SYSTEM_PROGRAM = address("11111111111111111111111111111111");
const RECORD_SEED = new TextEncoder().encode("zolana/registry/v0");
const SET_MERGING_ENABLED = 1;
const addressDecoder = getAddressDecoder();
const addressEncoder = getAddressEncoder();
async function userRecordAddress(owner) {
    let checkedOwner;
    try {
        checkedOwner = address(owner);
    }
    catch (cause) {
        throw new WalletError("WALLET_INVALID_ADDRESS", {
            details: { field: "owner" },
            cause,
        });
    }
    try {
        const [recordAddress, bump] = await getProgramDerivedAddress({
            programAddress: USER_REGISTRY_PROGRAM_ID,
            seeds: [RECORD_SEED, addressEncoder.encode(checkedOwner)],
        });
        return { address: recordAddress, bump };
    }
    catch (cause) {
        throw new WalletError("WALLET_PDA_DERIVATION", { cause });
    }
}
export async function internalUserRecordAddress(owner) {
    return (await userRecordAddress(owner)).address;
}
export async function internalUserRecordPda(owner) {
    return userRecordAddress(owner);
}
/**
 * One read of the record for the whole merge build: merging opt-in and the
 * committed identity are validated against the same snapshot.
 */
/** @internal */
export async function internalMergeRecord(input, context) {
    const pda = await userRecordAddress(input.owner);
    const record = await fetchDecodedUserRecordAt({ ...input, pda }, context);
    if (record === undefined) {
        throw new WalletError("WALLET_USER_REGISTRY_RECORD_NOT_FOUND", {
            details: { owner: input.owner },
        });
    }
    return Object.freeze({ ...record, recordAddress: pda.address });
}
class Reader {
    #bytes;
    #offset = 0;
    constructor(bytes) {
        this.#bytes = bytes;
    }
    bytes(length) {
        const end = this.#offset + length;
        if (end > this.#bytes.length)
            throw new WalletError("WALLET_INVALID_USER_RECORD");
        const value = this.#bytes.slice(this.#offset, end);
        this.#offset = end;
        return value;
    }
    u8() {
        return this.bytes(1)[0] ?? 0;
    }
    option(length) {
        const variant = this.u8();
        if (variant === 0)
            return undefined;
        if (variant !== 1)
            throw new WalletError("WALLET_INVALID_USER_RECORD");
        return this.bytes(length);
    }
}
function decodeRecordBody(data) {
    const reader = new Reader(data);
    if (reader.u8() !== 1)
        throw new WalletError("WALLET_INVALID_USER_RECORD");
    const owner = addressDecoder.decode(reader.bytes(32));
    const bump = reader.u8();
    const ownerP256 = reader.option(33);
    const nullifierPublicKey = reader.bytes(32);
    const viewingPublicKey = reader.bytes(33);
    const mergingEnabled = reader.u8();
    if (mergingEnabled > 1)
        throw new WalletError("WALLET_INVALID_USER_RECORD");
    return Object.freeze({
        owner,
        ...(ownerP256 === undefined ? {} : { ownerP256 }),
        nullifierPublicKey,
        viewingPublicKey,
        bump,
        mergingEnabled: mergingEnabled === 1,
    });
}
export function decodeUserRecordAccount(account) {
    if (account.owner !== USER_REGISTRY_PROGRAM_ID) {
        throw new WalletError("WALLET_USER_RECORD_PROGRAM_MISMATCH");
    }
    return decodeRecordBody(account.data);
}
function decodeRecord(account, expectedOwner, expectedBump) {
    const record = decodeUserRecordAccount(account);
    if (record.owner !== expectedOwner) {
        throw new WalletError("WALLET_USER_RECORD_OWNER_MISMATCH");
    }
    if (record.bump !== expectedBump)
        throw new WalletError("WALLET_USER_RECORD_BUMP_MISMATCH");
    return record;
}
async function fetchDecodedUserRecord(input, context) {
    const pda = await userRecordAddress(input.owner);
    return fetchDecodedUserRecordAt({ ...input, pda }, context);
}
async function fetchDecodedUserRecordAt(input, context) {
    const account = await input.rpc.getAccount(input.pda.address, context);
    if (account === undefined)
        return undefined;
    return decodeRecord(account, input.owner, input.pda.bump);
}
export async function fetchUserRecord(input, context) {
    try {
        const record = await fetchDecodedUserRecord(input, context);
        if (record === undefined)
            return undefined;
        return Object.freeze({
            owner: record.owner,
            ...(record.ownerP256 === undefined ? {} : { ownerP256: record.ownerP256 }),
            nullifierPublicKey: record.nullifierPublicKey,
            viewingPublicKey: record.viewingPublicKey,
            mergingEnabled: record.mergingEnabled,
            bump: record.bump,
        });
    }
    catch (cause) {
        throw wrapWalletError("WALLET_FETCH_USER_RECORD", cause);
    }
}
export async function fetchUserRecordChecked(input, context) {
    const record = await fetchUserRecord(input, context);
    if (record === undefined) {
        throw new WalletError("WALLET_USER_REGISTRY_RECORD_NOT_FOUND", {
            details: { owner: input.owner },
        });
    }
    return record;
}
export async function isWalletRegistered(input, context) {
    return (await fetchUserRecord(input, context)) !== undefined;
}
function signingPublicKeyFromRecord(owner, record) {
    return record.ownerP256 === undefined
        ? ShieldedPublicKey.fromEd25519(new Uint8Array(addressEncoder.encode(owner)))
        : ShieldedPublicKey.fromP256(P256PublicKey.fromBytes(record.ownerP256));
}
export function resolvedAddressFromRecord(owner, record) {
    const signingPublicKey = signingPublicKeyFromRecord(owner, record);
    const viewingPublicKey = P256PublicKey.fromBytes(record.viewingPublicKey);
    const address = ShieldedAddress.fromPublicKeys(signingPublicKey, record.nullifierPublicKey, viewingPublicKey);
    // A sender that resolves a recipient here writes this tag onto the output it
    // creates, so it must be the stable shielded-identity signing tag, not the
    // viewing key of the moment: a sync delegate can rotate the viewing key while
    // the signing public key stays put.
    return Object.freeze({
        owner,
        address,
        viewTag: address.confidentialViewTag(),
    });
}
export async function resolveRegisteredAddress(input, context) {
    const record = await fetchUserRecord(input, context);
    if (record === undefined)
        return undefined;
    return resolvedAddressFromRecord(input.owner, record);
}
/**
 * Rejects when the on-chain record under `owner` publishes keys other than
 * `keypair`'s. A shielded identity's nullifier key never rotates, so a
 * difference is an identity conflict rather than stale data.
 */
export async function validateRegisteredKeypair(input, context) {
    const record = await fetchUserRecordChecked({ rpc: input.rpc, owner: input.owner }, context);
    const signingPublicKey = input.keypair.signingPublicKey();
    const expectedOwnerP256 = signingPublicKey.signatureType() === "p256" ? signingPublicKey.p256().toBytes() : undefined;
    const ownerP256Matches = expectedOwnerP256 === undefined
        ? record.ownerP256 === undefined
        : record.ownerP256 !== undefined && equalBytes(record.ownerP256, expectedOwnerP256);
    if (!ownerP256Matches ||
        !equalBytes(record.nullifierPublicKey, input.keypair.nullifierKey().publicKey()) ||
        !equalBytes(record.viewingPublicKey, input.keypair.viewingKey().publicKey().toBytes())) {
        throw new WalletError("WALLET_REGISTERED_KEYPAIR_MISMATCH", {
            details: { owner: input.owner },
        });
    }
}
/**
 * Confidential output view tag for a transfer recipient. A registered owner
 * uses the tag of its published signing key. An unregistered owner, who can
 * only be paid by a public withdrawal, uses the zero tag.
 */
export async function recipientConfidentialViewTag(input, context) {
    const record = await fetchUserRecord({ rpc: input.rpc, owner: input.recipient }, context);
    if (record === undefined)
        return new Uint8Array(32);
    return signingPublicKeyFromRecord(input.recipient, record).confidentialViewTag();
}
/**
 * The three published fields the registry keys a record by. A record matching
 * all three needs no transaction; one differing in any of them is an identity
 * change, which only the rotating path may write.
 */
function publishedKeysMatch(record, address) {
    const ownerP256 = address.signingPublicKey.signatureType() === "p256"
        ? address.signingPublicKey.p256().toBytes()
        : undefined;
    const ownerMatches = ownerP256 === undefined
        ? record.ownerP256 === undefined
        : record.ownerP256 !== undefined && equalBytes(record.ownerP256, ownerP256);
    return (ownerMatches &&
        equalBytes(record.nullifierPublicKey, address.nullifierPublicKey) &&
        equalBytes(record.viewingPublicKey, address.viewingPublicKey.toBytes()));
}
export async function buildRegistrationTransaction(input, context) {
    try {
        if (input.address.signingPublicKey.signatureType() === "p256") {
            throw new WalletError("WALLET_P256_REGISTRATION_UNSUPPORTED");
        }
        const pda = await userRecordAddress(input.owner);
        const existing = await fetchDecodedUserRecordAt({ rpc: input.client, owner: input.owner, pda }, context);
        const instruction = registrationInstruction(input.owner, input.address, pda, existing);
        if (instruction === undefined)
            return undefined;
        const lifetime = await input.client.getLatestBlockhash(context);
        return checkedTransactionSize(buildUnsignedTransaction({
            feePayer: input.owner,
            lifetime,
            instructions: [instruction],
        }));
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_REGISTRATION", cause);
    }
}
export async function buildSetMergingEnabledTransaction(input, context) {
    try {
        const [recordAddress, lifetime] = await Promise.all([
            internalUserRecordAddress(input.owner),
            input.client.getLatestBlockhash(context),
        ]);
        return checkedTransactionSize(buildUnsignedTransaction({
            feePayer: input.owner,
            lifetime,
            instructions: [
                {
                    programAddress: USER_REGISTRY_PROGRAM_ID,
                    accounts: [
                        { address: recordAddress, role: AccountRole.WRITABLE },
                        { address: input.owner, role: AccountRole.READONLY_SIGNER },
                    ],
                    data: Uint8Array.of(SET_MERGING_ENABLED, input.enabled ? 1 : 0),
                },
            ],
        }));
    }
    catch (cause) {
        throw wrapWalletError("WALLET_BUILD_SET_MERGING_ENABLED", cause);
    }
}
function registrationInstruction(owner, shieldedAddress, pda, existing) {
    if (existing !== undefined && publishedKeysMatch(existing, shieldedAddress))
        return undefined;
    const ownerP256 = shieldedAddress.signingPublicKey.signatureType() === "p256"
        ? shieldedAddress.signingPublicKey.p256().toBytes()
        : undefined;
    return {
        programAddress: USER_REGISTRY_PROGRAM_ID,
        accounts: [
            { address: pda.address, role: AccountRole.WRITABLE },
            {
                address: owner,
                role: existing === undefined ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER,
            },
            ...(existing === undefined
                ? [{ address: SYSTEM_PROGRAM, role: AccountRole.READONLY }]
                : []),
        ],
        data: concat(Uint8Array.of(existing === undefined ? 0 : 2, ownerP256 === undefined ? 0 : 1), ...(ownerP256 === undefined ? [] : [ownerP256]), shieldedAddress.nullifierPublicKey, shieldedAddress.viewingPublicKey.toBytes()),
    };
}
