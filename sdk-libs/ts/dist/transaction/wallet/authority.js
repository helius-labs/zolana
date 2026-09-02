import { randomSalt } from "../../keypair/bytes.js";
import { EncryptedScheme, encodeAnonymousRecipient, encodeAnonymousSender, encodeOutputData, encodeSplitBundle, encryptAnonymous, encryptSplit, } from "../serialization/codecs.js";
import { encodeConfidentialSlots } from "../instructions/transact.js";
/** Binds local shielded keys to the Solana address that publishes them. */
export class LocalWalletAuthority {
    #solanaPublicKey;
    #keypair;
    constructor(input) {
        this.#solanaPublicKey = input.solanaPublicKey;
        this.#keypair = input.keypair;
    }
    solanaPublicKey() {
        return this.#solanaPublicKey;
    }
    shieldedAddress() {
        return Promise.resolve(this.#keypair.shieldedAddress());
    }
    viewingKeys() {
        return Promise.resolve([this.#keypair.viewingKey()]);
    }
    spendNullifierKey() {
        return Promise.resolve(this.#keypair.nullifierKey());
    }
    syncMaterial() {
        return Promise.resolve({
            identity: this.#keypair.shieldedAddress(),
            viewingKeys: [this.#keypair.viewingKey()],
            nullifierKey: this.#keypair.nullifierKey(),
        });
    }
    encryptConfidentialTransfer(input) {
        const tx = this.#keypair.viewingKey().transactionViewingKey(input.firstNullifier);
        const salt = randomSalt();
        return Promise.resolve({
            txViewingPublicKey: tx.publicKey(),
            salt,
            payload: encodeConfidentialSlots(input.outputs, input.assets, tx, salt),
        });
    }
    /**
     * Slot 0 carries the sender bundle encrypted to this wallet's own viewing
     * key; recipient `i` occupies slot `i + 1`. Both the order and the slot
     * indices are bound into each ciphertext, so they must match the layout the
     * transfer instruction publishes.
     */
    encryptAnonymousTransfer(input) {
        const viewingKey = this.#keypair.viewingKey();
        const tx = viewingKey.transactionViewingKey(input.firstNullifier);
        const salt = randomSalt();
        const slot = (scheme, recipient, plaintext, slotIndex, viewTag) => ({
            viewTag,
            data: encodeOutputData(scheme, encryptAnonymous(tx, recipient, plaintext, salt, slotIndex), "encrypted"),
        });
        return Promise.resolve({
            txViewingPublicKey: tx.publicKey(),
            salt,
            payload: [
                slot(EncryptedScheme.anonymousSender, viewingKey.publicKey(), encodeAnonymousSender(input.sender), 0, input.senderViewTag),
                ...input.recipients.map((recipient, index) => slot(EncryptedScheme.anonymousRecipient, recipient.recipientPublicKey, encodeAnonymousRecipient(recipient.plaintext), index + 1, recipient.viewTag)),
            ],
        });
    }
    encryptSplit(input) {
        const viewingKey = this.#keypair.viewingKey();
        const tx = viewingKey.transactionViewingKey(input.firstNullifier);
        const salt = randomSalt();
        const body = encryptSplit(tx, viewingKey.publicKey(), encodeSplitBundle(input.bundle), salt, 0);
        return Promise.resolve({
            txViewingPublicKey: tx.publicKey(),
            salt,
            payload: {
                viewTag: input.viewTag,
                data: encodeOutputData(EncryptedScheme.split, body, "encrypted"),
            },
        });
    }
    /** Local keys approve unattended; Rust takes the trait default here. */
    requestUserApproval(request) {
        void request;
        return Promise.resolve();
    }
}
