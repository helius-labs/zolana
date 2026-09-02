import { mergeDummyNullifier, mergeOutputBlinding } from "../../keypair/merge/index.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { TransactionError } from "../error.js";
import { copy, decodeAddress, equal } from "../internal.js";
import { SENDER_SLOT_COUNT } from "../instructions/transact.js";
import { EncryptedScheme, anonymousRecipientUtxo, anonymousSenderUtxos, confidentialUtxo, decodeAnonymousRecipient, decodeAnonymousSender, decodePlaintextTransfer, decodeProofless, decodeSplitBundle, decryptAnonymous, decryptConfidential, decryptConfidentialAsSender, prooflessUtxo, plaintextTransferUtxos, readOutputData, splitBundleUtxos, } from "../serialization/codecs.js";
import { Utxo } from "../utxo.js";
import { SOL_MINT } from "./asset.js";
import { SENDER_HISTORY_ROW_BASE, newViewingKeyEntry, Wallet, hex, } from "./state.js";
const U64_MAX = 0xffffffffffffffffn;
function validateMaterial(wallet, material) {
    if (!equal(material.identity.signingPublicKey.toBytes(), wallet.identity.signingPublicKey.toBytes()) ||
        !equal(material.identity.nullifierPublicKey, wallet.identity.nullifierPublicKey) ||
        !equal(material.identity.viewingPublicKey.toBytes(), wallet.identity.viewingPublicKey.toBytes())) {
        throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
    }
    if (!material.viewingKeys.some((key) => equal(key.publicKey().toBytes(), wallet.identity.viewingPublicKey.toBytes()))) {
        throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
    }
    if (!equal(material.nullifierKey.publicKey(), material.identity.nullifierPublicKey)) {
        throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
    }
}
function pushInto(into, tag, value) {
    const existing = into.get(tag);
    if (existing === undefined)
        into.set(tag, [value]);
    else
        existing.push(value);
}
function buildTagIndex(transactions) {
    const senderSites = new Map();
    const recipientSites = new Map();
    let unparsedTransactions = 0;
    for (const [transaction, tx] of transactions.entries()) {
        let classified = false;
        if (!tx.proofless && tx.txViewingPublicKey === undefined && tx.salt === undefined) {
            for (const [index, slot] of tx.outputSlots.entries()) {
                pushInto(recipientSites, hex(slot.viewTag), { transaction, slot: index });
                classified = true;
            }
            if (!classified)
                unparsedTransactions++;
            continue;
        }
        for (const [index, slot] of tx.outputSlots.entries()) {
            let scheme;
            try {
                scheme = readOutputData(slot.payload).scheme;
            }
            catch {
                continue;
            }
            const tag = hex(slot.viewTag);
            if (scheme === EncryptedScheme.anonymousSender || scheme === EncryptedScheme.split) {
                pushInto(senderSites, tag, transaction);
            }
            else {
                pushInto(recipientSites, tag, { transaction, slot: index });
            }
            classified = true;
        }
        if (!classified)
            unparsedTransactions++;
    }
    return { senderSites, recipientSites, unparsedTransactions };
}
function compareBigints(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
/** Addresses order by their 32 bytes, which base58 text does not preserve. */
function compareAssets(left, right) {
    const leftBytes = hex(decodeAddress(left));
    const rightBytes = hex(decodeAddress(right));
    return leftBytes < rightBytes ? -1 : leftBytes > rightBytes ? 1 : 0;
}
/** Retain every viewing key the authority can still use after rotation. */
function ensureViewingKeyEntries(history, viewingKeys) {
    const known = new Set(history.map((entry) => hex(entry.viewingPublicKey.toBytes())));
    const entries = [...history];
    for (const key of viewingKeys) {
        const id = hex(key.publicKey().toBytes());
        if (known.has(id))
            continue;
        known.add(id);
        entries.push(newViewingKeyEntry(key.publicKey(), 0n));
    }
    return entries;
}
function historyId(tx, index) {
    return { signature: tx.txSignature, slot: tx.slot, index };
}
function rowKey(row) {
    return [
        row.id.signature,
        row.id.slot,
        row.id.index,
        row.kind,
        row.direction,
        row.status,
        row.asset,
        row.amount,
        row.counterpartyViewingPublicKey === undefined
            ? ""
            : hex(row.counterpartyViewingPublicKey.toBytes()),
    ].join("|");
}
/**
 * The notes and history rows one sync produces, accumulated across every
 * viewing key the authority supplied. This is the counterpart of Rust
 * `SyncCtx`: it owns the staged wallet contents so a rejection leaves the
 * wallet untouched, and it carries the report counters each decode step
 * advances.
 */
class SyncPass {
    #owner;
    #nullifierPublicKey;
    #nullifierKey;
    #selfViewingPublicKey;
    #assets;
    #transactions;
    #utxos;
    #rows;
    #rowKeys;
    #outputHashes;
    #processedSlots = new Set();
    #processedOutbound = new Set();
    #unknownAssetsBySite = new Map();
    storedUtxos = 0;
    undecryptableCandidates = 0;
    constructor(input) {
        this.#owner = input.material.identity.signingPublicKey;
        this.#nullifierPublicKey = input.material.identity.nullifierPublicKey;
        this.#nullifierKey = input.material.nullifierKey;
        this.#selfViewingPublicKey = input.material.identity.viewingPublicKey;
        this.#assets = input.assets;
        this.#transactions = input.transactions;
        this.#utxos = [...input.utxos];
        this.#rows = [...input.rows];
        this.#rowKeys = new Set(this.#rows.map(rowKey));
        this.#outputHashes = new Set(this.#utxos.map((entry) => hex(entry.outputContext.hash)));
    }
    utxos() {
        return this.#utxos;
    }
    rows() {
        return this.#rows;
    }
    unknownAssetIds() {
        const ids = new Set();
        for (const candidate of this.#unknownAssetsBySite.values()) {
            for (const id of candidate.ids)
                ids.add(id);
        }
        return [...ids].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    }
    unknownAssetFields() {
        const fields = new Map();
        for (const candidate of this.#unknownAssetsBySite.values()) {
            for (const [key, field] of candidate.fields)
                fields.set(key, field);
        }
        return [...fields.values()]
            .map((field) => new Uint8Array(field))
            .sort((left, right) => {
            const leftKey = hex(left);
            const rightKey = hex(right);
            return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
        });
    }
    #store(utxo, outputContext, dataHash, zoneDataHash) {
        if (!equal(utxo.owner.toBytes(), this.#owner.toBytes()))
            return;
        const outputId = hex(outputContext.hash);
        if (this.#outputHashes.has(outputId))
            return;
        this.#utxos.push(Object.freeze({
            utxo,
            outputContext: Object.freeze({
                hash: copy(outputContext.hash),
                tree: outputContext.tree,
                leafIndex: outputContext.leafIndex,
            }),
            nullifier: utxo.nullifier(outputContext.hash, this.#nullifierKey),
            ...(dataHash === undefined ? {} : { dataHash }),
            ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
            spent: false,
        }));
        this.#outputHashes.add(outputId);
        this.storedUtxos++;
    }
    /**
     * Store a note whose slot is not known in advance, by finding the slot whose
     * committed leaf its hash reproduces. The sender-side bundles carry their
     * change this way: one bundle describes several outputs spread across the
     * transaction.
     */
    #storeInTx(utxo, tx) {
        const hash = utxo.hash(this.#nullifierPublicKey);
        const slot = tx.outputSlots.find((candidate) => equal(candidate.outputContext.hash, hash));
        if (slot === undefined) {
            this.undecryptableCandidates++;
            return;
        }
        this.#store(utxo, slot.outputContext, undefined, undefined);
    }
    /** Verify each 1:1 recipient note against the slot's committed leaf and store it. */
    #storeRecipientUtxos(utxos, outputContext, dataHash, zoneDataHash) {
        let stored = false;
        for (const utxo of utxos) {
            if (!equal(utxo.hash(this.#nullifierPublicKey, dataHash, zoneDataHash), outputContext.hash)) {
                this.undecryptableCandidates++;
                continue;
            }
            this.#store(utxo, outputContext, dataHash, zoneDataHash);
            stored = true;
        }
        return stored;
    }
    #record(row) {
        const key = rowKey(row);
        if (this.#rowKeys.has(key))
            return;
        this.#rowKeys.add(key);
        this.#rows.push(Object.freeze({ ...row, id: Object.freeze({ ...row.id }) }));
    }
    /**
     * Record a candidate that failed to become notes. When the failure was an
     * unknown asset id, remember the id so the client sync layer can backfill the
     * registry and retry; that is the single seam where a stale registry surfaces
     * during decode.
     */
    #noteUndecryptable(error, siteKey) {
        if (error instanceof TransactionError) {
            let candidate = this.#unknownAssetsBySite.get(siteKey);
            const assetCandidate = () => {
                if (candidate !== undefined)
                    return candidate;
                candidate = { ids: new Set(), fields: new Map() };
                this.#unknownAssetsBySite.set(siteKey, candidate);
                return candidate;
            };
            if (error.code === "TRANSACTION_UNKNOWN_ASSET") {
                const assetId = error.details?.["assetId"];
                if (typeof assetId === "string" && /^\d+$/u.test(assetId)) {
                    assetCandidate().ids.add(BigInt(assetId));
                }
            }
            else if (error.code === "TRANSACTION_UNKNOWN_ASSET_FIELD") {
                const value = error.details?.["assetField"];
                if (Array.isArray(value) &&
                    value.length === 32 &&
                    value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
                    const field = new Uint8Array(value);
                    assetCandidate().fields.set(hex(field), field);
                }
            }
        }
        this.undecryptableCandidates++;
    }
    #resolveAssetCandidate(siteKey) {
        this.#unknownAssetsBySite.delete(siteKey);
    }
    #spentAmounts(nullifiers) {
        const spent = new Set(nullifiers.map(hex));
        const byAsset = new Map();
        for (const entry of this.#utxos) {
            if (!spent.has(hex(entry.nullifier)))
                continue;
            const total = (byAsset.get(entry.utxo.asset) ?? 0n) + entry.utxo.amount;
            if (total > U64_MAX)
                throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
            byAsset.set(entry.utxo.asset, total);
        }
        return byAsset;
    }
    #recordReceived(tx, slotIndex, sender, utxo) {
        const direction = sender !== undefined && equal(sender.toBytes(), this.#selfViewingPublicKey.toBytes())
            ? "selfTransfer"
            : "inbound";
        this.#record({
            id: historyId(tx, tx.outputSlots[slotIndex]?.outputContext.leafIndex ?? BigInt(slotIndex)),
            kind: "privateTransfer",
            direction,
            status: "confirmed",
            asset: utxo.asset,
            amount: utxo.amount,
            ...(sender === undefined ? {} : { counterpartyViewingPublicKey: sender }),
        });
    }
    #recordDeposit(tx, outputContext, utxo) {
        this.#record({
            id: historyId(tx, outputContext.leafIndex),
            kind: "deposit",
            direction: "inbound",
            status: "confirmed",
            asset: utxo.asset,
            amount: utxo.amount,
        });
    }
    /**
     * One row per asset the transaction moved out, netted down by the change it
     * paid back to this wallet. A row whose net is zero is dropped but still
     * consumes its row index, so the surviving rows keep the indices they had.
     */
    #recordOutboundTransfer(tx, spent, change, kind, counterparty) {
        const byAsset = new Map(spent);
        for (const utxo of change) {
            const total = byAsset.get(utxo.asset);
            if (total === undefined)
                continue;
            byAsset.set(utxo.asset, total > utxo.amount ? total - utxo.amount : 0n);
        }
        [...byAsset]
            .sort(([left], [right]) => compareAssets(left, right))
            .forEach(([asset, amount], row) => {
            if (amount === 0n)
                return;
            this.#record({
                id: historyId(tx, SENDER_HISTORY_ROW_BASE + BigInt(row)),
                kind,
                direction: "outbound",
                status: "confirmed",
                asset,
                amount,
                ...(counterparty === undefined ? {} : { counterpartyViewingPublicKey: counterparty }),
            });
        });
    }
    /** A split pays nobody, so every asset it spent stays with the wallet. */
    #recordSplit(tx, spent) {
        [...spent]
            .sort(([left], [right]) => compareAssets(left, right))
            .forEach(([asset, amount], row) => {
            if (amount === 0n)
                return;
            this.#record({
                id: historyId(tx, SENDER_HISTORY_ROW_BASE + BigInt(row)),
                kind: "split",
                direction: "selfTransfer",
                status: "confirmed",
                asset,
                amount,
            });
        });
    }
    #recordMerge(tx, outputContext, utxo) {
        this.#record({
            id: historyId(tx, outputContext.leafIndex),
            kind: "merge",
            direction: "selfTransfer",
            status: "confirmed",
            asset: utxo.asset,
            amount: utxo.amount,
        });
    }
    /**
     * Whether `key` is the viewing key that authored `tx`: the transaction
     * viewing key derived from the first nullifier reproduces the published one
     * only for the spending wallet.
     */
    #authored(tx, key) {
        const firstNullifier = tx.nullifiers[0];
        if (tx.txViewingPublicKey === undefined || firstNullifier === undefined)
            return false;
        return equal(key.transactionViewingKey(firstNullifier).publicKey().toBytes(), tx.txViewingPublicKey.toBytes());
    }
    /**
     * Reconstruct the outbound history of a confidential transfer the wallet
     * authored. The unified scheme carries no sender-side recipient list, so the
     * author re-derives the transaction viewing key and decrypts every output
     * slot with it: change slots net the spent inputs down, recipient slots
     * reveal the counterparties. Dummy slots fail the decrypt and are skipped.
     */
    recordConfidentialSend(tx, index, key) {
        const firstNullifier = tx.nullifiers[0];
        const salt = tx.salt;
        if (tx.txViewingPublicKey === undefined || firstNullifier === undefined || salt === undefined) {
            return;
        }
        const txKey = key.transactionViewingKey(firstNullifier);
        if (!equal(txKey.publicKey().toBytes(), tx.txViewingPublicKey.toBytes()))
            return;
        if (this.#processedOutbound.has(index))
            return;
        this.#processedOutbound.add(index);
        const change = [];
        const recipientKeys = [];
        tx.outputSlots.forEach((slot, position) => {
            try {
                const frame = readOutputData(slot.payload);
                if (frame.encoding !== "encrypted" || frame.scheme !== EncryptedScheme.confidential)
                    return;
                const plaintext = decryptConfidentialAsSender(txKey, frame.body, salt, position);
                if (position < SENDER_SLOT_COUNT) {
                    change.push(confidentialUtxo(plaintext, this.#owner, this.#assets));
                }
                else {
                    // Each recipient slot stays sealed to its recipient, so the key
                    // prefixed to the ciphertext is the one thing the sender reads out.
                    recipientKeys.push(P256PublicKey.fromBytes(frame.body.slice(0, 33)));
                }
            }
            catch {
                // A dummy slot fails the transaction-key decrypt; skip it.
            }
        });
        const kind = recipientKeys.length === 0 ? "publicWithdrawal" : "privateTransfer";
        this.#recordOutboundTransfer(tx, this.#spentAmounts(tx.nullifiers), change, kind, recipientKeys.length === 1 ? recipientKeys[0] : undefined);
    }
    /**
     * Decode one candidate slot, dispatching on its encoding and scheme byte.
     * Recipient and confidential slots are 1:1 and verified against the slot's
     * committed leaf; the anonymous and split sender bundles, passed as slot 0,
     * store their change against the whole transaction.
     */
    decodeSlot(key, site) {
        const siteKey = `${String(site.transaction)}:${String(site.slot)}`;
        if (this.#processedSlots.has(siteKey))
            return;
        const tx = this.#transactions[site.transaction];
        const slot = tx?.outputSlots[site.slot];
        if (tx === undefined || slot === undefined) {
            this.undecryptableCandidates++;
            return;
        }
        if (!tx.proofless && tx.txViewingPublicKey === undefined && tx.salt === undefined) {
            this.#reconstructMerge(tx, site, siteKey);
            return;
        }
        let frame;
        try {
            frame = readOutputData(slot.payload);
        }
        catch {
            this.undecryptableCandidates++;
            return;
        }
        const { outputContext } = slot;
        const { body } = frame;
        if (frame.encoding === "plaintext" && frame.scheme === EncryptedScheme.proofless) {
            let deposit;
            let utxo;
            try {
                deposit = decodeProofless(body);
                utxo = prooflessUtxo(deposit, this.#owner);
            }
            catch (error) {
                this.#noteUndecryptable(error, siteKey);
                return;
            }
            this.#resolveAssetCandidate(siteKey);
            if (this.#storeRecipientUtxos([utxo], outputContext, deposit.dataHash, deposit.zoneDataHash)) {
                this.#processedSlots.add(siteKey);
                this.#recordDeposit(tx, outputContext, utxo);
            }
            return;
        }
        if (frame.encoding === "plaintext" && frame.scheme === EncryptedScheme.plaintextTransfer) {
            let utxos;
            try {
                utxos = plaintextTransferUtxos(decodePlaintextTransfer(body), this.#assets, SOL_MINT);
            }
            catch (error) {
                this.#noteUndecryptable(error, siteKey);
                return;
            }
            this.#resolveAssetCandidate(siteKey);
            for (const utxo of utxos)
                this.#storeInTx(utxo, tx);
            this.#processedSlots.add(siteKey);
            return;
        }
        if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousRecipient) {
            let sender;
            let utxo;
            try {
                const plaintext = decodeAnonymousRecipient(this.#decryptFor(key, tx, body, site.slot));
                sender = plaintext.senderPublicKey;
                utxo = anonymousRecipientUtxo(plaintext, this.#assets);
            }
            catch (error) {
                this.#noteUndecryptable(error, siteKey);
                return;
            }
            this.#resolveAssetCandidate(siteKey);
            if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
                this.#processedSlots.add(siteKey);
                this.#recordReceived(tx, site.slot, sender, utxo);
            }
            return;
        }
        if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.confidential) {
            let utxo;
            try {
                const { txViewingPublicKey, salt } = this.#envelope(tx);
                utxo = confidentialUtxo(decryptConfidential(key, txViewingPublicKey, body, salt, site.slot), this.#owner, this.#assets);
            }
            catch (error) {
                this.#noteUndecryptable(error, siteKey);
                return;
            }
            this.#resolveAssetCandidate(siteKey);
            if (this.#storeRecipientUtxos([utxo], outputContext, undefined, undefined)) {
                this.#processedSlots.add(siteKey);
                // A slot the wallet itself authored is its own change or self-send
                // output; its outbound history is recorded once per transaction by
                // `recordConfidentialSend`, so it must not also be logged here as an
                // inbound receipt.
                if (!this.#authored(tx, key))
                    this.#recordReceived(tx, site.slot, undefined, utxo);
            }
            return;
        }
        if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.anonymousSender) {
            let recipients;
            let change;
            try {
                const plaintext = decodeAnonymousSender(this.#decryptFor(key, tx, body, site.slot));
                recipients = plaintext.recipientViewingPublicKeys;
                change = anonymousSenderUtxos(plaintext, this.#assets, SOL_MINT);
            }
            catch (error) {
                this.#noteUndecryptable(error, siteKey);
                return;
            }
            this.#resolveAssetCandidate(siteKey);
            for (const utxo of change)
                this.#storeInTx(utxo, tx);
            this.#processedSlots.add(siteKey);
            if (!this.#processedOutbound.has(site.transaction)) {
                this.#processedOutbound.add(site.transaction);
                const kind = recipients.length === 0 ? "publicWithdrawal" : "privateTransfer";
                this.#recordOutboundTransfer(tx, this.#spentAmounts(tx.nullifiers), change, kind, recipients.length === 1 ? recipients[0] : undefined);
            }
            return;
        }
        if (frame.encoding === "encrypted" && frame.scheme === EncryptedScheme.split) {
            let utxos;
            try {
                const { txViewingPublicKey, salt } = this.#envelope(tx);
                utxos = splitBundleUtxos(decodeSplitBundle(key.decryptUtxo(body, txViewingPublicKey, salt, site.slot)), this.#assets);
            }
            catch (error) {
                this.#noteUndecryptable(error, siteKey);
                return;
            }
            this.#resolveAssetCandidate(siteKey);
            for (const utxo of utxos)
                this.#storeInTx(utxo, tx);
            this.#processedSlots.add(siteKey);
            if (!this.#processedOutbound.has(site.transaction)) {
                this.#processedOutbound.add(site.transaction);
                this.#recordSplit(tx, this.#spentAmounts(tx.nullifiers));
            }
            return;
        }
        this.undecryptableCandidates++;
    }
    /** Reconstruct the ciphertext-free merge output from this wallet's spent inputs. */
    #reconstructMerge(tx, site, siteKey) {
        const slot = tx.outputSlots[site.slot];
        const firstNullifier = tx.nullifiers[0];
        if (slot === undefined ||
            firstNullifier === undefined ||
            !this.#utxos.some((entry) => equal(entry.nullifier, firstNullifier))) {
            this.undecryptableCandidates++;
            return;
        }
        try {
            const matched = [];
            for (const [index, nullifier] of tx.nullifiers.entries()) {
                if (equal(nullifier, mergeDummyNullifier(this.#nullifierKey, firstNullifier, index))) {
                    continue;
                }
                const entry = this.#utxos.find((candidate) => equal(candidate.nullifier, nullifier));
                if (entry === undefined) {
                    this.undecryptableCandidates++;
                    return;
                }
                matched.push(entry);
            }
            const first = matched[0];
            if (first === undefined || matched.some((entry) => entry.utxo.asset !== first.utxo.asset)) {
                this.undecryptableCandidates++;
                return;
            }
            let amount = 0n;
            for (const entry of matched) {
                amount += entry.utxo.amount;
                if (amount > U64_MAX)
                    throw new TransactionError("TRANSACTION_WALLET_BALANCE_OVERFLOW");
            }
            const zoneProgramId = first.utxo.zoneProgramId;
            if (matched.some((entry) => entry.utxo.zoneProgramId !== zoneProgramId)) {
                this.undecryptableCandidates++;
                return;
            }
            const zoneDataHash = zoneProgramId === undefined
                ? undefined
                : slot.payload.length === 32
                    ? copy(slot.payload)
                    : null;
            if (zoneDataHash === null) {
                this.undecryptableCandidates++;
                return;
            }
            const utxo = new Utxo({
                owner: this.#owner,
                asset: first.utxo.asset,
                amount,
                blinding: mergeOutputBlinding(this.#nullifierKey, firstNullifier),
                ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
            });
            if (this.#storeRecipientUtxos([utxo], slot.outputContext, undefined, zoneDataHash)) {
                this.#processedSlots.add(siteKey);
                this.#recordMerge(tx, slot.outputContext, utxo);
            }
            return;
        }
        catch (error) {
            this.#noteUndecryptable(error, siteKey);
        }
    }
    /** The published transaction key and salt every encrypted scheme opens under. */
    #envelope(tx) {
        if (tx.txViewingPublicKey === undefined || tx.salt === undefined) {
            throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "envelope" });
        }
        return { txViewingPublicKey: tx.txViewingPublicKey, salt: tx.salt };
    }
    #decryptFor(key, tx, body, slotIndex) {
        const { txViewingPublicKey, salt } = this.#envelope(tx);
        return decryptAnonymous(key, txViewingPublicKey, body, salt, slotIndex);
    }
    /**
     * Open only the two stable discovery families: this viewing key's bootstrap
     * tag and the shielded identity's signing tag.
     */
    processStableTags(key, input) {
        const { index } = input;
        const recipientSites = (tag) => index.recipientSites.get(tag) ?? [];
        for (const site of recipientSites(hex(key.recipientBootstrapViewTag()))) {
            this.decodeSlot(key, site);
        }
        const identityTag = hex(input.identityTag);
        for (const site of recipientSites(identityTag))
            this.decodeSlot(key, site);
        for (const transaction of index.senderSites.get(identityTag) ?? []) {
            this.decodeSlot(key, { transaction, slot: 0 });
        }
        this.#transactions.forEach((tx, position) => {
            this.recordConfidentialSend(tx, position, key);
        });
    }
}
export async function decryptTransactions(input) {
    const material = await input.authority.syncMaterial();
    validateMaterial(input.wallet, material);
    const current = input.wallet._state();
    const index = buildTagIndex(input.transactions);
    const pass = new SyncPass({
        material,
        assets: input.wallet.registry,
        transactions: input.transactions,
        utxos: current.utxos,
        rows: current.transactions,
    });
    const identityTag = material.identity.signingPublicKey.confidentialViewTag();
    const viewingKeyHistory = ensureViewingKeyEntries(current.viewingKeyHistory, material.viewingKeys);
    for (const entry of viewingKeyHistory) {
        const id = hex(entry.viewingPublicKey.toBytes());
        const key = material.viewingKeys.find((candidate) => hex(candidate.publicKey().toBytes()) === id);
        if (key !== undefined)
            pass.processStableTags(key, { identityTag, index });
    }
    const nullifiers = new Set(current.nullifiers);
    for (const tx of input.transactions) {
        for (const nullifier of tx.nullifiers)
            nullifiers.add(hex(nullifier));
    }
    const utxos = pass
        .utxos()
        .map((entry) => entry.spent || !nullifiers.has(hex(entry.nullifier))
        ? entry
        : Object.freeze({ ...entry, spent: true }));
    const transactions = [...pass.rows()].sort((left, right) => compareBigints(left.id.slot, right.id.slot) ||
        left.id.signature.localeCompare(right.id.signature) ||
        compareBigints(left.id.index, right.id.index));
    input.wallet._replace({
        utxos,
        transactions,
        nullifiers,
        viewingKeyHistory,
        lastSynced: input.config?.syncedAt ?? 0n,
    });
    return Object.freeze({
        storedUtxos: pass.storedUtxos,
        unparsedTransactions: index.unparsedTransactions,
        undecryptableCandidates: pass.undecryptableCandidates,
        unknownAssetIds: pass.unknownAssetIds(),
        unknownAssetFields: pass.unknownAssetFields(),
    });
}
export async function decryptTransactionsWorkerEquivalent(input) {
    return decryptTransactions(input);
}
