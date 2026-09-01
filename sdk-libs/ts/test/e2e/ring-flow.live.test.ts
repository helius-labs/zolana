// Needs a running ring with its RPC started with RING_RPC_ALLOW_ORIGINS naming
// RING_ORIGIN (default http://localhost:3000). Reads ZOLANA_LOCALNET_URL,
// ZOLANA_INDEXER_URL, ZOLANA_PROVER_URL, ZOLANA_TREE, RING_PROGRAM_ID, RING_RPC_URL
// and RING_AUTHORITY_KEYPAIR. That key owns the ring config and holds a reader
// grant, every ring read is grant only.
import { readFile } from "node:fs/promises";

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import {
  address,
  createKeyPairSignerFromBytes,
  lamports,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  ShieldedKeypair,
  SigningKey,
  Wallet,
  createZolanaClient,
  syncWallet,
  type Bytes32,
} from "../../src/index.js";
import { LocalWalletAuthority } from "../../src/transaction/wallet/authority.js";
import { sha256 } from "../../src/interface/internal.js";
import { P256PublicKey } from "../../src/keypair/public-key.js";
import {
  RingError,
  RingRpc,
  buildRingDepositTransaction,
  buildRingLookupTableTransaction,
  buildRingTransferTransaction,
  fetchReaderGrant,
  fetchRingProgramConfig,
  grantReadAccessInstruction,
  messageSignerReader,
  revokeReadAccessInstruction,
  readerKeyBytes,
  type RingReadSigner,
} from "../../src/ring/index.js";
import type { ZolanaClient } from "../../src/client/client.js";
import { buildUnsignedTransaction } from "../../src/client/kit.js";
import { currentSlot, signSendAndConfirm, waitForSignature } from "./live-helpers.js";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`the ring live test requires ${name}`);
  return value;
}

interface Actor {
  readonly signer: KeyPairSigner;
  readonly keypair: ShieldedKeypair;
  readonly wallet: Wallet;
  readonly authority: LocalWalletAuthority;
}

async function freshActor(): Promise<Actor> {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  const signer = await createKeyPairSignerFromBytes(
    Uint8Array.of(...seed, ...ed25519.getPublicKey(seed)),
  );
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed as Bytes32));
  return {
    signer,
    keypair,
    wallet: new Wallet({ identity: keypair.shieldedAddress() }),
    authority: new LocalWalletAuthority({ solanaPublicKey: signer.address, keypair }),
  };
}

async function airdrop(client: ZolanaClient, recipient: Address): Promise<void> {
  const signature = await client.solanaRpc
    .requestAirdrop(recipient, lamports(5_000_000_000n))
    .send();
  await waitForSignature(client.solanaRpc, signature);
}

async function keypairSignerFromFile(path: string): Promise<KeyPairSigner> {
  const bytes = Uint8Array.from(JSON.parse(await readFile(path, "utf8")) as number[]);
  return createKeyPairSignerFromBytes(bytes);
}

async function sendInstruction(
  client: ZolanaClient,
  instruction: Instruction,
  signer: KeyPairSigner,
): Promise<void> {
  const lifetime = await client.getLatestBlockhash();
  const transaction = buildUnsignedTransaction({
    feePayer: signer.address,
    lifetime,
    instructions: [instruction],
  });
  await signSendAndConfirm(client, transaction, [signer]);
}

/** The WebAuthn envelope a browser would produce on `origin`, signed with a software P-256 key. */
function syntheticPasskey(origin: string): RingReadSigner & { readonly publicKey: P256PublicKey } {
  const secret = p256.utils.randomSecretKey();
  const publicKey = P256PublicKey.fromBytes(p256.getPublicKey(secret, true) as never);
  const host = new URL(origin).hostname;
  return {
    publicKey,
    reader: readerKeyBytes(publicKey),
    sign(message: Uint8Array) {
      const challenge = Buffer.from(sha256(message)).toString("base64url");
      const clientDataJSON = new TextEncoder().encode(
        JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }),
      );
      const authenticatorData = Uint8Array.from([
        ...sha256(new TextEncoder().encode(host)),
        0x05,
        0,
        0,
        0,
        1,
      ]);
      const signed = sha256(Uint8Array.from([...authenticatorData, ...sha256(clientDataJSON)]));
      const signature = p256.sign(signed, secret, { prehash: false, format: "der" });
      return Promise.resolve({ signature, authenticatorData, clientDataJSON });
    },
  };
}

async function ringReadError(
  ringRpc: RingRpc,
  ringProgramId: Address,
  signer: KeyPairSigner | RingReadSigner,
) {
  try {
    await ringRpc.getDecryptedTransactions({
      ringProgramId,
      signer: "reader" in signer ? signer : messageSignerReader(signer),
    });
  } catch (error) {
    if (error instanceof RingError) return error.details?.message;
    throw error;
  }
  return undefined;
}

async function sync(client: ZolanaClient, actor: Actor): Promise<void> {
  await syncWallet({
    client,
    wallet: actor.wallet,
    authority: actor.authority,
    config: { requireSlot: await currentSlot(client) },
  });
}

describe("ring flow", () => {
  it("deposits, transfers audited, and reads back as authority, delegate and passkey", async () => {
    const ringProgramId = address(requiredEnv("RING_PROGRAM_ID"));
    const client = await createZolanaClient({
      solanaRpcUrl: requiredEnv("ZOLANA_LOCALNET_URL"),
      indexerUrl: requiredEnv("ZOLANA_INDEXER_URL"),
      proverUrl: requiredEnv("ZOLANA_PROVER_URL"),
      tree: address(requiredEnv("ZOLANA_TREE")),
    });
    const ringRpc = new RingRpc(requiredEnv("RING_RPC_URL"));
    const health = await ringRpc.health();
    expect(health.mode).toBe("local");

    const sender = await freshActor();
    const recipient = await freshActor();
    await airdrop(client, sender.signer.address);

    const amount = 1_000_000_000n;
    // Input selection stops at the first note that covers the transfer, so the
    // deposits differ and the sender keeps a change output next to the recipient's.
    for (const deposited of [amount * 3n, amount]) {
      const deposit = await buildRingDepositTransaction({
        client,
        ringProgramId,
        feePayer: sender.signer.address,
        recipient: sender.keypair.shieldedAddress(),
        amount: deposited,
      });
      await signSendAndConfirm(client, deposit, [sender.signer]);
    }
    await sync(client, sender);
    expect(
      sender.wallet.utxos().filter((entry) => entry.utxo.ringProgramId === ringProgramId),
    ).toHaveLength(2);

    const table = await buildRingLookupTableTransaction({
      client,
      ringProgramId,
      feePayer: sender.signer.address,
    });
    await signSendAndConfirm(client, table.transaction, [sender.signer]);
    // A lookup table serves transactions only from the slot after its writes.
    const writtenAt = await currentSlot(client);
    while ((await currentSlot(client)) <= writtenAt) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    const transfer = await buildRingTransferTransaction({
      client,
      sourceRing: ringProgramId,
      destinationRing: ringProgramId,
      wallet: sender.wallet,
      authority: sender.authority,
      feePayer: sender.signer.address,
      recipient: recipient.keypair.shieldedAddress(),
      amount,
      lookupTable: table.address,
    });
    const signature = await signSendAndConfirm(client, transfer, [sender.signer]);

    // The indexer lags, so the page is polled.
    const authoritySigner = await keypairSignerFromFile(requiredEnv("RING_AUTHORITY_KEYPAIR"));
    const config = await fetchRingProgramConfig(client, ringProgramId);
    expect(config.authority).toBe(authoritySigner.address);
    let audited;
    for (let attempt = 0; attempt < 120 && audited === undefined; attempt++) {
      const ringView = await ringRpc.getDecryptedTransactions({
        ringProgramId,
        signer: messageSignerReader(authoritySigner),
      });
      audited = ringView.items.find((item) => item.signature === signature);
      if (audited === undefined) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    expect(audited).toBeDefined();
    // The 3x deposit is the covering note, the change slot keeps 2x.
    const amounts = [...(audited?.outputs.map((output) => output.amount) ?? [])].sort((a, b) =>
      a < b ? -1 : 1,
    );
    expect(amounts).toEqual([amount, amount * 2n]);
    expect(audited?.outputs.map((output) => output.ringProgramId)).toEqual([
      ringProgramId,
      ringProgramId,
    ]);

    // Participants read their own side from wallet sync.
    await airdrop(client, recipient.signer.address);
    await sync(client, recipient);
    const notes = recipient.wallet.utxos().filter((entry) => !entry.spent);
    expect(notes.map((entry) => entry.utxo.amount)).toContain(amount);
    expect(notes.map((entry) => entry.utxo.ringProgramId)).toEqual([ringProgramId]);
    await sync(client, sender);
    const change = sender.wallet.utxos().filter((entry) => !entry.spent);
    expect(change.length).toBeGreaterThan(0);
    expect(change.every((entry) => entry.utxo.ringProgramId === ringProgramId)).toBe(true);

    // The received note spends inside the ring again.
    const hop = await buildRingTransferTransaction({
      client,
      sourceRing: ringProgramId,
      destinationRing: ringProgramId,
      wallet: recipient.wallet,
      authority: recipient.authority,
      feePayer: recipient.signer.address,
      recipient: sender.keypair.shieldedAddress(),
      amount: amount / 2n,
      lookupTable: table.address,
    });
    const hopSignature = await signSendAndConfirm(client, hop, [recipient.signer]);
    let hopAudited;
    for (let attempt = 0; attempt < 120 && hopAudited === undefined; attempt++) {
      const ringView = await ringRpc.getDecryptedTransactions({
        ringProgramId,
        signer: messageSignerReader(authoritySigner),
      });
      hopAudited = ringView.items.find((item) => item.signature === hopSignature);
      if (hopAudited === undefined) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    expect(hopAudited?.outputs.map((output) => output.ringProgramId)).toEqual([
      ringProgramId,
      ringProgramId,
    ]);
    // The hop pays half the note onward, the change slot keeps the rest.
    const hopAmounts = [...(hopAudited?.outputs.map((output) => output.amount) ?? [])].sort(
      (a, b) => (a < b ? -1 : 1),
    );
    expect(hopAmounts).toEqual([amount / 2n, amount / 2n]);

    // A delegated reader reads after the grant and not after the revoke.
    const delegate = (await freshActor()).signer;
    expect(await ringReadError(ringRpc, ringProgramId, delegate)).toContain("no active grant");
    await sendInstruction(
      client,
      await grantReadAccessInstruction({
        ringProgramId,
        payer: authoritySigner,
        authority: authoritySigner,
        reader: delegate.address,
      }),
      authoritySigner,
    );
    expect(await fetchReaderGrant(client, ringProgramId, delegate.address)).toBe(true);
    const delegatedView = await ringRpc.getDecryptedTransactions({
      ringProgramId,
      signer: messageSignerReader(delegate),
    });
    expect(delegatedView.items.map((item) => item.signature)).toContain(signature);
    expect(await ringReadError(ringRpc, ringProgramId, sender.signer)).toContain("no active grant");
    await sendInstruction(
      client,
      await revokeReadAccessInstruction({
        ringProgramId,
        authority: authoritySigner,
        reader: delegate.address,
        rentRecipient: authoritySigner.address,
      }),
      authoritySigner,
    );
    expect(await fetchReaderGrant(client, ringProgramId, delegate.address)).toBe(false);
    expect(await ringReadError(ringRpc, ringProgramId, delegate)).toContain("no active grant");

    // The same through a passkey.
    const passkey = syntheticPasskey(process.env.RING_ORIGIN ?? "http://localhost:3000");
    expect(await ringReadError(ringRpc, ringProgramId, passkey)).toContain("no active grant");
    await sendInstruction(
      client,
      await grantReadAccessInstruction({
        ringProgramId,
        payer: authoritySigner,
        authority: authoritySigner,
        reader: passkey.publicKey,
      }),
      authoritySigner,
    );
    expect(await fetchReaderGrant(client, ringProgramId, passkey.publicKey)).toBe(true);
    const passkeyView = await ringRpc.getDecryptedTransactions({
      ringProgramId,
      signer: passkey,
    });
    expect(passkeyView.items.map((item) => item.signature)).toContain(signature);
    const elsewhere = syntheticPasskey("http://evil.example");
    expect(await ringReadError(ringRpc, ringProgramId, elsewhere)).toContain("origin");
    await sendInstruction(
      client,
      await revokeReadAccessInstruction({
        ringProgramId,
        authority: authoritySigner,
        reader: passkey.publicKey,
        rentRecipient: authoritySigner.address,
      }),
      authoritySigner,
    );
    expect(await ringReadError(ringRpc, ringProgramId, passkey)).toContain("no active grant");
  }, 600_000);
});
