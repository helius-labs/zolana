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
  generateKeyPairSigner,
  lamports,
  type Address,
  type Instruction,
  type KeyPairSigner,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  ShieldedKeypair,
  SigningKey,
  SPL_TOKEN_2022_PROGRAM_ID,
  Wallet,
  buildDepositTransaction,
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
  buildRingExitTransaction,
  buildRingLookupTableTransaction,
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
  fetchReaderGrant,
  fetchRingProgramConfig,
  grantReadAccessInstruction,
  messageSignerReader,
  revokeReadAccessInstruction,
  readerKeyBytes,
  type RingReadSigner,
} from "../../src/ring/index.js";
import type { ZolanaClient } from "../../src/client/client.js";
import { compileUnsignedTransaction } from "../../src/flows/compile.js";
import {
  currentSlot,
  signSendAndConfirm,
  signerFromWalletFile,
  tokenBalance,
  waitForSignature,
} from "./live-helpers.js";

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
  const transaction = compileUnsignedTransaction({
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

/** The indexer and the ring RPC lag behind confirmation, so the view is polled. */
async function waitForAudited(
  ringRpc: RingRpc,
  ringProgramId: Address,
  signer: KeyPairSigner,
  signature: string,
) {
  for (let attempt = 0; attempt < 120; attempt++) {
    const view = await ringRpc.getDecryptedTransactions({
      ringProgramId,
      signer: messageSignerReader(signer),
    });
    const item = view.items.find((entry) => entry.signature === signature);
    if (item !== undefined) return item;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`transaction ${signature} did not reach the ring view`);
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
      ringProgramId,
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
      ringProgramId,
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

  it("carries a token-2022 mint in from the default ring, back out, and into a public withdrawal", async () => {
    const ringProgramId = address(requiredEnv("RING_PROGRAM_ID"));
    // The Token-2022 test mint, the legacy mint's vault is asserted absolutely
    // by the private-flow suite.
    const mint = address(requiredEnv("ZOLANA_TEST_TOKEN_2022_MINT"));
    const fundingTokenAccount = address(requiredEnv("ZOLANA_TEST_TOKEN_2022_ACCOUNT"));
    const client = await createZolanaClient({
      solanaRpcUrl: requiredEnv("ZOLANA_LOCALNET_URL"),
      indexerUrl: requiredEnv("ZOLANA_INDEXER_URL"),
      proverUrl: requiredEnv("ZOLANA_PROVER_URL"),
      tree: address(requiredEnv("ZOLANA_TREE")),
    });
    const ringRpc = new RingRpc(requiredEnv("RING_RPC_URL"));
    const authoritySigner = await keypairSignerFromFile(requiredEnv("RING_AUTHORITY_KEYPAIR"));
    const mintAuthority = await signerFromWalletFile(requiredEnv("ZOLANA_TEST_AUTHORITY_WALLET"));

    const sender = await freshActor();
    const recipient = await freshActor();
    await airdrop(client, sender.signer.address);
    await airdrop(client, recipient.signer.address);

    // The bring-up mints 1_000_000 raw units and later suites share the supply.
    const deposited = 40_000n;
    const entry = 25_000n;
    const exit = 10_000n;
    const withdrawn = 5_000n;

    // The authority wallet funds the default deposit from its own token account.
    const deposit = await buildDepositTransaction({
      client,
      feePayer: mintAuthority.address,
      recipient: sender.keypair.shieldedAddress(),
      asset: mint,
      amount: deposited,
      splTokenAccount: fundingTokenAccount,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    await signSendAndConfirm(client, deposit, [mintAuthority]);
    await sync(client, sender);
    const defaultNotes = sender.wallet
      .utxos()
      .filter((note) => !note.spent && note.utxo.asset === mint);
    expect(defaultNotes.map((note) => [note.utxo.amount, note.utxo.ringProgramId])).toEqual([
      [deposited, undefined],
    ]);

    const table = await buildRingLookupTableTransaction({
      client,
      ringProgramId,
      feePayer: sender.signer.address,
    });
    await signSendAndConfirm(client, table.transaction, [sender.signer]);
    const writtenAt = await currentSlot(client);
    while ((await currentSlot(client)) <= writtenAt) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    // Entry, the default note funds a ring transfer.
    const entryTransaction = await buildRingTransferTransaction({
      client,
      ringProgramId,
      wallet: sender.wallet,
      authority: sender.authority,
      feePayer: sender.signer.address,
      recipient: recipient.keypair.shieldedAddress(),
      asset: mint,
      amount: entry,
      inputs: "default",
      lookupTable: table.address,
    });
    const entrySignature = await signSendAndConfirm(client, entryTransaction, [sender.signer]);
    const entryAudited = await waitForAudited(
      ringRpc,
      ringProgramId,
      authoritySigner,
      entrySignature,
    );
    expect(entryAudited.outputs.map((output) => output.asset)).toEqual([mint, mint]);
    expect(entryAudited.outputs.map((output) => output.ringProgramId)).toEqual([
      ringProgramId,
      ringProgramId,
    ]);
    await sync(client, recipient);
    const ringNotes = recipient.wallet
      .utxos()
      .filter((note) => !note.spent && note.utxo.asset === mint);
    expect(ringNotes.map((note) => [note.utxo.amount, note.utxo.ringProgramId])).toEqual([
      [entry, ringProgramId],
    ]);

    // A relayed transact proves, carries the owner as an extra signer, and
    // dies at the packet limit, the extra signature and static owner key
    // exceed the room the two proofs and framed outputs leave.
    const relayer = await generateKeyPairSigner();
    await expect(
      buildRingExitTransaction({
        client,
        ringProgramId,
        wallet: recipient.wallet,
        authority: recipient.authority,
        feePayer: relayer.address,
        recipient: sender.keypair.shieldedAddress(),
        asset: mint,
        amount: exit,
        lookupTable: table.address,
      }),
    ).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "INTERFACE_TRANSACTION_TOO_LARGE",
    });

    // Exit, part of the ring note returns to the sender's default ring.
    const exitTransaction = await buildRingExitTransaction({
      client,
      ringProgramId,
      wallet: recipient.wallet,
      authority: recipient.authority,
      feePayer: recipient.signer.address,
      recipient: sender.keypair.shieldedAddress(),
      asset: mint,
      amount: exit,
      lookupTable: table.address,
    });
    const exitSignature = await signSendAndConfirm(client, exitTransaction, [recipient.signer]);
    const exitAudited = await waitForAudited(
      ringRpc,
      ringProgramId,
      authoritySigner,
      exitSignature,
    );
    const exitRings = new Map(
      exitAudited.outputs.map((output) => [output.amount, output.ringProgramId]),
    );
    expect(exitRings.has(exit)).toBe(true);
    expect(exitRings.get(exit)).toBeUndefined();
    expect(exitRings.get(entry - exit)).toBe(ringProgramId);
    await sync(client, sender);
    const senderNotes = sender.wallet
      .utxos()
      .filter((note) => !note.spent && note.utxo.asset === mint)
      .map((note) => [note.utxo.amount, note.utxo.ringProgramId] as const)
      .sort((a, b) => (a[0] < b[0] ? -1 : 1));
    expect(senderNotes).toEqual([
      [exit, undefined],
      [deposited - entry, ringProgramId],
    ]);

    // The remaining ring note settles a public withdrawal into the funding account.
    await sync(client, recipient);
    const before = await tokenBalance(client, fundingTokenAccount);
    const withdrawalTransaction = await buildRingWithdrawalTransaction({
      client,
      ringProgramId,
      wallet: recipient.wallet,
      authority: recipient.authority,
      feePayer: recipient.signer.address,
      recipient: mintAuthority.address,
      asset: mint,
      amount: withdrawn,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
      lookupTable: table.address,
    });
    const withdrawalSignature = await signSendAndConfirm(client, withdrawalTransaction, [
      recipient.signer,
    ]);
    await waitForAudited(ringRpc, ringProgramId, authoritySigner, withdrawalSignature);
    expect((await tokenBalance(client, fundingTokenAccount)) - before).toBe(withdrawn);
  }, 600_000);
});
