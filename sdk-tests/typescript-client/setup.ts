/// <reference types="node" />

import { ZolanaApi } from "@zolana/api";
import { SolanaRpc, ZolanaClient, ZolanaIndexer } from "@zolana/client";
import { ProverClient } from "@zolana/client/prover";
import { TREE_ACCOUNT_SIZE, type Address, type Bytes32 } from "@zolana/interface";
import { createTreeInstruction } from "@zolana/interface/instructions";
import { ShieldedKeypair } from "@zolana/keypair";
import { executeSyncInstruction } from "@zolana/smart-account-client";
import { AssetRegistry, Wallet } from "@zolana/transaction";
import { LocalWalletAuthority } from "@zolana/wallet";
import { startLocalStack, type LocalStack } from "@zolana/test-kit";
import {
  confirm,
  createProtocolConfigInstructions,
  createStandardAccountInstructions,
  minimumBalanceForRentExemption,
  nativeKeypair,
  requestAirdrop,
  sendAndConfirm,
  standardAccounts,
  systemCreateAccountInstruction,
  type NativeKeypair,
} from "@zolana/test-kit/node";

const PAYER_SEED = 1;
const AUTHORITY_SEED = 2;
const TREE_SEED = 3;
const SENDER_SEED = 4;
const RECIPIENT_SEED = 5;

const PAYER_LAMPORTS = 100_000_000_000n;
const AUTHORITY_LAMPORTS = 10_000_000_000n;
const PROTOCOL_VAULT_LAMPORTS = 5_000_000_000n;
const PARTICIPANT_LAMPORTS = 10_000_000_000n;

/**
 * One participant in the example: the shielded key material, the local wallet
 * state its notes are decrypted into, and the native keypair that pays fees.
 * All three derive from a single ed25519 seed, so the participant's Solana
 * address and its shielded address share one key.
 */
export interface ExampleParticipant {
  readonly keypair: ShieldedKeypair;
  readonly authority: LocalWalletAuthority;
  readonly wallet: Wallet;
  readonly native: NativeKeypair;
  readonly address: Address;
}

export interface ExampleContext {
  readonly stack: LocalStack;
  readonly client: ZolanaClient;
  readonly tree: Address;
  readonly assets: AssetRegistry;
  readonly sender: ExampleParticipant;
  readonly recipient: ExampleParticipant;
  stop(): Promise<void>;
}

function seedBytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function participant(seed: number): ExampleParticipant {
  const bytes = seedBytes(seed);
  const keypair = ShieldedKeypair.fromEd25519(bytes, 0);
  const native = nativeKeypair(bytes);
  return Object.freeze({
    keypair,
    authority: new LocalWalletAuthority({ solanaPublicKey: native.address, keypair }),
    wallet: new Wallet({ identity: keypair.shieldedAddress(), registry: new AssetRegistry() }),
    native,
    address: native.address,
  });
}

/**
 * Brings up a validator, prover, and indexer, then puts the protocol into the
 * state the example needs: the Squads settings accounts exist, the protocol
 * config names the protocol vault as the protocol, forester, merge, tree, and
 * zone authority, and one state tree is live. Returns two funded participants
 * sharing that tree.
 */
export async function setup(
  input: Readonly<{ portOffset?: number }> = {},
): Promise<ExampleContext> {
  const stack = await startLocalStack(
    input.portOffset === undefined ? {} : { portOffset: input.portOffset },
  );
  try {
    const rpc = new SolanaRpc({ url: stack.rpcUrl });
    const accounts = standardAccounts();
    const payer = nativeKeypair(seedBytes(PAYER_SEED));
    const authority = nativeKeypair(seedBytes(AUTHORITY_SEED));
    const tree = nativeKeypair(seedBytes(TREE_SEED));
    const sender = participant(SENDER_SEED);
    const recipient = participant(RECIPIENT_SEED);

    // Each airdrop is its own transaction, and the funded accounts sign the
    // very next one, so every airdrop has to be confirmed before continuing.
    const airdrops = await Promise.all(
      (
        [
          [payer.address, PAYER_LAMPORTS],
          [authority.address, AUTHORITY_LAMPORTS],
          [accounts.protocolVault, PROTOCOL_VAULT_LAMPORTS],
          [sender.address, PARTICIPANT_LAMPORTS],
          [recipient.address, PARTICIPANT_LAMPORTS],
        ] as const
      ).map(([address, lamports]) =>
        requestAirdrop({ rpcUrl: stack.rpcUrl, address, lamports }),
      ),
    );
    await Promise.all(airdrops.map((signature) => confirm({ rpc, signature })));

    // Every settings account is created with the same signer, so one keypair
    // authorizes protocol, forester, merge, tree, and zone actions.
    for (const instruction of createStandardAccountInstructions({
      creator: payer.address,
      signers: {
        protocol: authority.address,
        forester: authority.address,
        merge: authority.address,
        tree: authority.address,
        zone: authority.address,
      },
    })) {
      await sendAndConfirm({
        rpc,
        feePayer: payer.address,
        instructions: [instruction],
        keypairs: [payer],
      });
    }

    await sendAndConfirm({
      rpc,
      feePayer: payer.address,
      instructions: [
        executeSyncInstruction({
          settings: accounts.protocolSettings,
          accountIndex: 0,
          signerKeys: [authority.address],
          innerInstructions: createProtocolConfigInstructions({
            authority: accounts.protocolVault,
          }),
        }),
      ],
      keypairs: [payer, authority],
    });

    const lamports = await minimumBalanceForRentExemption({
      rpcUrl: stack.rpcUrl,
      space: TREE_ACCOUNT_SIZE,
    });
    await sendAndConfirm({
      rpc,
      feePayer: payer.address,
      instructions: [
        systemCreateAccountInstruction({
          payer: payer.address,
          account: tree.address,
          lamports,
          space: BigInt(TREE_ACCOUNT_SIZE),
        }),
        executeSyncInstruction({
          settings: accounts.protocolSettings,
          accountIndex: 0,
          signerKeys: [authority.address],
          innerInstructions: [
            createTreeInstruction({
              authority: accounts.protocolVault,
              tree: tree.address,
              owner: accounts.protocolVault,
            }),
          ],
        }),
      ],
      keypairs: [payer, tree, authority],
    });

    const client = new ZolanaClient({
      rpc,
      indexer: new ZolanaIndexer(new ZolanaApi({ url: stack.indexerUrl })),
      prover: new ProverClient({ url: stack.proverUrl }),
      tree: tree.address,
    });

    return Object.freeze({
      stack,
      client,
      tree: tree.address,
      assets: new AssetRegistry(),
      sender,
      recipient,
      stop: () => stack.stop(),
    });
  } catch (cause) {
    await stack.stop();
    throw cause;
  }
}
