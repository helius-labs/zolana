/// <reference types="node" />

import { SolanaRpc, ZolanaClient } from "@zolana/client";
import {
  TREE_ACCOUNT_SIZE,
  type Address,
  type Bytes32,
  type TransactionSigner,
} from "@zolana/interface";
import { createTreeInstruction } from "@zolana/interface/instructions";
import { ShieldedKeypair } from "@zolana/keypair";
import { executeSyncInstruction } from "@zolana/smart-account-client";
import { AssetRegistry } from "@zolana/transaction";
import { createSolanaSigner, LocalWalletAuthority } from "@zolana/wallet";
import { startLocalStack, type LocalStack } from "@zolana/test-kit";
import {
  confirm,
  createProtocolConfigInstructions,
  createStandardAccountInstructions,
  minimumBalanceForRentExemption,
  requestAirdrop,
  sendAndConfirm,
  standardAccounts,
  systemCreateAccountInstruction,
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
 * One participant in the example: the shielded key material, the authority that
 * decrypts its notes, and the signer that pays its fees. All three come from a
 * single ed25519 seed, so the participant's Solana address and its shielded
 * address share one key.
 */
export interface ExampleParticipant {
  readonly keypair: ShieldedKeypair;
  readonly authority: LocalWalletAuthority;
  readonly signer: TransactionSigner;
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

function signer(seed: number): TransactionSigner {
  return createSolanaSigner(ShieldedKeypair.fromEd25519(seedBytes(seed), 0));
}

function participant(seed: number): ExampleParticipant {
  const keypair = ShieldedKeypair.fromEd25519(seedBytes(seed), 0);
  const solanaSigner = createSolanaSigner(keypair);
  return Object.freeze({
    keypair,
    authority: new LocalWalletAuthority({ solanaPublicKey: solanaSigner.address, keypair }),
    signer: solanaSigner,
    address: solanaSigner.address,
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
    const accounts = standardAccounts();
    const payer = signer(PAYER_SEED);
    const authority = signer(AUTHORITY_SEED);
    const tree = signer(TREE_SEED);
    const sender = participant(SENDER_SEED);
    const recipient = participant(RECIPIENT_SEED);

    // The tree address comes from a keypair the example holds, so the client
    // can be wired before the account it points at exists.
    const client = ZolanaClient.fromUrls({
      rpc: new SolanaRpc({ url: stack.rpcUrl }),
      indexerUrl: stack.indexerUrl,
      proverUrl: stack.proverUrl,
      tree: tree.address,
    });

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
    await Promise.all(airdrops.map((signature) => confirm({ rpc: client, signature })));

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
      await sendAndConfirm({ client, feePayer: payer, instructions: [instruction] });
    }

    await sendAndConfirm({
      client,
      feePayer: payer,
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
      signers: [authority],
    });

    const lamports = await minimumBalanceForRentExemption({
      rpcUrl: stack.rpcUrl,
      space: TREE_ACCOUNT_SIZE,
    });
    await sendAndConfirm({
      client,
      feePayer: payer,
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
            createTreeInstruction({ authority: accounts.protocolVault, tree: tree.address }),
          ],
        }),
      ],
      signers: [tree, authority],
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
