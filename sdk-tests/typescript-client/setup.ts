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
import { createSolanaSigner } from "@zolana/wallet";
import { startLocalStack } from "@zolana/test-kit";
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
 * Infra for the example: localnet URLs, one live state tree, and two funded
 * shielded keypairs. The example constructs the client and participant wiring.
 */
export interface ExampleContext {
  readonly rpcUrl: URL;
  readonly indexerUrl: URL;
  readonly proverUrl: URL;
  readonly tree: Address;
  readonly sender: ShieldedKeypair;
  readonly recipient: ShieldedKeypair;
  stop(): Promise<void>;
}

function seedBytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function signer(seed: number): TransactionSigner {
  return createSolanaSigner(ShieldedKeypair.fromEd25519(seedBytes(seed), 0));
}

function fundedKeypair(seed: number): { keypair: ShieldedKeypair; address: Address } {
  const keypair = ShieldedKeypair.fromEd25519(seedBytes(seed), 0);
  return { keypair, address: createSolanaSigner(keypair).address };
}

/**
 * Brings up a validator, prover, and indexer, then puts the protocol into the
 * state the example needs: the Squads settings accounts exist, the protocol
 * config names the protocol vault as the protocol, forester, merge, tree, and
 * zone authority, and one state tree is live. Returns two funded keypairs
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
    const sender = fundedKeypair(SENDER_SEED);
    const recipient = fundedKeypair(RECIPIENT_SEED);

    // Temporary client for setup RPCs only; the example builds its own.
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
      rpcUrl: stack.rpcUrl,
      indexerUrl: stack.indexerUrl,
      proverUrl: stack.proverUrl,
      tree: tree.address,
      sender: sender.keypair,
      recipient: recipient.keypair,
      stop: () => stack.stop(),
    });
  } catch (cause) {
    await stack.stop();
    throw cause;
  }
}
