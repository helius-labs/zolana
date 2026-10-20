import { compileUnsignedTransaction } from "../flows/compile.js";
import { DEFAULT_COMPUTE_UNIT_LIMIT, checkedAddress } from "../flows/internal.js";
import type { BlockhashProvider, ChainReader, TreeContext } from "../client/ports.js";
import type {
  Address,
  AssetDeposit,
  Bytes32,
  DepositAsset,
  Instruction,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import {
  decodeProtocolConfigAccount,
  decodeSplAssetRegistryAccount,
} from "../interface/codecs/index.js";
import {
  createSplInterfaceInstruction,
  depositInstruction,
} from "../interface/instructions/index.js";
import { protocolConfigAddress, splAssetRegistryAddress } from "../interface/pda/index.js";
import { initializePoseidon } from "../hasher/index.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { SOL_MINT } from "../transaction/asset.js";

import { resolveDepositSettlement } from "../flows/settlement.js";

import { WalletError, wrapWalletError } from "./error.js";
import { resolveShieldedRecipient } from "./registry.js";

/** @internal */
export interface DepositParams {
  readonly recipient: ShieldedAddress;
  readonly asset: Address;
  readonly amount: bigint;
  readonly depositor?: Address;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
}

/** @internal */
export class Deposit {
  readonly data: Omit<AssetDeposit, "asset">;
  readonly asset: Address;
  readonly settlement: DepositAsset;

  constructor(
    input: Readonly<{
      data: Omit<AssetDeposit, "asset">;
      asset: Address;
      settlement: DepositAsset;
    }>,
  ) {
    this.data = Object.freeze({
      ...input.data,
      viewTag: new Uint8Array(input.data.viewTag) as Bytes32,
      recipientOwnerHash: new Uint8Array(input.data.recipientOwnerHash) as Bytes32,
      ...(input.data.memo === undefined ? {} : { memo: new Uint8Array(input.data.memo) }),
    });
    this.asset = input.asset;
    this.settlement = input.settlement;
  }

  instruction(tree: Address, sender: Address): Promise<Instruction> {
    return depositInstruction({
      tree,
      depositor: sender,
      deposits: [{ ...this.data, asset: this.settlement }],
    });
  }

  viewTag(): Bytes32 {
    return new Uint8Array(this.data.viewTag) as Bytes32;
  }
}

/** @internal */
export async function createDeposit(params: DepositParams): Promise<Deposit> {
  try {
    await initializePoseidon();
    if (params.amount <= 0n || params.amount > 0xffff_ffff_ffff_ffffn) {
      throw new WalletError("WALLET_INVALID_AMOUNT", {
        details: { amount: params.amount.toString() },
      });
    }
    const recipientOwnerHash = params.recipient.ownerHash();
    const data: Omit<AssetDeposit, "asset"> = {
      // Confidential rings key the owner tag off the signing key, and the
      // wallet sync reads it back that way. The viewing key is a different key.
      viewTag: params.recipient.confidentialViewTag(),
      recipientOwnerHash,
      amount: params.amount,
      ...(params.memo === undefined ? {} : { memo: new Uint8Array(params.memo) }),
    };
    // A SOL deposit needs no token accounts, so one supplied alongside it is
    // ignored rather than rejected.
    const settlement = await resolveDepositSettlement(
      {
        asset: params.asset,
        ...(params.depositor === undefined ? {} : { depositor: params.depositor }),
        ...(params.splTokenAccount === undefined
          ? {}
          : { splTokenAccount: params.splTokenAccount }),
        ...(params.splTokenProgram === undefined
          ? {}
          : { splTokenProgram: params.splTokenProgram }),
      },
      () =>
        new WalletError("WALLET_MISSING_SPL_TOKEN_ACCOUNT", {
          details: { mint: params.asset },
        }),
    );
    // The blinding comes from the leaf index the output lands at, so read the
    // UTXO hash from the event.
    return new Deposit({
      data,
      asset: params.asset,
      settlement,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_CREATE_DEPOSIT", cause);
  }
}

export type DepositClient = TreeContext & BlockhashProvider & Pick<ChainReader, "getAccount">;

export interface DepositTransactionParams {
  readonly client: DepositClient;
  readonly feePayer: Address;
  readonly depositor?: Address;
  readonly tree?: Address;
  readonly recipient: Address | ShieldedAddress;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenAccount?: Address;
  readonly splTokenProgram?: Address | null;
  readonly memo?: Uint8Array;
  /**
   * Prepend the instruction that creates the mint's registry entry and vault
   * when the mint has none, paid for by the depositor. Defaults to true and is
   * ignored for SOL. Two first deposits of one mint built concurrently both
   * carry the creation, so the second to land fails.
   */
  readonly createSplInterface?: boolean;
  /** Placed verbatim before every other instruction, in order. */
  readonly setupInstructions?: readonly Instruction[];
}

/**
 * Whether a deposit of `mint` must first create its SPL interface. Throws when
 * creation is needed but the depositor may not do it, so a transaction known to
 * fail on chain is never built.
 */
async function splInterfaceCreationNeeded(
  client: Pick<ChainReader, "getAccount">,
  mint: Address,
  depositor: Address,
  context?: RequestContext,
): Promise<boolean> {
  const registry = await client.getAccount(await splAssetRegistryAddress(mint), context);
  // Anyone can send lamports to the registry PDA before it is created, which
  // leaves a data-less account the program's create path still accepts. Any
  // account with data is decoded, so a malformed one fails instead of passing.
  if (registry !== undefined && registry.data.length > 0) {
    decodeSplAssetRegistryAccount(registry.data);
    return false;
  }
  const configAccount = await client.getAccount(await protocolConfigAddress(), context);
  if (configAccount === undefined) {
    throw new WalletError("WALLET_PROTOCOL_CONFIG_NOT_FOUND", { details: { mint } });
  }
  const config = decodeProtocolConfigAccount(configAccount.data);
  // The program's create_spl_interface check owns this policy.
  if (!config.splInterfaceCreationIsPermissionless && config.authority !== depositor) {
    throw new WalletError("WALLET_SPL_INTERFACE_CREATION_RESTRICTED", {
      details: { mint, depositor },
    });
  }
  return true;
}

/** Caller-built instructions are structural objects, so their addresses are revalidated. */
function checkedSetupInstruction(instruction: Instruction, index: number): void {
  checkedAddress(instruction.programAddress, `setupInstructions[${String(index)}].programAddress`);
  instruction.accounts?.forEach((account, slot) =>
    checkedAddress(
      account.address,
      `setupInstructions[${String(index)}].accounts[${String(slot)}].address`,
    ),
  );
}

export async function buildDepositTransaction(
  input: DepositTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    input.setupInstructions?.forEach(checkedSetupInstruction);
    const recipient = await resolveShieldedRecipient(
      { rpc: input.client, recipient: input.recipient },
      (unregistered) =>
        new WalletError("WALLET_RECIPIENT_NOT_REGISTERED", {
          details: { recipient: unregistered },
        }),
      context,
    );
    const depositor = input.depositor ?? input.feePayer;
    const tree = input.tree ?? input.client.tree;
    const asset = input.asset ?? SOL_MINT;
    const deposit = await createDeposit({
      recipient,
      asset,
      amount: input.amount,
      depositor,
      ...(input.splTokenAccount === undefined ? {} : { splTokenAccount: input.splTokenAccount }),
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
      ...(input.memo === undefined ? {} : { memo: input.memo }),
    });
    const createInterface =
      asset !== SOL_MINT &&
      (input.createSplInterface ?? true) &&
      (await splInterfaceCreationNeeded(input.client, asset, depositor, context));
    const instructions = [
      ...(createInterface
        ? [
            await createSplInterfaceInstruction({
              authority: depositor,
              mint: asset,
              ...(input.splTokenProgram === undefined
                ? {}
                : { tokenProgram: input.splTokenProgram }),
            }),
          ]
        : []),
      await deposit.instruction(tree, depositor),
    ];
    const lifetime = await input.client.getLatestBlockhash(context);
    return compileUnsignedTransaction({
      feePayer: input.feePayer,
      lifetime,
      computeUnitLimit: DEFAULT_COMPUTE_UNIT_LIMIT,
      ...(input.setupInstructions === undefined
        ? {}
        : { setupInstructions: input.setupInstructions }),
      instructions,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_DEPOSIT", cause);
  }
}
