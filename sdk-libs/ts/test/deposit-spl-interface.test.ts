import {
  address,
  decompileTransactionMessage,
  getAddressEncoder,
  getCompiledTransactionMessageDecoder,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
  SPL_TOKEN_2022_PROGRAM_ID,
} from "../src/interface/index.js";
import { decodeProtocolConfigAccount } from "../src/interface/codecs/index.js";
import { SYSTEM_PROGRAM } from "../src/interface/instructions/index.js";
import { PROTOCOL_CONFIG_SIZE, StateDiscriminator } from "../src/interface/state.js";
import { protocolConfigAddress, splAssetRegistryAddress } from "../src/interface/pda/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { SOL_MINT } from "../src/transaction/index.js";
import {
  buildDepositTransaction,
  type DepositClient,
  type DepositTransactionParams,
} from "../src/wallet/deposit.js";
import type { RpcAccount } from "../src/client/rpc.js";
import type { Instruction, Transaction } from "../src/interface/types.js";

import { depositClient } from "./helpers/clients.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const OTHER = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const MINT = address("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");

// Rust `ProtocolConfig`: discriminator, five addresses (authority first), then
// the tree-creation, ring-activation and SPL-interface permission flags.
const AUTHORITY_OFFSET = 1;
const SPL_INTERFACE_PERMISSIONLESS_OFFSET = 1 + 5 * 32 + 2;
// Rust `SplAssetRegistry`: discriminator, seven reserved bytes, mint, asset id.
const SPL_ASSET_REGISTRY_SIZE = 48;
const REGISTRY_MINT_OFFSET = 8;

function protocolConfig(authority: Address, permissionless: boolean): RpcAccount {
  const data = new Uint8Array(PROTOCOL_CONFIG_SIZE);
  data[0] = StateDiscriminator.protocolConfig;
  data.set(getAddressEncoder().encode(authority), AUTHORITY_OFFSET);
  data[SPL_INTERFACE_PERMISSIONLESS_OFFSET] = permissionless ? 1 : 0;
  // Pin the fixture to the decoder so a layout change fails here, not silently.
  expect(decodeProtocolConfigAccount(data)).toMatchObject({
    authority,
    splInterfaceCreationIsPermissionless: permissionless,
  });
  return { owner: SHIELDED_POOL_PROGRAM_ID, data, lamports: 1n };
}

function registryEntry(): RpcAccount {
  const data = new Uint8Array(SPL_ASSET_REGISTRY_SIZE);
  data[0] = StateDiscriminator.splAssetRegistry;
  data.set(getAddressEncoder().encode(MINT), REGISTRY_MINT_OFFSET);
  return { owner: SHIELDED_POOL_PROGRAM_ID, data, lamports: 1n };
}

/** A client whose chain holds only the given protocol config and registry entry. */
async function chain(accounts: Readonly<{ config?: RpcAccount; registry?: RpcAccount }>) {
  const byAddress = new Map([
    [await protocolConfigAddress(), accounts.config],
    [await splAssetRegistryAddress(MINT), accounts.registry],
  ]);
  return {
    getAccount: vi.fn(async (account: Address) => byAddress.get(account)),
    getLatestBlockhash: vi.fn(depositClient().getLatestBlockhash),
  };
}

function splDepositParams(
  client: Partial<DepositClient>,
  overrides: Partial<DepositTransactionParams> = {},
): DepositTransactionParams {
  return {
    client: depositClient(client),
    feePayer: PAYER,
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    asset: MINT,
    amount: 5n,
    splTokenAccount: OTHER,
    ...overrides,
  };
}

function splDeposit(
  client: Partial<DepositClient>,
  overrides: Partial<DepositTransactionParams> = {},
): Promise<Transaction> {
  return buildDepositTransaction(splDepositParams(client, overrides));
}

function instructionsOf(transaction: Transaction): readonly Instruction[] {
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  return decompileTransactionMessage(compiled, { lastValidBlockHeight: 1n }).instructions;
}

function tagsOf(transaction: Transaction): number[] {
  return instructionsOf(transaction).map((instruction) => instruction.data?.[0] ?? -1);
}

const CREATE_THEN_DEPOSIT = [InstructionTag.createSplInterface, InstructionTag.deposit];

describe("deposit SPL interface setup", () => {
  it("prepends the interface creation when the mint has no registry entry", async () => {
    const transaction = await splDeposit(await chain({ config: protocolConfig(OTHER, true) }));
    expect(tagsOf(transaction)).toEqual(CREATE_THEN_DEPOSIT);
    const [create] = instructionsOf(transaction);
    expect(create?.accounts?.[0]?.address).toBe(PAYER);
  });

  it("still creates the interface when someone sent lamports to the registry PDA", async () => {
    const transaction = await splDeposit(
      await chain({
        config: protocolConfig(OTHER, true),
        registry: { owner: SYSTEM_PROGRAM, data: new Uint8Array(0), lamports: 1n },
      }),
    );
    expect(tagsOf(transaction)).toEqual(CREATE_THEN_DEPOSIT);
  });

  it("builds only the deposit when the registry entry exists", async () => {
    const client = await chain({ registry: registryEntry() });
    const transaction = await splDeposit(client);
    expect(tagsOf(transaction)).toEqual([InstructionTag.deposit]);
    expect(client.getAccount).toHaveBeenCalledOnce();
  });

  it("refuses a registry account whose data does not decode", async () => {
    const registry = { ...registryEntry(), data: Uint8Array.of(0xff, 0, 0) };
    const client = await chain({ registry });
    await expect(splDeposit(client)).rejects.toMatchObject({
      code: "WALLET_BUILD_DEPOSIT",
      causeCode: "INTERFACE_INVALID_ACCOUNT_DATA",
    });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("does not look anything up when createSplInterface is false", async () => {
    const client = await chain({});
    const transaction = await splDeposit(client, { createSplInterface: false });
    expect(tagsOf(transaction)).toEqual([InstructionTag.deposit]);
    expect(client.getAccount).not.toHaveBeenCalled();
  });

  it("ignores createSplInterface: true for SOL", async () => {
    const client = await chain({});
    const transaction = await splDeposit(client, { asset: SOL_MINT, createSplInterface: true });
    expect(tagsOf(transaction)).toEqual([InstructionTag.deposit]);
    expect(client.getAccount).not.toHaveBeenCalled();
  });

  it("refuses a depositor that may not create the interface, before the blockhash", async () => {
    const client = await chain({ config: protocolConfig(OTHER, false) });
    await expect(splDeposit(client)).rejects.toMatchObject({
      code: "WALLET_BUILD_DEPOSIT",
      causeCode: "WALLET_SPL_INTERFACE_CREATION_RESTRICTED",
    });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("lets the protocol authority create the interface when creation is restricted", async () => {
    const transaction = await splDeposit(await chain({ config: protocolConfig(PAYER, false) }));
    expect(tagsOf(transaction)).toEqual(CREATE_THEN_DEPOSIT);
  });

  it("fails closed when the protocol config account is missing, before the blockhash", async () => {
    const client = await chain({});
    await expect(splDeposit(client)).rejects.toMatchObject({
      code: "WALLET_BUILD_DEPOSIT",
      causeCode: "WALLET_PROTOCOL_CONFIG_NOT_FOUND",
    });
    expect(client.getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("creates the interface with the Token-2022 program", async () => {
    const transaction = await splDeposit(await chain({ config: protocolConfig(OTHER, true) }), {
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    const [create] = instructionsOf(transaction);
    expect(create?.accounts?.some((a) => a.address === SPL_TOKEN_2022_PROGRAM_ID)).toBe(true);
  });

  it("places setupInstructions first, before the interface creation", async () => {
    const setup: Instruction = {
      programAddress: SHIELDED_POOL_PROGRAM_ID,
      accounts: [],
      data: Uint8Array.of(0xee),
    };
    const transaction = await splDeposit(await chain({ config: protocolConfig(OTHER, true) }), {
      setupInstructions: [setup],
    });
    expect(tagsOf(transaction)).toEqual([0xee, ...CREATE_THEN_DEPOSIT]);
  });

  it("refuses a setup instruction with a malformed address before any lookup", async () => {
    const client = await chain({ config: protocolConfig(OTHER, true) });
    // A structural object a caller built without the SDK, which the type cannot stop.
    const params = {
      ...splDepositParams(client),
      setupInstructions: [
        { programAddress: SHIELDED_POOL_PROGRAM_ID, accounts: [{ address: "nope", role: 0 }] },
      ],
    };
    await expect(Reflect.apply(buildDepositTransaction, undefined, [params])).rejects.toMatchObject(
      { code: "WALLET_BUILD_DEPOSIT", causeCode: "CLIENT_INVALID_BASE58" },
    );
    expect(client.getAccount).not.toHaveBeenCalled();
  });
});
