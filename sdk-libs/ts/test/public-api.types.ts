import type { TransactionSigner as RootTransactionSigner } from "../src/index.js";
import type { SyncWalletConfig } from "../src/wallet/index.js";
// @ts-expect-error -- the wallet subpath must not re-export consumer-owned signer types.
import type { TransactionSigner as WalletTransactionSigner } from "../src/wallet/index.js";
// @ts-expect-error -- anonymous counter state is not part of wallet history.
import type { CounterpartyCounter } from "../src/transaction/index.js";
// @ts-expect-error -- bounded sync no longer reports generic scan rounds.
import type { SyncWalletReport } from "../src/wallet/index.js";

export type RootSignerExport = RootTransactionSigner;
export type WalletSignerExportMustStayAbsent = WalletTransactionSigner;
export type CounterpartyCounterMustStayAbsent = CounterpartyCounter;
export type SyncWalletReportMustStayAbsent = SyncWalletReport;

// @ts-expect-error -- stable discovery has no configurable counter window.
export const obsoleteSyncConfig: SyncWalletConfig = { tagWindow: 1n };

import type { ShieldedKeys } from "../src/transaction/index.js";
import type { WalletKeys } from "../src/client/index.js";
declare const keys: ShieldedKeys;
declare const walletKeys: WalletKeys;
// @ts-expect-error -- no long-lived secret leaves the keys.
export const leakedNullifierKey = keys.nullifierKey;
// @ts-expect-error -- no long-lived secret leaves the keys.
export const leakedViewingKey = keys.viewingKey;
// @ts-expect-error -- the shared point would make the keys a chosen-point ECDH oracle.
export const rawEcdh = keys.ecdh;
// @ts-expect-error -- the SDK signs with the caller's Solana signer, never through the keys.
export const signer = walletKeys.signTransaction;
// @ts-expect-error -- proving lives on the client-layer WalletKeys, not on ShieldedKeys.
export const proveOnShieldedKeys = keys.prove;
