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
