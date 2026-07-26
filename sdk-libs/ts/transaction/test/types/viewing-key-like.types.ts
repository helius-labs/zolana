import type { Bytes16 } from "@zolana/interface";
import type { P256PublicKey, ViewingKey, ViewingKeyLike } from "@zolana/keypair";

import type {
  ConfidentialOutputPlaintext,
  DecodeContext,
  MergePlaintext,
} from "../../src/serialization/index.js";
import {
  decodeContextForSlot,
  decryptAnonymous,
  decryptConfidential,
  decryptConfidentialAsSender,
  decryptMerge,
  encryptAnonymous,
  encryptConfidential,
  encryptMerge,
} from "../../src/serialization/index.js";
import type { WalletSyncMaterial } from "../../src/wallet/index.js";

/**
 * K11: the codec call sites bind the viewing-key capability interface, so a
 * backend that holds its own key material can encrypt and decrypt without
 * being the concrete in-memory class. Nothing here runs; `npm run typecheck`
 * compiles this project, which is what makes the assertions a gate rather than
 * a comment. Widening any parameter below back to `ViewingKey` fails it.
 */
declare const backend: ViewingKeyLike;
declare const recipient: P256PublicKey;
declare const confidential: ConfidentialOutputPlaintext;
declare const merge: MergePlaintext;
declare const salt: Bytes16;
declare const body: Uint8Array;

encryptConfidential(backend, recipient, confidential, salt, 0);
encryptAnonymous(backend, recipient, body, salt, 0);
decryptAnonymous(backend, recipient, body, salt, 0);
decryptConfidential(backend, recipient, body, salt, 0);
decryptConfidentialAsSender(backend, body, salt, 0);
encryptMerge(backend, recipient, merge);
decryptMerge(backend, body);

/**
 * The control. `ViewingKey` keeps private fields, so it accepts no structural
 * stand-in; an unused `@ts-expect-error` is itself a compile error, so this
 * fails the moment the assertions above stop meaning anything.
 */
declare function widened(key: ViewingKey): void;
// @ts-expect-error a capability backend is not the concrete key
widened(backend);

/**
 * Rust's `DecodeCx` binds `&'a ViewingKey` and `WalletSyncMaterial` holds
 * `Vec<ViewingKey>`, so these three stay concrete. Widening them would make
 * TypeScript the more permissive of the two rather than the narrower.
 */
declare const material: WalletSyncMaterial;
declare const context: DecodeContext;
const contextKey: ViewingKey = context.viewingKey;
const materialKeys: readonly ViewingKey[] = material.viewingKeys;
void contextKey;
void materialKeys;
// @ts-expect-error DecodeCx binds the concrete viewing key in Rust
decodeContextForSlot(backend, { nullifiers: [] }, 0);
