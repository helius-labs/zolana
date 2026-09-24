import {
  decodeCacheAccount,
  decodeProtocolConfigAccount,
  decodeSplAssetCounterAccount,
  decodeSplAssetRegistryAccount,
  decodeRingConfigAccount,
} from "./codecs/index.js";
import type {
  CacheAccount,
  ProtocolConfigAccount,
  SplAssetCounterAccount,
  SplAssetRegistryAccount,
  RingConfigAccount,
} from "./types.js";

export function decodeProtocolConfig(data: Uint8Array): ProtocolConfigAccount {
  return decodeProtocolConfigAccount(data);
}

export function decodeSplAssetCounter(data: Uint8Array): SplAssetCounterAccount {
  return decodeSplAssetCounterAccount(data);
}

export function decodeSplAssetRegistry(data: Uint8Array): SplAssetRegistryAccount {
  return decodeSplAssetRegistryAccount(data);
}

export function decodeRingConfig(data: Uint8Array): RingConfigAccount {
  return decodeRingConfigAccount(data);
}

export function decodeCache(data: Uint8Array): CacheAccount {
  return decodeCacheAccount(data);
}
