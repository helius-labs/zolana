import {
  decodeProtocolConfigAccount,
  decodeSplAssetCounterAccount,
  decodeSplAssetRegistryAccount,
  decodeZoneConfigAccount,
} from "./codecs/index.js";
import type {
  ProtocolConfigAccount,
  SplAssetCounterAccount,
  SplAssetRegistryAccount,
  ZoneConfigAccount,
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

export function decodeZoneConfig(data: Uint8Array): ZoneConfigAccount {
  return decodeZoneConfigAccount(data);
}
