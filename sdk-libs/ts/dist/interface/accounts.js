import { decodeProtocolConfigAccount, decodeSplAssetCounterAccount, decodeSplAssetRegistryAccount, decodeZoneConfigAccount, } from "./codecs/index.js";
export function decodeProtocolConfig(data) {
    return decodeProtocolConfigAccount(data);
}
export function decodeSplAssetCounter(data) {
    return decodeSplAssetCounterAccount(data);
}
export function decodeSplAssetRegistry(data) {
    return decodeSplAssetRegistryAccount(data);
}
export function decodeZoneConfig(data) {
    return decodeZoneConfigAccount(data);
}
