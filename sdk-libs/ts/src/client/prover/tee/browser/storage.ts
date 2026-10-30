import { refused } from "../platform.js";

const STATES = "repositories";
const MARKERS = "initialized";

export function openPolicyDatabase(name: string, signal: AbortSignal): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const request = globalThis.indexedDB.open(name, 1);
    const fail = (): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", fail);
      reject(refused("policy_storage"));
    };
    signal.addEventListener("abort", fail, { once: true });
    request.onblocked = fail;
    request.onerror = fail;
    request.onupgradeneeded = () => {
      if (settled || signal.aborted) {
        request.transaction?.abort();
        return;
      }
      request.result.createObjectStore(STATES);
      request.result.createObjectStore(MARKERS);
    };
    request.onsuccess = () => {
      const db = request.result;
      if (settled || signal.aborted) {
        db.close();
        fail();
        return;
      }
      if (
        db.objectStoreNames.length !== 2 ||
        !db.objectStoreNames.contains(STATES) ||
        !db.objectStoreNames.contains(MARKERS)
      ) {
        db.close();
        fail();
        return;
      }
      settled = true;
      signal.removeEventListener("abort", fail);
      db.onversionchange = () => db.close();
      resolve(db);
    };
    if (signal.aborted) fail();
  });
}

/** The separate marker detects accidental deletion of just a repository row. */
export function readPolicyState(
  db: IDBDatabase,
  namespace: string,
): Promise<Readonly<{ marker: unknown; data: unknown }>> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STATES, MARKERS], "readonly");
    const data = transaction.objectStore(STATES).get(namespace);
    const marker = transaction.objectStore(MARKERS).get(namespace);
    transaction.oncomplete = () => {
      const storedData: unknown = data.result;
      const storedMarker: unknown = marker.result;
      resolve({ marker: storedMarker, data: storedData });
    };
    transaction.onabort = () => reject(refused("policy_storage"));
    transaction.onerror = () => reject(refused("policy_storage"));
  });
}

/** Finish a verified checkpoint before releasing the Web Lock, even on cancellation. */
export function writePolicyState(db: IDBDatabase, namespace: string, data: object): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STATES, MARKERS], "readwrite", { durability: "strict" });
    transaction.objectStore(STATES).put(data, namespace);
    transaction.objectStore(MARKERS).put(1, namespace);
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(refused("policy_storage"));
    transaction.onerror = () => reject(refused("policy_storage"));
  });
}
