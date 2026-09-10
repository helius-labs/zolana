/** Race work against cancellation even when an I/O implementation ignores signals. */
export function abortable<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return work;
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    const cleanup = () => signal.removeEventListener("abort", abort);
    // Always observe work, including when the signal was already aborted.
    work.then(
      (value) => {
        cleanup();
        if (signal.aborted) reject(signal.reason);
        else resolve(value);
      },
      (error: unknown) => {
        cleanup();
        reject(signal.aborted ? signal.reason : error);
      },
    );
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  });
}
