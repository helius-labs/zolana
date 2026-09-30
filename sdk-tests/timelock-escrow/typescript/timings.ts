export class Timings {
  readonly #entries: { readonly label: string; readonly ms: number }[] = [];

  record(label: string, ms: number): void {
    this.#entries.push({ label, ms });
  }

  measure<T>(label: string, run: () => T): T {
    const started = performance.now();
    try {
      return run();
    } finally {
      this.record(label, performance.now() - started);
    }
  }

  async measureAsync<T>(label: string, run: () => Promise<T>): Promise<T> {
    const started = performance.now();
    try {
      return await run();
    } finally {
      this.record(label, performance.now() - started);
    }
  }

  report(): string {
    const width = Math.max(...this.#entries.map((entry) => entry.label.length));
    return this.#entries
      .map((entry) => `timing ${entry.label.padEnd(width)} ${entry.ms.toFixed(1).padStart(9)} ms`)
      .join("\n");
  }
}
