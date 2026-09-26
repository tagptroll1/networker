import { getConnections, type Connection } from './api';

export class HistoryStore {
  entries = $state<Connection[]>([]);
  error = $state('');
  loading = $state(true);
  #request: AbortController | null = null;
  #sequence = 0;
  #disposed = false;

  async load(fetcher: typeof fetch = fetch): Promise<void> {
    if (this.#disposed) return;
    this.#request?.abort();
    const request = new AbortController();
    this.#request = request;
    const sequence = ++this.#sequence;
    this.loading = true;
    this.error = '';
    try {
      const entries = await getConnections(100, undefined, (url, init) => fetcher(url, { ...init, signal: request.signal }));
      if (!this.#disposed && sequence === this.#sequence) this.entries = entries;
    } catch (error) {
      if (!this.#disposed && sequence === this.#sequence) this.error = String(error instanceof Error ? error.message : error);
    } finally {
      if (!this.#disposed && sequence === this.#sequence) { this.loading = false; this.#request = null; }
    }
  }

  dispose(): void {
    this.#disposed = true;
    this.#sequence++;
    this.#request?.abort();
    this.#request = null;
  }
}
