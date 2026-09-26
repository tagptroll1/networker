import { expect, it, vi } from 'vitest';
import { HistoryStore } from './history.svelte';

it('keeps newest history refresh even when previous request settles later', async () => {
  const pending: Array<(response: Response) => void> = [];
  const fetcher = vi.fn(() => new Promise<Response>((resolve) => pending.push(resolve))) as unknown as typeof fetch;
  const store = new HistoryStore();
  const first = store.load(fetcher);
  const second = store.load(fetcher);
  pending[1](new Response('[]'));
  await second;
  expect(store.entries).toEqual([]);
  expect(store.loading).toBe(false);
  pending[0](new Response('not json'));
  await first;
  expect(store.error).toBe('');
  store.dispose();
  await store.load(fetcher);
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('ignores pending response after view closes', async () => {
  let resolve!: (response: Response) => void;
  const fetcher = vi.fn(() => new Promise<Response>((done) => { resolve = done; })) as unknown as typeof fetch;
  const store = new HistoryStore();
  const pending = store.load(fetcher);
  store.dispose();
  resolve(new Response('not json'));
  await pending;
  expect(store.error).toBe('');
  expect(store.entries).toEqual([]);
});
