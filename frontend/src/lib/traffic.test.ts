import { expect, it, vi } from 'vitest';
import { TrafficStore } from './traffic.svelte';
import type { Flow } from './api';
import type { LiveState } from './live';

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

it('keeps SSE snapshot when initial HTTP read settles later and ignores updates after cleanup', async () => {
  let resolveFlows!: (response: Response) => void;
  const fetcher = vi.fn((url: string) => url === '/api/config'
    ? Promise.resolve(new Response('{"origin":null}'))
    : new Promise<Response>((resolve) => { resolveFlows = resolve; })) as unknown as typeof fetch;
  let update!: (flows: Flow[]) => void;
  let status!: (state: LiveState) => void;
  const stop = vi.fn();
  const store = new TrafficStore();
  const cleanup = store.start(fetcher, (onFlows, onStatus) => { update = onFlows; status = onStatus; return stop; });
  const event = { id: 1 } as Flow;
  update([event]);
  resolveFlows(new Response('[]'));
  await tick();
  expect(store.flows).toEqual([event]);
  expect(store.liveLoading).toBe(false);
  status('connected');
  expect(store.liveState).toBe('connected');
  cleanup();
  update([]);
  expect(store.flows).toEqual([event]);
  expect(stop).toHaveBeenCalledOnce();
});
