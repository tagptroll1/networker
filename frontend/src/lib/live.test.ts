import { expect, it, vi } from 'vitest';
import { subscribeFlows, type LiveState } from './live';
import type { Flow } from './api';

it('replaces snapshots, handles reconnect and releases EventSource', () => {
  const listeners = new Map<string, (event: MessageEvent) => void>();
  const source = {
    addEventListener: vi.fn((type: string, listener: (event: MessageEvent) => void) => { listeners.set(type, listener); }),
    removeEventListener: vi.fn((type: string) => { listeners.delete(type); }),
    close: vi.fn()
  } as unknown as EventSource;
  const update = vi.fn<(flows: Flow[]) => void>();
  const status = vi.fn<(state: LiveState, error?: string) => void>();
  const create = vi.fn(() => source);
  const stop = subscribeFlows(update, status, create);
  expect(create).toHaveBeenCalledWith('/api/events');
  const flow = {
    id: 1, started_at: '2026-09-25T12:00:00Z', last_seen: '2026-09-25T12:00:01Z',
    app: 'Spotify', local: '[::1]:123', remote: '[2001:db8::1]:443', protocol: 'tcp',
    direction: 'outbound', status: 'established', sent_bytes: 5, received_bytes: 6, location: null, source: 'host'
  };
  listeners.get('flows')!(new MessageEvent('flows', { data: JSON.stringify([flow]) }));
  listeners.get('flows')!(new MessageEvent('flows', { data: '[]' }));
  expect(update.mock.calls.map(([items]) => items.length)).toEqual([1, 0]);
  listeners.get('error')!(new MessageEvent('error'));
  expect(status).toHaveBeenLastCalledWith('reconnecting', expect.any(String));
  listeners.get('open')!(new MessageEvent('open'));
  expect(status).toHaveBeenLastCalledWith('connected');
  stop();
  expect(source.close).toHaveBeenCalledOnce();
  expect(listeners.size).toBe(0);
});
