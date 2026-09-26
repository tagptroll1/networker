import { expect, it } from 'vitest';
import type { Flow } from './api';
import { destinationName, isInternal, visibleTraffic } from './visibility';

function flow(remote: string, domain?: string): Flow {
  return { remote, domain } as Flow;
}

it('hides loopback connections by default and restores them on toggle', () => {
  const flows = [flow('127.0.0.1:8765'), flow('127.12.2.3:443'), flow('[::1]:8765'), flow('[::ffff:127.0.0.1]:80'), flow('192.168.1.2:53')];
  expect(visibleTraffic(flows, false)).toEqual([flows[4]]);
  expect(visibleTraffic(flows, true)).toEqual(flows);
});

it('prefers observed domain and falls back to IP', () => {
  expect(destinationName(flow('203.0.113.42:443', 'example.com'))).toBe('example.com');
  expect(destinationName(flow('[2001:db8::1]:443'))).toBe('2001:db8::1');
});

it('classifies private, loopback and link-local addresses as internal', () => {
  const internal = ['10.1.2.3:22', '172.16.0.1:80', '172.31.255.1:80', '192.168.1.2:53', '127.0.0.1:8765', '169.254.1.1:80', '100.64.0.1:80', '[::1]:80', '[fd00::1]:443', '[fe80::1]:443', '[::ffff:192.168.1.2]:53'];
  const external = ['203.0.113.42:443', '172.32.0.1:80', '172.15.0.1:80', '8.8.8.8:53', '[2001:db8::1]:443', '[::ffff:8.8.8.8]:53'];
  for (const remote of internal) expect(isInternal(flow(remote)), remote).toBe(true);
  for (const remote of external) expect(isInternal(flow(remote)), remote).toBe(false);
});
