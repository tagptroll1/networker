import { describe, expect, it, vi } from 'vitest';
import { ApiError, getConfig, getConnections, getDNS, getFlows, parseConfig, parseConnections, parseDNS, parseFlows, parseLabels, setLabel } from './api';
import { appName, formatLocation, formatTime, network, remoteIP, status, who } from './format';

const sample = {
  id: 7, started_at: '2026-09-25T12:00:00Z', app: 'unknown', protocol: 'tcp', direction: 'outbound',
  status: 'observed', sent_bytes: 42, received_bytes: 300, location: null, source: 'host'
};

describe('API', () => {
  it('parses unset and configured origin', () => {
    expect(parseConfig({ origin: null, router: false })).toEqual({ origin: null, router: false });
    expect(parseConfig({ origin: { latitude: 59.91, longitude: 10.75 }, router: true })).toEqual({ origin: { latitude: 59.91, longitude: 10.75 }, router: true });
    expect(() => parseConfig({ origin: {} })).toThrow('Invalid API response');
    expect(() => parseConfig({ origin: null })).toThrow('Invalid API response');
  });

  it('parses full snapshots including IPv6, absent PID and null location', () => {
    expect(parseFlows([])).toEqual([]);
    const [flow] = parseFlows([{ ...sample, last_seen: sample.started_at, local: '[::1]:31234', remote: '[2001:db8::1]:443' }]);
    expect(flow.pid).toBeUndefined();
    expect(flow.location).toBeNull();
    expect(remoteIP(flow.remote)).toBe('2001:db8::1');
    expect(remoteIP('203.0.113.4:443')).toBe('203.0.113.4');
    expect(parseFlows([{ ...sample, last_seen: sample.started_at, local: '192.0.2.1:123', remote: '203.0.113.42:443', domain: 'example.com' }])[0].domain).toBe('example.com');
    expect(() => parseFlows([{ ...flow, domain: 42 }])).toThrow('Invalid API response');
    expect(() => parseFlows([{ ...flow, location: undefined }])).toThrow('Invalid API response');
  });

  it('parses stored summaries with optional geolocation fields', () => {
    expect(parseConnections([])).toEqual([]);
    const [entry] = parseConnections([{ ...sample, remote_ip: '2001:db8::1', remote_port: 443,
      location: { latitude: 40, longitude: -73, accuracy_km: 50, country: 'US', asn: 42 } }]);
    expect(entry.remote_ip).toBe('2001:db8::1');
    expect(entry.location?.city).toBeUndefined();
    expect(formatLocation(entry.location)).toBe('US');
    expect(formatLocation(null)).toBe('Unknown location');
    expect(appName(entry.app)).toBe('Unknown app');
    expect(status(entry.status)).toBe('Observed');
    expect(formatTime(entry.started_at)).toBe(new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(entry.started_at)));
  });

  it('parses attribution in live and stored connections', () => {
    const details = { pid: 123, local: '127.0.0.1:13420', executable: '/usr/bin/http-client', unit: 'browser.scope' };
    expect(parseFlows([{ ...sample, ...details, last_seen: sample.started_at, remote: '127.0.0.1:49153' }])[0]).toMatchObject(details);
    expect(parseConnections([{ ...sample, ...details, remote_ip: '127.0.0.1', remote_port: 49153 }])[0]).toMatchObject(details);
    expect(() => parseConnections([{ ...sample, ...details, pid: '123', remote_ip: '127.0.0.1', remote_port: 49153 }])).toThrow('Invalid API response');
  });

  it('parses router devices and names them by lease or IP', () => {
    const base = { ...sample, last_seen: sample.started_at, local: '192.168.20.20:40000', remote: '203.0.113.1:443', app: '', source: 'router' };
    const [tv] = parseFlows([{ ...base, device: { ip: '192.168.20.20', mac: 'AA:BB:CC:00:00:20', name: 'Living-Room-TV', vlan: 20, interface: 'TV' } }]);
    expect([tv.source, who(tv), network(tv.device)]).toEqual(['router', 'Living-Room-TV', 'VLAN 20 · TV']);
    const [unnamed] = parseFlows([{ ...base, device: { ip: '192.168.20.21' } }]);
    expect([who(unnamed), network(unnamed.device)]).toEqual(['192.168.20.21', '']);
    expect(who({ source: 'host', app: 'unknown' })).toBe('Unknown app');
    expect(() => parseFlows([{ ...base, source: 'switch' }])).toThrow('Invalid API response');
    expect(() => parseFlows([{ ...base, device: { ip: '192.168.20.20', vlan: '20' } }])).toThrow('Invalid API response');
  });

  it('parses labels and writes them as JSON', async () => {
    expect(parseLabels({ vlans: { '10': 'Office' }, ips: {} })).toEqual({ vlans: { '10': 'Office' }, ips: {} });
    expect(() => parseLabels({ vlans: { '10': 1 }, ips: {} })).toThrow('Invalid API response');
    const fetcher = vi.fn(async () => new Response(null, { status: 204 })) as unknown as typeof fetch;
    await setLabel('ip', '192.168.10.21', 'Mac', fetcher);
    expect(vi.mocked(fetcher).mock.calls[0]).toEqual(['/api/labels/ip/192.168.10.21', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{"name":"Mac"}' }]);
    const bad = vi.fn(async () => new Response('forbidden', { status: 403 })) as unknown as typeof fetch;
    await expect(setLabel('vlan', '10', 'x', bad)).rejects.toEqual(new ApiError(403, 'API error (403): forbidden'));
  });

  it('parses DNS questions', async () => {
    const entry = { id: 1, queried_at: '2026-09-25T12:00:00Z', name: 'example.com', type: 'AAAA', server_ip: '127.0.0.53' };
    expect(parseDNS([entry])).toEqual([entry]);
    expect(() => parseDNS([{ ...entry, name: null }])).toThrow('Invalid API response');
    const fetcher = vi.fn(async () => new Response(JSON.stringify([entry]))) as unknown as typeof fetch;
    expect(await getDNS(100, fetcher)).toEqual([entry]);
    expect(vi.mocked(fetcher).mock.calls[0][0]).toBe('/api/dns?limit=100');
  });

  it('uses same-origin endpoints, includes history limit, and reports HTTP failures', async () => {
    const fetcher = vi.fn(async (url: string) => new Response(url.startsWith('/api/flows') ? '[]' : url.startsWith('/api/connections') ? '[]' : '{"origin":null,"router":false}')) as unknown as typeof fetch;
    expect(await getConfig(fetcher)).toEqual({ origin: null, router: false });
    expect(await getFlows(fetcher)).toEqual([]);
    expect(await getConnections(100, '2026-09-25T12:00:00Z', fetcher)).toEqual([]);
    expect(vi.mocked(fetcher).mock.calls[2][0]).toBe('/api/connections?limit=100&since=2026-09-25T12%3A00%3A00Z');
    expect(() => getConnections(501)).toThrow(RangeError);
    const bad = vi.fn(async () => new Response('limit must be 1..500', { status: 400 })) as unknown as typeof fetch;
    await expect(getConnections(100, undefined, bad)).rejects.toEqual(new ApiError(400, 'API error (400): limit must be 1..500'));
    const disconnected = vi.fn(async () => { throw new Error('network'); }) as unknown as typeof fetch;
    await expect(getConfig(disconnected)).rejects.toThrow('Cannot reach');
  });
});
