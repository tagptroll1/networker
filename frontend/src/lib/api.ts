export type Location = {
  latitude: number;
  longitude: number;
  accuracy_km: number;
  city?: string;
  country?: string;
  asn?: number;
  organization?: string;
};

export type Origin = { latitude: number; longitude: number };
export type Config = { origin: Origin | null; router: boolean };

// LAN client as known by the router: DHCP lease name and the VLAN of its subnet.
export type Device = { ip: string; mac?: string; name?: string; vlan?: number; interface?: string; label?: string; vlan_name?: string };

// The user's own names, keyed by VLAN id and IP address.
export type Labels = { vlans: Record<string, string>; ips: Record<string, string> };

type Traffic = {
  id: number;
  started_at: string;
  app: string;
  pid?: number;
  executable?: string;
  unit?: string;
  local?: string;
  protocol: 'tcp' | 'udp';
  direction: 'outbound' | 'inbound';
  status: 'established' | 'observed';
  sent_bytes: number;
  received_bytes: number;
  location: Location | null;
  // host: this machine, seen by eBPF. router: another LAN device, seen by the router.
  source: 'host' | 'router';
  device?: Device;
};

export type Flow = Traffic & {
  last_seen: string;
  local: string;
  remote: string;
  domain?: string;
};

export type Connection = Traffic & {
  remote_ip: string;
  remote_port: number;
  remote_name?: string;
};

export type DNSQuery = { id: number; queried_at: string; name: string; type: string; server_ip: string };

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid API response');
  return value as Record<string, unknown>;
}

function text(value: unknown): string {
  if (typeof value !== 'string') throw new Error('Invalid API response');
  return value;
}

function number(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('Invalid API response');
  return value;
}

function bool(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new Error('Invalid API response');
  return value;
}

function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (!choices.includes(value as T)) throw new Error('Invalid API response');
  return value as T;
}

function location(value: unknown): Location | null {
  if (value === null) return null;
  const v = object(value);
  return {
    latitude: number(v.latitude), longitude: number(v.longitude), accuracy_km: number(v.accuracy_km),
    ...(v.city === undefined ? {} : { city: text(v.city) }),
    ...(v.country === undefined ? {} : { country: text(v.country) }),
    ...(v.asn === undefined ? {} : { asn: number(v.asn) }),
    ...(v.organization === undefined ? {} : { organization: text(v.organization) })
  };
}

function device(value: unknown): Device {
  const v = object(value);
  return {
    ip: text(v.ip),
    ...(v.mac === undefined ? {} : { mac: text(v.mac) }),
    ...(v.name === undefined ? {} : { name: text(v.name) }),
    ...(v.vlan === undefined ? {} : { vlan: number(v.vlan) }),
    ...(v.interface === undefined ? {} : { interface: text(v.interface) }),
    ...(v.label === undefined ? {} : { label: text(v.label) }),
    ...(v.vlan_name === undefined ? {} : { vlan_name: text(v.vlan_name) })
  };
}

function traffic(value: unknown): Traffic {
  const v = object(value);
  return {
    id: number(v.id), started_at: text(v.started_at), app: text(v.app),
    ...(v.pid === undefined ? {} : { pid: number(v.pid) }),
    ...(v.executable === undefined ? {} : { executable: text(v.executable) }),
    ...(v.unit === undefined ? {} : { unit: text(v.unit) }),
    ...(v.local === undefined ? {} : { local: text(v.local) }),
    protocol: choice(v.protocol, ['tcp', 'udp']),
    direction: choice(v.direction, ['outbound', 'inbound']),
    status: choice(v.status, ['established', 'observed']),
    sent_bytes: number(v.sent_bytes), received_bytes: number(v.received_bytes),
    location: location(v.location),
    source: choice(v.source, ['host', 'router']),
    ...(v.device === undefined ? {} : { device: device(v.device) })
  };
}

export function parseConfig(value: unknown): Config {
  const v = object(value);
  if (v.origin === null) return { origin: null, router: bool(v.router) };
  const o = object(v.origin);
  return { origin: { latitude: number(o.latitude), longitude: number(o.longitude) }, router: bool(v.router) };
}

export function parseFlows(value: unknown): Flow[] {
  if (!Array.isArray(value)) throw new Error('Invalid API response');
  return value.map((item) => {
    const v = object(item);
    return {
      ...traffic(v), last_seen: text(v.last_seen), local: text(v.local), remote: text(v.remote),
      ...(v.domain === undefined ? {} : { domain: text(v.domain) })
    };
  });
}

export function parseConnections(value: unknown): Connection[] {
  if (!Array.isArray(value)) throw new Error('Invalid API response');
  return value.map((item) => {
    const v = object(item);
    return {
      ...traffic(v), remote_ip: text(v.remote_ip), remote_port: number(v.remote_port),
      ...(v.remote_name === undefined ? {} : { remote_name: text(v.remote_name) })
    };
  });
}

export function parseDNS(value: unknown): DNSQuery[] {
  if (!Array.isArray(value)) throw new Error('Invalid API response');
  return value.map((item) => {
    const v = object(item);
    return { id: number(v.id), queried_at: text(v.queried_at), name: text(v.name), type: text(v.type), server_ip: text(v.server_ip) };
  });
}

async function get<T>(path: string, parse: (value: unknown) => T, fetcher: typeof fetch): Promise<T> {
  let response: Response;
  try {
    response = await fetcher(path);
  } catch {
    throw new Error('Cannot reach the API');
  }
  if (!response.ok) throw new ApiError(response.status, `API error (${response.status}): ${(await response.text()).trim()}`);
  return parse(await response.json());
}

export const getConfig = (fetcher: typeof fetch = fetch) => get('/api/config', parseConfig, fetcher);
export const getFlows = (fetcher: typeof fetch = fetch) => get('/api/flows', parseFlows, fetcher);
export function getConnections(limit = 100, since?: string, fetcher: typeof fetch = fetch): Promise<Connection[]> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new RangeError('limit must be 1..500');
  const params = new URLSearchParams({ limit: String(limit) });
  if (since) params.set('since', since);
  return get(`/api/connections?${params}`, parseConnections, fetcher);
}

export function getDNS(limit = 100, fetcher: typeof fetch = fetch): Promise<DNSQuery[]> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new RangeError('limit must be 1..500');
  return get(`/api/dns?limit=${limit}`, parseDNS, fetcher);
}

function names(value: unknown): Record<string, string> {
  return Object.fromEntries(Object.entries(object(value)).map(([key, name]) => [key, text(name)]));
}

export function parseLabels(value: unknown): Labels {
  const v = object(value);
  return { vlans: names(v.vlans), ips: names(v.ips) };
}

export const getLabels = (fetcher: typeof fetch = fetch) => get('/api/labels', parseLabels, fetcher);

// Names a VLAN or IP address; an empty name removes the label.
export async function setLabel(kind: 'vlan' | 'ip', key: string, name: string, fetcher: typeof fetch = fetch): Promise<void> {
  let response: Response;
  try {
    response = await fetcher(`/api/labels/${kind}/${encodeURIComponent(key)}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name })
    });
  } catch {
    throw new Error('Cannot reach the API');
  }
  if (!response.ok) throw new ApiError(response.status, `API error (${response.status}): ${(await response.text()).trim()}`);
}
