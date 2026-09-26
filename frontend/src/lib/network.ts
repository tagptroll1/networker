import type { Flow, Labels } from './api';

export type Client = { ip: string; name: string; lease?: string; label?: string; host: boolean; flows: number };
export type VlanGroup = { vlan: number; name?: string; interface?: string; clients: Client[] };

const ipOrder = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });

// Groups the LAN clients seen in live traffic by VLAN. VLANs and addresses
// that only have a label are included, so named ones stay listed while idle.
// VLAN 0 holds clients whose VLAN is unknown, including idle labelled ones.
export function networkGroups(flows: Flow[], labels: Labels = { vlans: {}, ips: {} }): VlanGroup[] {
  const groups = new Map<number, VlanGroup>();
  const group = (vlan: number) => {
    let item = groups.get(vlan);
    if (!item) {
      item = { vlan, clients: [], ...(labels.vlans[vlan] ? { name: labels.vlans[vlan] } : {}) };
      groups.set(vlan, item);
    }
    return item;
  };
  const clients = new Map<string, Client>();
  for (const flow of flows) {
    const device = flow.device;
    if (!device) continue;
    const item = group(device.vlan ?? 0);
    if (device.interface) item.interface = device.interface;
    if (device.vlan_name) item.name = device.vlan_name;
    let client = clients.get(device.ip);
    if (!client) {
      client = { ip: device.ip, name: '', host: flow.source === 'host', flows: 0 };
      clients.set(device.ip, client);
      item.clients.push(client);
    }
    client.flows++;
    if (device.name) client.lease = device.name;
    const label = labels.ips[device.ip] || device.label;
    if (label) client.label = label;
    client.name = client.label || client.lease || (client.host ? 'This machine' : client.ip);
  }
  for (const vlan of Object.keys(labels.vlans)) group(Number(vlan));
  for (const [ip, label] of Object.entries(labels.ips)) {
    if (!clients.has(ip)) group(0).clients.push({ ip, name: label, label, host: false, flows: 0 });
  }
  for (const item of groups.values()) item.clients.sort((a, b) => Number(b.host) - Number(a.host) || ipOrder(a.ip, b.ip));
  return [...groups.values()].sort((a, b) => (a.vlan || 5000) - (b.vlan || 5000));
}

export type Hidden = { vlans: number[]; clients: string[] };

// A flow shows on the map unless its VLAN or its client is switched off.
export function shownOnMap(flow: Flow, hidden: Hidden): boolean {
  if (!flow.device) return true;
  return !hidden.vlans.includes(flow.device.vlan ?? 0) && !hidden.clients.includes(flow.device.ip);
}
