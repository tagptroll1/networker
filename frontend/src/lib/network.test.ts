import { expect, it } from 'vitest';
import type { Flow } from './api';
import { networkGroups, shownOnMap } from './network';

function flow(id: number, source: 'host' | 'router', device?: Flow['device']): Flow {
  return {
    id, app: source === 'host' ? 'firefox' : '', started_at: '2026-09-26T12:00:00Z', last_seen: '2026-09-26T12:00:01Z',
    local: `${device?.ip ?? '127.0.0.1'}:1000`, remote: '203.0.113.1:443', direction: 'outbound', protocol: 'tcp',
    status: 'observed', sent_bytes: 1, received_bytes: 1, location: null, source, ...(device ? { device } : {})
  };
}

const flows = [
  flow(1, 'router', { ip: '192.168.20.20', name: 'Living-Room-TV', vlan: 20, interface: 'TV' }),
  flow(2, 'host', { ip: '192.168.10.20', name: 'desktop', vlan: 10, interface: 'Management' }),
  flow(3, 'router', { ip: '192.168.10.21', vlan: 10, interface: 'Management', label: 'Mac', vlan_name: 'Office' }),
  flow(4, 'router', { ip: '192.168.20.20', name: 'Living-Room-TV', vlan: 20, interface: 'TV' }),
  flow(5, 'host')
];

it('groups live clients by VLAN with this machine first', () => {
  const groups = networkGroups(flows);
  expect(groups.map((group) => [group.vlan, group.name, group.interface])).toEqual([[10, 'Office', 'Management'], [20, undefined, 'TV']]);
  expect(groups[0].clients.map((client) => [client.ip, client.name, client.host])).toEqual([['192.168.10.20', 'desktop', true], ['192.168.10.21', 'Mac', false]]);
  expect(groups[1].clients).toMatchObject([{ ip: '192.168.20.20', name: 'Living-Room-TV', lease: 'Living-Room-TV', flows: 2 }]);
});

it('keeps labelled but idle VLANs and addresses listed', () => {
  const groups = networkGroups(flows, { vlans: { '30': 'Guest' }, ips: { '10.0.0.5': 'NAS', '192.168.20.20': 'Living room TV' } });
  expect(groups.map((group) => group.vlan)).toEqual([10, 20, 30, 0]);
  expect(groups[1].clients[0]).toMatchObject({ name: 'Living room TV', lease: 'Living-Room-TV', label: 'Living room TV' });
  expect(groups[3].clients).toEqual([{ ip: '10.0.0.5', name: 'NAS', label: 'NAS', host: false, flows: 0 }]);
});

it('hides flows by VLAN or client, never flows without a device', () => {
  const hidden = { vlans: [20], clients: ['192.168.10.21'] };
  expect(flows.filter((item) => shownOnMap(item, hidden)).map((item) => item.id)).toEqual([2, 5]);
});
