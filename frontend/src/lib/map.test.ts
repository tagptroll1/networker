import { expect, it } from 'vitest';
import { destinations, labelLines, mapNodes, placeLabels, viewNodes, type Rect } from './map';
import type { Flow } from './api';

function flow(id: number, latitude: number, longitude: number, sent_bytes: number, received_bytes: number): Flow {
  return {
    id, app: 'Spotify', started_at: '2026-09-25T12:00:00Z', last_seen: '2026-09-25T12:00:01Z',
    local: '127.0.0.1:123', remote: `203.0.113.${id}:443`, direction: 'outbound', protocol: 'tcp',
    status: 'observed', sent_bytes, received_bytes, source: 'host',
    location: { latitude, longitude, accuracy_km: 50, country: 'US' }
  };
}

const overlaps = (a: Rect, b: Rect) => a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;

it('groups connections at same approximate destination and sums connection totals', () => {
  const groups = destinations([flow(1, 40, -73, 500, 800), flow(2, 40, -73, 200, 100), flow(3, 60, 5, 1, 0)], 2);
  expect(groups).toHaveLength(2);
  expect(groups[0].flows).toHaveLength(2);
  expect([groups[0].sent, groups[0].received, groups[0].primary.id]).toEqual([700, 900, 2]);
});

it('skips unlocated and incoming flows for map routes', () => {
  const unlocated = { ...flow(1, 40, -73, 1, 0), location: null };
  const incoming = { ...flow(2, 40, -73, 1, 0), direction: 'inbound' as const };
  expect(destinations([unlocated, incoming], null)).toEqual([]);
});

it('keeps nearby places as separate markers and only merges overlapping ones', () => {
  const groups = destinations([
    flow(1, 40, -73, 500, 100), flow(2, 40, -73, 200, 100),
    flow(3, 40.2, -72.9, 1, 0), flow(4, 40, -65, 1, 0), flow(5, 60, 5, 1, 0)
  ], null);
  const nodes = mapNodes(groups, 1000);
  expect(nodes.map((node) => node.flows.map((flow) => flow.id))).toEqual([[4], [1, 2, 3], [5]]);
  expect(nodes[1]).toMatchObject({ sent: 701, received: 200, primary: { id: 1 } });
  expect(mapNodes(groups.slice().reverse(), 1000)).toEqual(nodes);
  expect(mapNodes(groups, 40000)).toHaveLength(4);
});

it('merges overlapping markers across the map edge', () => {
  const groups = destinations([flow(1, 10, -179.9, 1, 0), flow(2, 10, 179.9, 1, 0)], null);
  expect(mapNodes(groups, 1000).map((node) => node.flows.map((flow) => flow.id))).toEqual([[1, 2]]);
});

it('prefers selected connection as marker primary', () => {
  const groups = destinations([flow(1, 40, -73, 500, 100), flow(2, 40.1, -73, 1, 0)], 2);
  expect(mapNodes(groups, 1000, 2)[0].primary.id).toBe(2);
});

it('shows full labels when isolated', () => {
  const nodes = mapNodes(destinations([flow(1, 40, -73, 2048, 100), flow(2, 50, 60, 1, 0)], null), 1000);
  const labels = placeLabels(nodes, 1000, []);
  expect(labels.map((label) => label.level)).toEqual(['full', 'full']);
  expect(labels[0].lines).toEqual(labelLines(nodes[0], 'full'));
  expect(labels[0].lines[2]).toContain('2 KiB');
});

it('compacts crowded labels and never overlaps labels, markers or obstacles', () => {
  const flows = Array.from({ length: 40 }, (_, i) => flow(i + 1, 20 + (i % 8) * 6, -20 + Math.floor(i / 8) * 6, 1000 * (i + 1), 0));
  const nodes = mapNodes(destinations(flows, null), 1000);
  const obstacle = { x: 0, y: 0, width: 220, height: 40 };
  const labels = placeLabels(nodes, 1000, [obstacle]);
  expect(nodes).toHaveLength(40);
  expect(labels.some((label) => label.level === 'compact')).toBe(true);
  expect(labels.length).toBeGreaterThan(5);
  const markers = nodes.map((node) => ({ key: node.key, x: node.x - 7, y: node.y - 7, width: 14, height: 14 }));
  for (const label of labels) {
    expect(overlaps(label, obstacle)).toBe(false);
    for (const other of labels) if (other !== label) expect(overlaps(label, other)).toBe(false);
    for (const marker of markers) if (marker.key !== label.key) expect(overlaps(label, marker)).toBe(false);
  }
});

it('labels selected marker first', () => {
  const nodes = mapNodes(destinations([flow(1, 40, -73, 9000, 0), flow(2, 40, -62, 1, 0)], 2), 1000, 2);
  const labels = placeLabels(nodes, 1000, [], 2);
  expect(labels.find((label) => label.key === nodes[1].key)?.level).toBe('full');
});

it('zooming separates merged markers and view drops markers outside the map', () => {
  const groups = destinations([flow(1, 50, 8, 1, 0), flow(2, 50.5, 9, 1, 0), flow(3, -33, 151, 1, 0)], null);
  expect(mapNodes(groups, 1000)).toHaveLength(2);
  const zoomed = mapNodes(groups, 8000);
  expect(zoomed).toHaveLength(3);
  // Pan so Europe fills the view; Sydney falls outside.
  const visible = viewNodes(zoomed, -4000, -800, 1000);
  expect(visible.map((node) => node.flows[0].id).sort()).toEqual([1, 2]);
  expect(visible.every((node) => node.x >= 0 && node.x <= 1000 && node.y >= 0 && node.y <= 500)).toBe(true);
});

it('names other devices with their VLAN in full labels', () => {
  const tv = { ...flow(1, 40, -73, 10, 20), app: '', source: 'router' as const, device: { ip: '192.168.20.20', name: 'Living-Room-TV', vlan: 20 } };
  const [node] = mapNodes(destinations([tv], null), 1000);
  expect(labelLines(node, 'full')[0]).toBe('Living-Room-TV · VLAN 20');
  expect(labelLines(node, 'compact')[0]).toMatch(/^Living-Room-TV/);
  const [own] = mapNodes(destinations([{ ...flow(2, 40, -73, 10, 20), device: { ip: '192.168.10.20', vlan: 10 } }], null), 1000);
  expect(labelLines(own, 'full')[0]).toBe('Spotify');
});
