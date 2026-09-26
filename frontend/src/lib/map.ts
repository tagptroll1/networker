import type { Flow, Location } from './api';
import { formatBytes, formatLocation, vlan, who } from './format';
import { destinationName } from './visibility';

export type Destination = {
  key: string;
  location: Location;
  flows: Flow[];
  primary: Flow;
  sent: number;
  received: number;
};

export type MapNode = {
  key: string;
  x: number;
  y: number;
  location: Location;
  flows: Flow[];
  primary: Flow;
  sent: number;
  received: number;
};

export type Rect = { x: number; y: number; width: number; height: number };
export type LabelLevel = 'full' | 'compact';
export type MapLabel = Rect & { key: string; level: LabelLevel; lines: string[] };

// Label text is monospace, so width follows from character count.
export const LABEL_CHAR = 6.2;
export const LABEL_LINE = 13;
export const LABEL_PAD_X = 6;
export const LABEL_PAD_Y = 3;
const LABEL_BORDER = 1;
// Markers closer than this would overlap, so they share one marker.
export const NODE_SPACING = 14;
const LABEL_GAP = 9;
const EDGE = 4;
const FULL_CHARS = 26;
const COMPACT_CHARS = 20;

const traffic = (flow: Flow) => flow.sent_bytes + flow.received_bytes;

function pickPrimary(current: Flow, flow: Flow, selected: number | null): Flow {
  if (flow.id === selected) return flow;
  if (current.id === selected) return current;
  return traffic(flow) > traffic(current) ? flow : current;
}

export function destinations(flows: Flow[], selected: number | null): Destination[] {
  const grouped = new Map<string, Destination>();
  for (const flow of flows) {
    if (!flow.location || flow.direction !== 'outbound') continue;
    const { latitude, longitude } = flow.location;
    const key = `${latitude.toFixed(3)}:${longitude.toFixed(3)}`;
    let group = grouped.get(key);
    if (!group) {
      group = { key, location: flow.location, flows: [], primary: flow, sent: 0, received: 0 };
      grouped.set(key, group);
    }
    group.flows.push(flow);
    group.sent += flow.sent_bytes;
    group.received += flow.received_bytes;
    group.primary = pickPrimary(group.primary, flow, selected);
  }
  return [...grouped.values()].sort((a, b) => b.sent + b.received - a.sent - a.received || a.key.localeCompare(b.key));
}

// Places each destination at its exact projected position. Only destinations
// whose markers would physically overlap share a marker.
export function mapNodes(groups: Destination[], width: number, selected: number | null = null): MapNode[] {
  const nodes: MapNode[] = [];
  const height = width / 2;
  for (const group of [...groups].sort((a, b) => a.key.localeCompare(b.key))) {
    const x = (group.location.longitude + 180) * width / 360;
    const y = (90 - group.location.latitude) * height / 180;
    let node = nodes.find((item) => Math.hypot(Math.min(Math.abs(item.x - x), width - Math.abs(item.x - x)), item.y - y) < NODE_SPACING);
    if (!node) {
      node = { key: group.key, x, y, location: group.location, flows: [], primary: group.primary, sent: 0, received: 0 };
      nodes.push(node);
    }
    node.flows.push(...group.flows);
    node.sent += group.sent;
    node.received += group.received;
    node.primary = pickPrimary(node.primary, group.primary, selected);
  }
  for (const node of nodes) node.flows.sort((a, b) => a.id - b.id);
  return nodes;
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function labelLines(node: MapNode, level: LabelLevel): string[] {
  const extra = node.flows.length > 1 ? ` +${node.flows.length - 1}` : '';
  if (level === 'compact') {
    const total = formatBytes(node.sent + node.received);
    return [`${clip(who(node.primary), COMPACT_CHARS - extra.length - total.length - 1)}${extra} ${total}`];
  }
  // Other LAN devices show their VLAN beside the device name.
  const tag = node.primary.source === 'router' && vlan(node.primary.device) ? ` · ${vlan(node.primary.device)}` : '';
  return [
    `${clip(who(node.primary), FULL_CHARS - extra.length - tag.length)}${extra}${tag}`,
    clip(`${destinationName(node.primary)} · ${formatLocation(node.location)}`, FULL_CHARS),
    `↑ ${formatBytes(node.sent)} ↓ ${formatBytes(node.received)}`
  ];
}

function labelSize(lines: string[]) {
  return {
    width: Math.ceil(Math.max(...lines.map((line) => line.length)) * LABEL_CHAR + (LABEL_PAD_X + LABEL_BORDER) * 2),
    height: lines.length * LABEL_LINE + (LABEL_PAD_Y + LABEL_BORDER) * 2
  };
}

// Candidate spots around a marker, most readable first.
function candidates(x: number, y: number, width: number, height: number): Rect[] {
  const d = LABEL_GAP * 0.7;
  return [
    { x: x + LABEL_GAP, y: y - height / 2 },
    { x: x - LABEL_GAP - width, y: y - height / 2 },
    { x: x + d, y: y - d - height },
    { x: x + d, y: y + d },
    { x: x - d - width, y: y - d - height },
    { x: x - d - width, y: y + d },
    { x: x - width / 2, y: y - LABEL_GAP - height },
    { x: x - width / 2, y: y + LABEL_GAP }
  ].map((spot) => ({ ...spot, width, height }));
}

const overlaps = (a: Rect, b: Rect) => a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;

// Gives every marker the most informative label that fits without covering
// other labels, markers or map controls. First pass gives as many markers as
// possible a compact label; second pass expands those with room to spare.
export function placeLabels(nodes: MapNode[], width: number, obstacles: Rect[], selected: number | null = null): MapLabel[] {
  const height = width / 2;
  const markers = nodes.map((node) => ({ x: node.x - NODE_SPACING / 2, y: node.y - NODE_SPACING / 2, width: NODE_SPACING, height: NODE_SPACING }));
  const order = nodes
    .map((node, index) => ({ node, index }))
    .sort((a, b) =>
      Number(b.node.flows.some((flow) => flow.id === selected)) - Number(a.node.flows.some((flow) => flow.id === selected)) ||
      b.node.sent + b.node.received - a.node.sent - a.node.received ||
      a.node.key.localeCompare(b.node.key));
  const placed = new Map<number, MapLabel>();

  const fit = (index: number, level: LabelLevel): MapLabel | null => {
    const node = nodes[index];
    const lines = labelLines(node, level);
    const size = labelSize(lines);
    for (const spot of candidates(node.x, node.y, size.width, size.height)) {
      if (spot.x < EDGE || spot.y < EDGE || spot.x + spot.width > width - EDGE || spot.y + spot.height > height - EDGE) continue;
      if (obstacles.some((rect) => overlaps(spot, rect))) continue;
      if (markers.some((rect, other) => other !== index && overlaps(spot, rect))) continue;
      if ([...placed].some(([other, rect]) => other !== index && overlaps(spot, rect))) continue;
      return { ...spot, key: node.key, level, lines };
    }
    return null;
  };

  for (const { index } of order) {
    const label = fit(index, 'compact');
    if (label) placed.set(index, label);
  }
  for (const { index } of order) {
    if (!placed.has(index)) continue;
    const label = fit(index, 'full');
    if (label) placed.set(index, label);
  }
  return [...placed.values()];
}

// Shifts nodes from zoomed world space into the visible map and drops the rest.
export function viewNodes(nodes: MapNode[], dx: number, dy: number, width: number): MapNode[] {
  const height = width / 2;
  return nodes
    .map((node) => ({ ...node, x: node.x + dx, y: node.y + dy }))
    .filter((node) => node.x >= 0 && node.x <= width && node.y >= 0 && node.y <= height);
}
