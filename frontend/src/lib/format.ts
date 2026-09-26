import type { Device, Location } from './api';

const dateTime = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'medium' });

export function formatTime(stamp: string): string {
  const date = new Date(stamp);
  return Number.isNaN(date.getTime()) ? 'Unknown time' : dateTime.format(date);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), 4);
  return `${new Intl.NumberFormat('en-GB', { maximumFractionDigits: 1 }).format(bytes / 1024 ** unit)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`;
}

export function formatLocation(value: Location | null): string {
  if (!value) return 'Unknown location';
  return [value.city, value.country].filter(Boolean).join(', ') || 'Approximate location';
}

export function remoteIP(socket: string): string {
  if (socket.startsWith('[')) return socket.slice(1, socket.lastIndexOf(']'));
  return socket.slice(0, socket.lastIndexOf(':'));
}

export function direction(value: 'outbound' | 'inbound'): string {
  return value === 'outbound' ? 'Outbound' : 'Inbound';
}

export function status(value: 'established' | 'observed'): string {
  return value === 'established' ? 'Established' : 'Observed';
}

export function appName(name: string): string {
  return name === 'unknown' ? 'Unknown app' : name;
}

// Who made the connection: the app on this machine, or the other LAN device.
export function who(traffic: { source: 'host' | 'router'; app: string; device?: Device }): string {
  if (traffic.source === 'host') return appName(traffic.app);
  return traffic.device?.label || traffic.device?.name || traffic.device?.ip || 'Unknown device';
}

// Short VLAN tag: the user's name for it, or its id.
export function vlan(device?: Device): string {
  if (!device?.vlan) return '';
  return device.vlan_name || `VLAN ${device.vlan}`;
}

// VLAN id, the user's name for it and router interface, e.g. "VLAN 20 · Living room · TV".
export function network(device?: Device): string {
  return [device?.vlan ? `VLAN ${device.vlan}` : '', device?.vlan_name, device?.interface].filter(Boolean).join(' · ');
}
