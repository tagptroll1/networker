import type { Flow } from './api';
import { remoteIP } from './format';

export function isLocalhost(flow: Flow): boolean {
  const ip = remoteIP(flow.remote);
  return ip === '::1' || /^127\./.test(ip) || /^::ffff:127\./i.test(ip);
}

export function visibleTraffic(flows: Flow[], showLocalhost: boolean): Flow[] {
  return showLocalhost ? flows : flows.filter((flow) => !isLocalhost(flow));
}

export function destinationName(flow: Flow): string {
  return flow.domain || remoteIP(flow.remote);
}

// Private, loopback, link-local and CGNAT ranges, IPv4 (incl. IPv4-mapped IPv6) and IPv6.
export function isInternal(flow: Flow): boolean {
  const ip = remoteIP(flow.remote).toLowerCase().replace(/^::ffff:(?=\d+\.)/, '');
  const v4 = ip.split('.').map(Number);
  if (v4.length === 4) {
    const [a, b] = v4;
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  return ip === '::1' || /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip);
}
