<script lang="ts">
  import { onMount } from 'svelte';
  import { HistoryStore } from './history.svelte';
  import { getDNS, type DNSQuery } from './api';
  import ProcessDetails from './ProcessDetails.svelte';
  import { direction, formatBytes, formatLocation, formatTime, network, status, vlan, who } from './format';

  const history = new HistoryStore();
  let search = $state('');
  let filter = $state<'all' | 'outbound' | 'inbound'>('all');
  let expanded = $state<number | null>(null);
  let dns = $state<DNSQuery[]>([]);
  let dnsError = $state('');
  let dnsLoading = $state(true);
  let dnsRequest: AbortController | null = null;
  async function loadDNS() {
    dnsRequest?.abort();
    const request = new AbortController();
    dnsRequest = request;
    dnsLoading = true;
    dnsError = '';
    try {
      const entries = await getDNS(100, (url, init) => fetch(url, { ...init, signal: request.signal }));
      if (dnsRequest === request) dns = entries;
    } catch (error) {
      if (dnsRequest === request) dnsError = String(error instanceof Error ? error.message : error);
    } finally {
      if (dnsRequest === request) { dnsLoading = false; dnsRequest = null; }
    }
  }
  let visibleDNS = $derived(dns.filter((entry) => `${entry.name} ${entry.type} ${entry.server_ip}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())));
  let visibleHistory = $derived(history.entries.filter((entry) =>
    (filter === 'all' || entry.direction === filter) &&
    `${who(entry)} ${entry.device?.ip ?? ''} ${network(entry.device)} ${entry.remote_name ?? ''} ${entry.remote_ip} ${entry.remote_port} ${entry.location?.city ?? ''} ${entry.location?.country ?? ''}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())
  ));

  onMount(() => {
    void history.load();
    void loadDNS();
    return () => { history.dispose(); dnsRequest?.abort(); dnsRequest = null; };
  });
</script>

<div class="history-note"><span class="note-symbol">ⓘ</span><span>Shows up to 100 newest connections. The API has no paging; retention follows the server's time and row limits. A row is a connection or a UDP activity period, not a packet.</span></div>
<section class="panel list-panel"><div class="section-head"><div><div class="eyebrow">RECORDED CONNECTIONS</div><h2>Recent activity <span class="count">{visibleHistory.length}</span></h2></div><button class="refresh" onclick={() => void history.load()} disabled={history.loading}>↻ Refresh</button></div>
  {#if history.error}<div role="alert" class="alert">Could not load history: {history.error}</div>{/if}
  <div class="toolbar"><label class="search"><span aria-hidden="true">⌕</span><input aria-label="Search history" type="search" placeholder="Search app, device, VLAN, IP or location…" bind:value={search} /></label><div class="filters" aria-label="Filter direction"><button class:chosen={filter === 'all'} onclick={() => filter = 'all'}>All</button><button class:chosen={filter === 'outbound'} onclick={() => filter = 'outbound'}>Outbound</button><button class:chosen={filter === 'inbound'} onclick={() => filter = 'inbound'}>Inbound</button></div></div>
  {#if history.loading}<p class="empty">Loading history…</p>
  {:else if visibleHistory.length === 0}<p class="empty">{history.entries.length ? 'No matches.' : 'No connections recorded yet.'}</p>
  {:else}<div class="table-scroll"><table><thead><tr><th>TIME</th><th>APP / DEVICE</th><th>DESTINATION</th><th>LOCATION</th><th>TYPE</th><th>TRAFFIC</th></tr></thead><tbody>{#each visibleHistory as entry (entry.id)}
    <tr><td class="time">{formatTime(entry.started_at)}</td><td><strong>{who(entry)}{#if vlan(entry.device)} <span class="vlan-tag" class:router={entry.source === 'router'}>{vlan(entry.device)}</span>{/if}</strong><button class="detail-toggle" aria-expanded={expanded === entry.id} onclick={() => expanded = expanded === entry.id ? null : entry.id}>{entry.source === 'router' ? 'Device details' : 'Process details'}</button></td><td class="mono">{entry.remote_ip}<span class="port">:{entry.remote_port}</span>{#if entry.remote_name}<small>{entry.remote_name}</small>{/if}</td><td>{formatLocation(entry.location)}<small>{entry.location ? `± ${entry.location.accuracy_km} km${entry.location.organization ? ` · ${entry.location.organization}` : ''}` : ''}</small></td><td><span class="pill">{entry.protocol.toUpperCase()} · {direction(entry.direction)}</span><small>{status(entry.status)}</small></td><td class="bytes">↑ {formatBytes(entry.sent_bytes)}<small>↓ {formatBytes(entry.received_bytes)}</small></td></tr>
    {#if expanded === entry.id}<tr class="history-detail-row"><td colspan="6"><ProcessDetails pid={entry.pid} local={entry.local} executable={entry.executable} unit={entry.unit} source={entry.source} device={entry.device} /></td></tr>{/if}
  {/each}</tbody></table></div>{/if}
</section>
<section class="panel list-panel"><div class="section-head"><div><div class="eyebrow">DNS QUERIES</div><h2>Recent domain names <span class="count">{visibleDNS.length}</span></h2></div><button class="refresh" onclick={() => void loadDNS()} disabled={dnsLoading}>↻ Refresh</button></div>
  <p class="footnote">Shows up to 100 newest DNS queries over UDP port 53. These are domain names, not full URLs. Encrypted DNS and DNS over TCP are not shown.</p>
  {#if dnsError}<div role="alert" class="alert">Could not load DNS history: {dnsError}</div>{/if}
  {#if dnsLoading}<p class="empty">Loading DNS history…</p>
  {:else if visibleDNS.length === 0}<p class="empty">{dns.length ? 'No matches.' : 'No DNS queries recorded yet.'}</p>
  {:else}<div class="table-scroll"><table><thead><tr><th>TIME</th><th>DOMAIN</th><th>TYPE</th><th>DNS SERVER</th></tr></thead><tbody>{#each visibleDNS as entry (entry.id)}
    <tr><td class="time">{formatTime(entry.queried_at)}</td><td class="mono">{entry.name}</td><td>{entry.type}</td><td class="mono">{entry.server_ip}</td></tr>
  {/each}</tbody></table></div>{/if}
</section>
