<script lang="ts">
  import MapView from './MapView.svelte';
  import MapAside from './MapAside.svelte';
  import { networkGroups, shownOnMap, type Hidden } from './network';
  import ProcessDetails from './ProcessDetails.svelte';
  import type { Flow } from './api';
  import type { TrafficStore } from './traffic.svelte';
  import { direction, formatBytes, formatLocation, formatTime, network, status, vlan, who } from './format';
  import { destinationName, isInternal, visibleTraffic } from './visibility';

  let { traffic, showLocalhost, toggleLocalhost }: { traffic: TrafficStore; showLocalhost: boolean; toggleLocalhost: () => void } = $props();
  let search = $state('');
  let filter = $state<'all' | 'outbound' | 'inbound'>('all');
  let selected = $state<number | null>(null);

  let shown = $derived(visibleTraffic(traffic.flows, showLocalhost));
  // Map-only toggles for VLANs and clients, remembered in this browser.
  let hidden = $state<Hidden>({ vlans: [], clients: [] });
  try {
    const saved = JSON.parse(localStorage.getItem('networker.map-hidden') ?? 'null');
    if (Array.isArray(saved?.vlans) && Array.isArray(saved?.clients)) hidden = { vlans: saved.vlans.filter(Number.isInteger), clients: saved.clients.filter((ip: unknown) => typeof ip === 'string') };
  } catch { /* storage unavailable */ }
  function hide(value: Hidden) {
    hidden = value;
    try { localStorage.setItem('networker.map-hidden', JSON.stringify(value)); } catch { /* storage unavailable */ }
  }
  // The selected connection stays listed and mapped after it closes, until deselected.
  let lastSelected: Flow | null = null;
  let selectedFlow = $derived.by(() => lastSelected = selected === null ? null : shown.find((flow) => flow.id === selected) ?? (lastSelected?.id === selected ? lastSelected : null));
  let kept = $derived(selectedFlow && !shown.some((flow) => flow.id === selectedFlow.id) ? [...shown, selectedFlow] : shown);
  let groups = $derived(networkGroups(shown));
  let onMap = $derived(kept.filter((flow) => shownOnMap(flow, hidden)));
  let totalSent = $derived(shown.reduce((sum, flow) => sum + flow.sent_bytes, 0));
  let totalReceived = $derived(shown.reduce((sum, flow) => sum + flow.received_bytes, 0));
  let internal = $derived(shown.filter(isInternal).length);
  let mappable = $derived(shown.filter((flow) => flow.location && flow.direction === 'outbound'));
  let mappedInternal = $derived(mappable.filter(isInternal).length);
  let visibleFlows = $derived(kept.filter((flow) =>
    (filter === 'all' || flow.direction === filter) &&
    `${who(flow)} ${flow.device?.ip ?? ''} ${network(flow.device)} ${flow.domain ?? ''} ${flow.remote} ${flow.local} ${flow.location?.city ?? ''} ${flow.location?.country ?? ''}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())
  ));
</script>

<div class="stats">
  <div class="stat"><span>ACTIVE CONNECTIONS</span><strong><span class="split">{shown.length - internal}<em>external</em></span><span class="split">{internal}<em>internal</em></span></strong><small>Last 30 seconds</small></div>
  <div class="stat"><span>MAPPED CONNECTIONS</span><strong><span class="split">{mappable.length - mappedInternal}<em>external</em></span><span class="split">{mappedInternal}<em>internal</em></span></strong><small>Outbound, known location</small></div>
  <div class="stat"><span>SENT ↑</span><strong>{formatBytes(totalSent)}</strong><small>Active connections · total</small></div>
  <div class="stat"><span>RECEIVED ↓</span><strong>{formatBytes(totalReceived)}</strong><small>Active connections · total</small></div>
</div>
{#if traffic.configError}<div role="alert" class="alert">Could not load map config: {traffic.configError}</div>{/if}
{#if traffic.liveError}<div role="alert" class="alert">{traffic.liveError}</div>{/if}
<section class="panel map-panel"><div class="section-head"><div><div class="eyebrow">GEOGRAPHIC OVERVIEW</div></div><span class="head-note">{#if traffic.config?.router}<i class="legend sent"></i> This machine <i class="legend router"></i> Other devices{:else}<i class="legend sent"></i> Sent{/if} <i class="legend received"></i> Received</span></div>
  {#if traffic.config === null && !traffic.configError}<p class="empty">Loading map config…</p>{:else}<MapView origin={traffic.config?.origin ?? null} flows={onMap} {selected} select={(id) => selected = id === null || selected === id ? null : id} aside={traffic.config?.router ? deviceToggles : undefined} />{/if}
</section>
<section class="panel list-panel"><div class="section-head"><div><div class="eyebrow">ACTIVITY</div><h2>Active connections <span class="count">{visibleFlows.length}</span></h2></div></div>
  <div class="toolbar"><label class="search"><span aria-hidden="true">⌕</span><input aria-label="Search active connections" type="search" placeholder="Search app, device, VLAN, domain, IP or location…" bind:value={search} /></label><div class="filters" aria-label="Filter connections"><button class:chosen={filter === 'all'} onclick={() => filter = 'all'}>All</button><button class:chosen={filter === 'outbound'} onclick={() => filter = 'outbound'}>Outbound</button><button class:chosen={filter === 'inbound'} onclick={() => filter = 'inbound'}>Inbound</button><button class:chosen={showLocalhost} aria-pressed={showLocalhost} onclick={toggleLocalhost}>Show localhost</button></div></div>
  {#if traffic.liveLoading}<p class="empty">Loading active connections…</p>
  {:else if visibleFlows.length === 0}<p class="empty">{shown.length ? 'No matches.' : 'No active connections right now.'}</p>
  {:else}<div class="flow-list">{#each visibleFlows as flow (flow.id)}
    <div class="flow-item"><button class="flow-row" class:selected={selected === flow.id} onclick={() => selected = selected === flow.id ? null : flow.id} aria-expanded={selected === flow.id} aria-label={`Details for ${who(flow)} to ${destinationName(flow)} (${flow.remote})`}>
      <span class="app-icon" class:router={flow.source === 'router'}>{flow.source === 'router' ? '◆' : who(flow).slice(0, 1).toUpperCase()}</span><span class="flow-main"><strong>{who(flow)}{#if vlan(flow.device)} <span class="vlan-tag" class:router={flow.source === 'router'}>{vlan(flow.device)}</span>{/if}</strong>{#if flow.domain}<small>{flow.domain}</small>{/if}<small class="mono">{flow.remote} <span class="muted-text">· {flow.protocol.toUpperCase()}</span></small></span>
      <span class="flow-place">{formatLocation(flow.location)}<small>{flow.location ? `± ${flow.location.accuracy_km} km` : 'Not on map'}</small></span>
      <span class="flow-transfer">↑ {formatBytes(flow.sent_bytes)}<small>↓ {formatBytes(flow.received_bytes)}</small></span>
      <span class="flow-meta">{direction(flow.direction)}<small>{status(flow.status)} · {formatTime(flow.last_seen)}</small></span>
    </button>
    {#if selected === flow.id}<div class="flow-detail"><ProcessDetails pid={flow.pid} local={flow.local} executable={flow.executable} unit={flow.unit} source={flow.source} device={flow.device} /></div>{/if}</div>
  {/each}</div>{/if}
</section>

{#snippet deviceToggles()}<MapAside {groups} {hidden} change={hide} />{/snippet}
