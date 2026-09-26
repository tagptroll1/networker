<script lang="ts">
  import { onMount } from 'svelte';
  import '../app.css';
  import DashboardShell from '$lib/DashboardShell.svelte';
  import LivePanel from '$lib/LivePanel.svelte';
  import HistoryPanel from '$lib/HistoryPanel.svelte';
  import NamesPanel from '$lib/NamesPanel.svelte';
  import { TrafficStore } from '$lib/traffic.svelte';
  import { visibleTraffic } from '$lib/visibility';

  const traffic = new TrafficStore();
  let view = $state<'live' | 'history' | 'names'>('live');
  let showLocalhost = $state(false);
  onMount(() => traffic.start());
</script>

<svelte:head>
  <title>Networker | Network traffic</title>
  <meta name="description" content="Local overview of active network connections and connection history." />
</svelte:head>

<DashboardShell {view} count={visibleTraffic(traffic.flows, showLocalhost).length} router={traffic.config?.router ?? false} switchView={(next) => view = next}>
  {#if view === 'live'}
    <LivePanel {traffic} {showLocalhost} toggleLocalhost={() => showLocalhost = !showLocalhost} />
  {:else if view === 'history'}
    <HistoryPanel />
  {:else}
    <NamesPanel {traffic} />
  {/if}
</DashboardShell>
