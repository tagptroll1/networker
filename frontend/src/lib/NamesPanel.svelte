<script lang="ts">
  import { onMount } from 'svelte';
  import { getLabels, setLabel, type Labels } from './api';
  import { networkGroups } from './network';
  import type { TrafficStore } from './traffic.svelte';

  let { traffic }: { traffic: TrafficStore } = $props();
  let labels = $state<Labels>({ vlans: {}, ips: {} });
  let loading = $state(true);
  let error = $state('');
  let saved = $state('');
  let newKind = $state<'ip' | 'vlan'>('ip');
  let newKey = $state('');
  let newName = $state('');

  let groups = $derived(networkGroups(traffic.flows, labels));

  async function load() {
    try {
      labels = await getLabels();
      error = '';
    } catch (e) {
      error = String(e instanceof Error ? e.message : e);
    } finally {
      loading = false;
    }
  }
  onMount(() => { void load(); });

  async function save(kind: 'vlan' | 'ip', key: string, name: string) {
    name = name.trim();
    const current = kind === 'vlan' ? labels.vlans[key] : labels.ips[key];
    if ((current ?? '') === name) return;
    try {
      await setLabel(kind, key, name);
      const next = { ...labels[kind === 'vlan' ? 'vlans' : 'ips'] };
      if (name) next[key] = name;
      else delete next[key];
      labels = kind === 'vlan' ? { ...labels, vlans: next } : { ...labels, ips: next };
      error = '';
      saved = name ? `Saved "${name}"` : 'Name removed';
    } catch (e) {
      error = String(e instanceof Error ? e.message : e);
    }
  }

  function commit(kind: 'vlan' | 'ip', key: string) {
    return (event: Event) => void save(kind, key, (event.currentTarget as HTMLInputElement).value);
  }
  function enter(event: KeyboardEvent) {
    if (event.key === 'Enter') (event.currentTarget as HTMLInputElement).blur();
  }

  let validNew = $derived(newKind === 'vlan'
    ? /^\d+$/.test(newKey) && Number(newKey) >= 1 && Number(newKey) <= 4094
    : /^[0-9a-fA-F:.]+$/.test(newKey) && (newKey.includes('.') || newKey.includes(':')));
  async function add(event: SubmitEvent) {
    event.preventDefault();
    if (!validNew || !newName.trim()) return;
    await save(newKind, newKind === 'vlan' ? String(Number(newKey)) : newKey, newName);
    if (!error) { newKey = ''; newName = ''; }
  }
</script>

<div class="history-note"><span class="note-symbol">ⓘ</span><span>Give VLANs and IP addresses your own names. Names are stored locally in networker, not on the router, and show on the map, in the live view and in history. An empty field removes the name. The list shows VLANs and devices in active traffic, plus everything you have named.</span></div>
{#if error}<div role="alert" class="alert">Could not save or load names: {error}</div>{/if}
<section class="panel list-panel">
  <div class="section-head"><div><div class="eyebrow">NETWORK</div><h2>VLANs and devices</h2></div><span class="head-note" aria-live="polite">{saved}</span></div>
  {#if loading}<p class="empty">Loading names…</p>
  {:else if groups.length === 0}<p class="empty">No VLANs or devices yet. Needs router integration, or add one below.</p>
  {:else}
    <div class="names">
      {#each groups as group (group.vlan)}
        <div class="name-group">
          <div class="name-row vlan">
            <span class="name-key">{group.vlan ? `VLAN ${group.vlan}` : 'Unknown VLAN'}</span>
            {#if group.vlan}
              <input aria-label={`Name for VLAN ${group.vlan}`} value={labels.vlans[group.vlan] ?? ''} placeholder={group.interface ?? 'VLAN name'} maxlength="64" onchange={commit('vlan', String(group.vlan))} onkeydown={enter} />
            {:else}<span></span>{/if}
            <span class="name-hint">{group.interface ? `Interface: ${group.interface}` : ''}</span>
          </div>
          {#each group.clients as client (client.ip)}
            <div class="name-row">
              <span class="name-key mono">{client.ip}</span>
              <input aria-label={`Name for ${client.ip}`} value={labels.ips[client.ip] ?? ''} placeholder={client.lease ?? (client.host ? 'This machine' : 'Device name')} maxlength="64" onchange={commit('ip', client.ip)} onkeydown={enter} />
              <span class="name-hint">{client.host ? 'This machine' : client.lease ? `DHCP: ${client.lease}` : client.flows ? '' : 'Not in active traffic'}</span>
            </div>
          {/each}
        </div>
      {/each}
    </div>
  {/if}
  <form class="name-add" onsubmit={add}>
    <select aria-label="Type" bind:value={newKind}><option value="ip">IP address</option><option value="vlan">VLAN</option></select>
    <input aria-label={newKind === 'vlan' ? 'VLAN number' : 'IP address'} placeholder={newKind === 'vlan' ? '1–4094' : '192.168.0.10'} bind:value={newKey} class="mono" />
    <input aria-label="Name" placeholder="Name" maxlength="64" bind:value={newName} />
    <button type="submit" disabled={!validNew || !newName.trim()}>Add</button>
  </form>
</section>

<style>
  .names { display: grid; gap: 14px; }
  .name-group { border-top: 1px solid #ffffff10; padding-top: 10px; }
  .name-row { display: grid; grid-template-columns: 150px minmax(0, 320px) minmax(0, 1fr); gap: 14px; align-items: center; padding: 5px 6px 5px 22px; }
  .name-row.vlan { padding-left: 6px; }
  .name-key { color: #cbdad0; font-size: 12px; }
  .vlan .name-key { color: #dce7ff; font: 700 11px ui-monospace, monospace; letter-spacing: .06em; }
  .name-hint { color: #82988f; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  input, select { min-width: 0; border: 1px solid #ffffff1c; border-radius: 6px; padding: 7px 9px; color: #dee8e1; background: #0f1a20; font: inherit; font-size: 12px; }
  input:focus, select:focus { outline: none; border-color: #8db4ff99; }
  .name-add { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 20px; padding-top: 16px; border-top: 1px solid #ffffff10; }
  .name-add input:first-of-type { width: 160px; }
  .name-add input:last-of-type { flex: 1; min-width: 160px; }
  .name-add button { border: 1px solid #a2e1b066; border-radius: 6px; padding: 7px 14px; color: #b5f1ce; background: #b0e7c017; cursor: pointer; font-size: 12px; }
  .name-add button:disabled { opacity: .45; cursor: default; }
  @media (max-width: 720px) {
    .name-row { grid-template-columns: 1fr; gap: 4px; padding-left: 6px; }
  }
</style>
