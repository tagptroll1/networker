<script lang="ts">
  import type { Hidden, VlanGroup } from './network';

  let { groups, hidden, change }: { groups: VlanGroup[]; hidden: Hidden; change: (hidden: Hidden) => void } = $props();
  let open = $state(false);
  try { open = localStorage.getItem('networker.map-aside') === 'open'; } catch { /* storage unavailable */ }

  function setOpen(value: boolean) {
    open = value;
    try { localStorage.setItem('networker.map-aside', value ? 'open' : 'closed'); } catch { /* storage unavailable */ }
  }
  const toggle = <T,>(list: T[], item: T) => list.includes(item) ? list.filter((value) => value !== item) : [...list, item];
  let count = $derived(hidden.vlans.length + hidden.clients.length);
  let ips = $derived(groups.flatMap((group) => group.clients.map((client) => client.ip)));
  let allOff = $derived(ips.length > 0 && ips.every((ip) => hidden.clients.includes(ip)));
  // Hides every client but leaves VLANs on, so one device can be ticked back alone.
  const toggleAll = () => change(allOff ? { vlans: [], clients: [] } : { vlans: [], clients: ips });
</script>

<aside class="map-aside" class:open aria-label="Show or hide VLANs and devices on the map">
  <button class="aside-toggle" aria-expanded={open} onclick={() => setOpen(!open)}>DEVICES {count ? `· ${count} HIDDEN` : ''} {open ? '▾' : '▸'}</button>
  {#if open}
    <div class="aside-body">
      {#if ips.length}<button class="toggle-all" onclick={toggleAll}>{allOff ? 'Show all' : 'Hide all'}</button>{/if}
      {#each groups as group (group.vlan)}
        {@const vlanOff = hidden.vlans.includes(group.vlan)}
        <section>
          <label class="vlan-row">
            <input type="checkbox" checked={!vlanOff} onchange={() => change({ ...hidden, vlans: toggle(hidden.vlans, group.vlan) })} />
            <span>{group.vlan ? `VLAN ${group.vlan}` : 'Unknown VLAN'}</span>
            <small>{group.name || group.interface || ''}</small>
          </label>
          {#each group.clients as client (client.ip)}
            <label class="client-row" class:off={vlanOff}>
              <input type="checkbox" checked={!hidden.clients.includes(client.ip)} disabled={vlanOff} onchange={() => change({ ...hidden, clients: toggle(hidden.clients, client.ip) })} />
              <span class:host={client.host}>{client.name}</span>
              {#if client.name !== client.ip}<small>{client.ip}</small>{/if}
            </label>
          {/each}
        </section>
      {:else}
        <p>No devices in active traffic.</p>
      {/each}
    </div>
  {/if}
</aside>

<style>
  .map-aside { position: absolute; top: 58px; right: 18px; z-index: 4; display: flex; flex-direction: column; align-items: flex-end; max-height: calc(100% - 118px); }
  .aside-toggle { border: 1px solid #ffffff35; border-radius: 6px; padding: 8px 11px; color: #a0b7af; background: #142229e8; font: 600 10px/1.2 ui-monospace, monospace; letter-spacing: .1em; cursor: pointer; }
  .aside-toggle:hover, .aside-toggle:focus-visible, .open .aside-toggle { border-color: #8db4ff99; color: #dce7ff; }
  .aside-body { width: 230px; margin-top: 6px; min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 8px; border: 1px solid #8db4ff40; border-radius: 9px; background: #12232bf2; box-shadow: 0 8px 30px #060f13dd; }
  section + section { margin-top: 6px; padding-top: 6px; border-top: 1px solid #ffffff12; }
  label { display: grid; grid-template-columns: 16px minmax(0, 1fr); column-gap: 6px; align-items: center; padding: 3px 4px; border-radius: 4px; cursor: pointer; }
  label:hover { background: #ffffff0a; }
  label span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  label small { grid-column: 2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #8299a0; font: 9px ui-monospace, monospace; }
  input { margin: 0; accent-color: #8db4ff; }
  .vlan-row span { color: #dce7ff; font: 700 10px ui-monospace, monospace; letter-spacing: .06em; }
  .client-row { padding-left: 14px; color: #c3d6cc; font-size: 11px; }
  .client-row span.host { color: #b5f1ce; }
  .client-row.off { opacity: .45; cursor: default; }
  .toggle-all { width: 100%; margin-bottom: 6px; padding: 6px; border: 1px solid #8db4ff55; border-radius: 5px; color: #dce7ff; background: none; font-size: 10px; cursor: pointer; }
  p { margin: 4px; color: #8fa49c; font-size: 11px; }
</style>
