<script lang="ts">
  import type { Device } from './api';
  import { network } from './format';

  let { pid, local, executable, unit, source = 'host', device }: {
    pid?: number; local?: string; executable?: string; unit?: string; source?: 'host' | 'router'; device?: Device;
  } = $props();
</script>

<dl class="process-details">
  <div><dt>Local address</dt><dd class="mono">{local || 'Not stored'}</dd></div>
  {#if source === 'router'}
    <div><dt>Device</dt><dd>{device?.label || device?.name || 'Unknown name (no DHCP lease)'}{device?.label && device.name ? ` (DHCP: ${device.name})` : ''}</dd></div>
    <div><dt>MAC address</dt><dd class="mono">{device?.mac || 'Unknown'}</dd></div>
    <div><dt>Source</dt><dd>Router connection table · no process details</dd></div>
  {:else}
    <div><dt>PID</dt><dd>{pid || 'Unknown'}</dd></div>
    <div><dt>Executable</dt><dd class="mono">{executable || 'Unknown'}</dd></div>
    <div><dt>Systemd unit</dt><dd>{unit || 'Unknown'}</dd></div>
  {/if}
  {#if device}<div><dt>VLAN · interface</dt><dd>{network(device) || 'Unknown'}</dd></div>{/if}
</dl>
