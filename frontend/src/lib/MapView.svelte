<script lang="ts">
  import { prefersReducedMotion } from 'svelte/motion';
  import type { Snippet } from 'svelte';
  import type { Flow, Origin } from './api';
  import { direction, formatBytes, formatLocation, formatTime, network, remoteIP, status, vlan, who } from './format';
  import { destinations, mapNodes, NODE_SPACING, placeLabels, viewNodes, type MapLabel, type MapNode, type Rect } from './map';
  import { destinationName } from './visibility';

  let { origin, flows, selected, select, aside }: {
    origin: Origin | null;
    flows: Flow[];
    selected: number | null;
    // null deselects.
    select: (id: number | null) => void;
    // Optional panel drawn inside the map, e.g. device toggles.
    aside?: Snippet;
  } = $props();

  // Inline land path keeps coastlines crisp and thin at every zoom level.
  let land = $state('');
  $effect(() => {
    fetch('/world.svg').then((response) => response.text()).then((svg) => land = svg.match(/ d="([^"]+)"/)?.[1] ?? '').catch(() => {});
  });

  const point = (latitude: number, longitude: number) => ({
    x: (longitude + 180) * 1000 / 360,
    y: (90 - latitude) * 500 / 180
  });

  // Wrap over map edge instead of drawing a false line across the entire world.
  function arc(a: { x: number; y: number }, b: { x: number; y: number }, shift = 0): string {
    let x = b.x;
    if (x - a.x > 500) x -= 1000;
    if (x - a.x < -500) x += 1000;
    const ax = a.x + shift;
    const bx = x + shift;
    const lift = Math.min(75, Math.abs(bx - ax) * 0.16);
    return `M ${ax} ${a.y} Q ${(ax + bx) / 2} ${(a.y + b.y) / 2 - lift} ${bx} ${b.y}`;
  }

  const LEAVE_MS = 9000;

  // Fades from wherever the fade is at `at`, so an element redrawn mid-fade
  // (e.g. panned back into view) continues instead of starting over.
  function fadeOut(at: number) {
    return (node: Element) => {
      const elapsed = performance.now() - at;
      const from = Number(getComputedStyle(node).opacity) * Math.max(0, 1 - elapsed / LEAVE_MS);
      const animation = node.animate([{ opacity: from }, { opacity: 0 }], { duration: Math.max(0, LEAVE_MS - elapsed), fill: 'forwards' });
      return () => animation.cancel();
    };
  }

  function measureMap(node: HTMLElement) {
    const observer = new ResizeObserver(([entry]) => {
      mapWidth = entry.contentRect.width;
    });
    observer.observe(node);
    return { destroy: () => observer.disconnect() };
  }

  // Expands on the side the label already occupies, so the card grows out of it.
  function popupPosition(node: MapNode, label: MapLabel | undefined, width: number) {
    const popupWidth = Math.min(270, width - 24);
    const popupHeight = Math.min(260, width / 2 - 24);
    const right = node.x + 10;
    const left = node.x - popupWidth - 10;
    const fitsRight = right + popupWidth <= width - 12;
    const fitsLeft = left >= 12;
    const preferLeft = label !== undefined && label.x + label.width / 2 < node.x;
    const x = preferLeft && fitsLeft ? left : fitsRight ? right : fitsLeft ? left : Math.max(12, Math.min(width - popupWidth - 12, node.x - popupWidth / 2));
    const top = label ? Math.min(label.y, node.y - 10) : node.y - popupHeight / 2;
    return {
      x,
      y: Math.max(12, Math.min(width / 2 - popupHeight - 12, top)),
      width: popupWidth,
      height: popupHeight
    };
  }

  let hoverTimer: ReturnType<typeof setTimeout> | undefined;
  function hover(key: string) {
    clearTimeout(hoverTimer);
    hoveredKey = key;
  }
  // Short delay lets the pointer travel from marker to expanded card.
  function unhover() {
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => hoveredKey = null, 140);
  }

  const MAX_ZOOM = 16;
  const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

  function setView(k: number, x: number, y: number) {
    k = clamp(k, 1, MAX_ZOOM);
    view = { k, x: clamp(x, 1000 - 1000 * k, 0), y: clamp(y, 500 - 500 * k, 0) };
  }

  // Keeps the map point under (px, py) fixed while zooming.
  function zoomAt(px: number, py: number, factor: number) {
    const u = px * 1000 / mapWidth;
    const v = py * 1000 / mapWidth;
    const k = clamp(view.k * factor, 1, MAX_ZOOM);
    setView(k, u - (u - view.x) * k / view.k, v - (v - view.y) * k / view.k);
  }

  function panBy(dx: number, dy: number) {
    setView(view.k, view.x + dx * 1000 / mapWidth, view.y + dy * 1000 / mapWidth);
  }

  // Page scrolls as usual once the zoom limit is reached. The details card
  // scrolls its own list instead of zooming the map.
  function wheelZoom(node: HTMLElement) {
    const onWheel = (event: WheelEvent) => {
      if (event.target instanceof Element && event.target.closest('.node-popup, .map-aside')) return;
      const delta = event.deltaY * (event.deltaMode === 1 ? 16 : 1);
      const k = clamp(view.k * Math.exp(-delta * 0.002), 1, MAX_ZOOM);
      if (k === view.k) return;
      event.preventDefault();
      const box = node.getBoundingClientRect();
      zoomAt(event.clientX - box.left, event.clientY - box.top, k / view.k);
    };
    node.addEventListener('wheel', onWheel, { passive: false });
    return { destroy: () => node.removeEventListener('wheel', onWheel) };
  }

  const pointers = new Map<number, { x: number; y: number }>();
  let dragging = $state(false);
  let press: { x: number; y: number } | null = null;
  function localPoint(event: PointerEvent) {
    const box = (event.currentTarget as HTMLElement).getBoundingClientRect();
    return { x: event.clientX - box.left, y: event.clientY - box.top };
  }
  function pointerDown(event: PointerEvent) {
    // Drags start on the map itself, not on markers, labels or controls.
    if (!(event.target instanceof SVGElement)) return;
    hoveredKey = null;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    pointers.set(event.pointerId, localPoint(event));
    dragging = true;
    press = pointers.size === 1 ? localPoint(event) : null;
  }
  function pointerMove(event: PointerEvent) {
    const previous = pointers.get(event.pointerId);
    if (!previous) return;
    const before = [...pointers.values()];
    pointers.set(event.pointerId, localPoint(event));
    const after = [...pointers.values()];
    if (after.length === 1) return panBy(after[0].x - previous.x, after[0].y - previous.y);
    // Two fingers: pan with the midpoint, zoom with the spread.
    const mid = (points: { x: number; y: number }[]) => ({ x: (points[0].x + points[1].x) / 2, y: (points[0].y + points[1].y) / 2 });
    const spread = (points: { x: number; y: number }[]) => Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y);
    const a = mid(before);
    const b = mid(after);
    panBy(b.x - a.x, b.y - a.y);
    if (spread(before) > 0) zoomAt(b.x, b.y, spread(after) / spread(before));
  }
  function pointerUp(event: PointerEvent) {
    // A press on the map background that did not drag deselects.
    if (event.type === 'pointerup' && press && pointers.has(event.pointerId)) {
      const end = localPoint(event);
      if (Math.hypot(end.x - press.x, end.y - press.y) < 5) { pinned = null; select(null); }
    }
    press = null;
    pointers.delete(event.pointerId);
    dragging = pointers.size > 0;
  }

  let plotted = $derived(flows.filter((flow) => flow.location && flow.direction === 'outbound'));
  // Connections that just closed stay drawn like live ones while they fade,
  // so they keep following pan and zoom. A connection that reappears is live again.
  const departed = new Map<number, { flow: Flow; at: number }>();
  let previous: Flow[] = [];
  let expired = $state(0);
  let leaving = $derived.by(() => {
    void expired;
    const now = performance.now();
    const live = new Set(plotted.map((flow) => flow.id));
    for (const flow of previous) if (!live.has(flow.id) && !departed.has(flow.id)) departed.set(flow.id, { flow, at: now });
    previous = plotted;
    for (const [id, item] of departed) if (live.has(id) || now - item.at >= LEAVE_MS || prefersReducedMotion.current) departed.delete(id);
    return [...departed.values()];
  });
  $effect(() => {
    if (leaving.length === 0) return;
    const timer = setTimeout(() => expired++, Math.min(...leaving.map((item) => item.at + LEAVE_MS)) - performance.now());
    return () => clearTimeout(timer);
  });
  let routes = $derived([...plotted.map((flow) => ({ flow, at: null as number | null })), ...leaving]);
  let mapWidth = $state(1000);
  let wrap = $state<HTMLElement>();
  let mapSelection = $derived(plotted.some((flow) => flow.id === selected) ? selected : null);
  let groups = $derived(destinations(flows, mapSelection));
  // View offset is in viewBox units, so it survives resizes.
  let view = $state({ k: 1, x: 0, y: 0 });
  // Markers are laid out at zoomed size, so zooming in separates dense areas.
  let nodes = $derived(viewNodes(mapNodes(groups, mapWidth * view.k, mapSelection), view.x * mapWidth / 1000, view.y * mapWidth / 1000, mapWidth));
  // A closed connection's marker fades only where no live marker covers it.
  let leavingNodes = $derived(
    viewNodes(mapNodes(destinations(leaving.map((item) => item.flow), null), mapWidth * view.k), view.x * mapWidth / 1000, view.y * mapWidth / 1000, mapWidth)
      .filter((ghost) => !nodes.some((node) => Math.hypot(node.x - ghost.x, node.y - ghost.y) < NODE_SPACING))
      .map((node) => ({ node, at: Math.max(...node.flows.map((flow) => departed.get(flow.id)?.at ?? 0)) }))
  );
  let originPoint = $derived(origin ? point(origin.latitude, origin.longitude) : null);
  let crt = $state(true);
  let obstacles = $state<Rect[]>([]);
  // The aside grows when opened, so labels are placed again around it.
  let asideSize = $state(0);
  $effect(() => {
    const target = wrap?.querySelector('.map-aside');
    if (!target) return;
    const observer = new ResizeObserver(() => asideSize++);
    observer.observe(target);
    return () => observer.disconnect();
  });
  // Map controls and the origin marker must stay readable, so labels avoid them.
  $effect(() => {
    void [mapWidth, groups.length, plotted.length, crt, asideSize];
    if (!wrap) return;
    const rects = [...wrap.querySelectorAll<HTMLElement>('.map-label, .map-count, .crt-toggle, .map-aside')]
      .map((el) => ({ x: el.offsetLeft, y: el.offsetTop, width: el.offsetWidth, height: el.offsetHeight }));
    if (originPoint) {
      const scale = mapWidth / 1000;
      rects.push({ x: (originPoint.x * view.k + view.x) * scale - 6, y: (originPoint.y * view.k + view.y) * scale - 6, width: 12, height: 12 });
    }
    obstacles = rects;
  });
  let labels = $derived(placeLabels(nodes, mapWidth, obstacles, mapSelection));
  // The selected node's label keeps its place for the popup but is not drawn, since the popup covers it.
  let shownLabels = $derived(labels.filter((label) => !nodes.find((node) => node.key === label.key)?.flows.some((flow) => flow.id === mapSelection)));
  let hoveredKey = $state<string | null>(null);
  // A connection picked on the map keeps its card open until deselected.
  let pinned = $state<number | null>(null);
  function pick(id: number) {
    pinned = mapSelection === id ? null : id;
    select(id);
  }
  let activeNode = $derived(nodes.find((node) => node.key === hoveredKey) ?? (pinned !== null && pinned === mapSelection ? nodes.find((node) => node.flows.some((flow) => flow.id === pinned)) : undefined));
  let focused = $derived(activeNode?.flows.find((flow) => flow.id === mapSelection));
</script>

<svelte:window onkeydown={(event) => { if (event.key === 'Escape') hoveredKey = null; }} />

<div class="map-wrap" class:crt bind:this={wrap} class:dragging use:measureMap use:wheelZoom onpointerdown={pointerDown} onpointermove={pointerMove} onpointerup={pointerUp} onpointercancel={pointerUp} role="region" aria-label="Map of outbound connections">
  <svg viewBox="0 0 1000 500" role="img" aria-label="World map with approximate origin and outbound connections">
    <defs>
      <pattern id="grid" width="83.333" height="83.333" patternUnits="userSpaceOnUse">
        <path d="M 83.333 0 L 0 0 0 83.333" fill="none" stroke="#d5e4d9" stroke-width="0.5" opacity=".11" />
      </pattern>
    </defs>
    <rect width="1000" height="500" fill="#101c22" />
    <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
    <path d={land} class="land" />
    <rect width="1000" height="500" fill="url(#grid)" />
    {#if originPoint}
      {#each routes as { flow, at } (flow.id)}
        {@const target = point(flow.location!.latitude, flow.location!.longitude)}
        {@const active = mapSelection === flow.id}
        <g {@attach at === null ? undefined : fadeOut(at)} class:leaving={at !== null} class:muted={mapSelection !== null && !active} class:router={flow.source === 'router'}>
          {#each [-1000, 0, 1000] as shift}
            <path d={arc(originPoint, target, shift)} class="route sent" />
            {#if flow.received_bytes > 0}
              <path d={arc(originPoint, target, shift)} class="route received" />
            {/if}
            <path d={arc(originPoint, target, shift)} class="route moving" />
          {/each}
        </g>
      {/each}
    {/if}
    {#if originPoint}
      <circle cx={originPoint.x} cy={originPoint.y} r={7 / view.k} fill="#ecca89" opacity=".15" />
      <circle cx={originPoint.x} cy={originPoint.y} r={3 / view.k} fill="#f6d398" />
    {/if}
    </g>
  </svg>
  {#each shownLabels as label (label.key)}
    <div
      class="node-label"
      class:router={nodes.find((node) => node.key === label.key)?.primary.source === 'router'}
      class:compact={label.level === 'compact'}
      style:left={`${label.x}px`}
      style:top={`${label.y}px`}
      style:width={`${label.width}px`}
      style:height={`${label.height}px`}
      aria-hidden="true"
      onpointerenter={() => hover(label.key)}
      onpointerleave={(event) => { if (event.pointerType !== 'touch') unhover(); }}
    >
      {#each label.lines as line, index}<span class:head={index === 0} class:bytes={index === label.lines.length - 1 && label.level === 'full'}>{line}</span>{/each}
    </div>
  {/each}
  {#each leavingNodes as { node, at } (node.key)}
    <span
      class="node-marker leaving"
      class:multi={node.flows.length > 1}
      class:router={node.flows.every((flow) => flow.source === 'router')}
      class:mixed={node.flows.some((flow) => flow.source === 'router') && node.flows.some((flow) => flow.source === 'host')}
      style:left={`${Math.max(6, Math.min(mapWidth - 6, node.x))}px`}
      style:top={`${Math.max(6, Math.min(mapWidth / 2 - 6, node.y))}px`}
      {@attach fadeOut(at)}
      aria-hidden="true"
    ></span>
  {/each}
  {#each nodes as node (node.key)}
    <button
      class="node-marker"
      class:multi={node.flows.length > 1}
      class:router={node.flows.every((flow) => flow.source === 'router')}
      class:mixed={node.flows.some((flow) => flow.source === 'router') && node.flows.some((flow) => flow.source === 'host')}
      class:selected={node.flows.some((flow) => flow.id === mapSelection)}
      class:active={activeNode?.key === node.key}
      style:left={`${Math.max(6, Math.min(mapWidth - 6, node.x))}px`}
      style:top={`${Math.max(6, Math.min(mapWidth / 2 - 6, node.y))}px`}
      onpointerenter={() => hover(node.key)}
      onpointerleave={(event) => { if (event.pointerType !== 'touch') unhover(); }}
      onfocus={() => hover(node.key)}
      onblur={unhover}
      onclick={() => pick(node.primary.id)}
      aria-label={`${formatLocation(node.location)} · ${node.flows.length} ${node.flows.length === 1 ? 'connection' : 'connections'}. Select connection`}
      aria-expanded={activeNode?.key === node.key}
    ></button>
  {/each}
  {#if activeNode}
    {@const position = popupPosition(activeNode, labels.find((label) => label.key === activeNode.key), mapWidth)}
    <div class="node-popup" role="group" aria-label="Connections at {formatLocation(activeNode.location)}" style:left={`${position.x}px`} style:top={`${position.y}px`} style:width={`${position.width}px`} style:max-height={`${position.height}px`} onpointerenter={() => hover(activeNode.key)} onpointerleave={(event) => { if (event.pointerType !== 'touch') unhover(); }} onfocusin={() => hover(activeNode.key)} onfocusout={unhover}>
      <div class="popup-heading"><strong>{formatLocation(activeNode.location)}</strong><span>↑ {formatBytes(activeNode.sent)} · ↓ {formatBytes(activeNode.received)}</span></div>
      {#if focused}
        <div class="popup-detail"><strong>{who(focused)}</strong>{#if focused.domain} · {focused.domain}{/if}{#if network(focused.device)}<br /><span class="vlan">{focused.source === 'router' && focused.device?.name ? `${focused.device.ip} · ` : ''}{network(focused.device)}</span>{/if}<br /><span class="socket">{focused.remote}</span><br />{formatLocation(focused.location)} · ±{focused.location!.accuracy_km} km{focused.location?.organization ? ` · ${focused.location.organization}` : ''}{focused.location?.asn ? ` (AS${focused.location.asn})` : ''}<br />↑ {formatBytes(focused.sent_bytes)} · ↓ {formatBytes(focused.received_bytes)}<br />{focused.protocol.toUpperCase()} · {direction(focused.direction)} · {status(focused.status)} · last seen {formatTime(focused.last_seen)}</div>
      {/if}
      <div class="popup-flows">
        {#each activeNode.flows as flow (flow.id)}
          <button class:selected={flow.id === mapSelection} onclick={() => pick(flow.id)}>
            <strong>{who(flow)} <span>· {destinationName(flow)}</span></strong>
            <small>{vlan(flow.device) ? `${vlan(flow.device)} · ` : ''}{remoteIP(flow.remote)} · {formatLocation(flow.location)} · ↑ {formatBytes(flow.sent_bytes)} · ↓ {formatBytes(flow.received_bytes)}</small>
          </button>
        {/each}
      </div>
    </div>
  {/if}
  <div class="map-count">{groups.length} places · {plotted.length} outbound connections</div>
  <div class="map-label top"><span class="pin"></span> APPROXIMATE GEOLOCATION</div>
  {@render aside?.()}
  <button class="crt-toggle" aria-pressed={crt} onclick={() => crt = !crt}>CRT {crt ? 'ON' : 'OFF'}</button>
  <div class="map-label bottom">{origin ? `${origin.latitude.toFixed(2)}°, ${origin.longitude.toFixed(2)}° · origin` : 'Origin not configured'}</div>
  {#if !origin}
    <div class="map-notice">Set <code>-origin-lat</code> and <code>-origin-lon</code> at startup to draw lines.</div>
  {:else if plotted.length === 0}
    <div class="map-notice">No active outbound connections with a known location.</div>
  {/if}
</div>

<style>
  .map-wrap { position: relative; width: 100%; aspect-ratio: 2 / 1; overflow: hidden; border-radius: 13px; background: #101c22; cursor: grab; touch-action: none; user-select: none; }
  .map-wrap.dragging { cursor: grabbing; }
  .map-wrap.crt::after { content: ''; position: absolute; inset: 0; z-index: 0; pointer-events: none; background: radial-gradient(ellipse at center, transparent 50%, #030c0e6b 100%), repeating-linear-gradient(to bottom, transparent 0 2px, #030a0c3d 2px 4px); box-shadow: inset 0 0 40px 10px #030c0e66; }
  .crt svg { filter: brightness(1.1) contrast(1.08) saturate(1.18); }
  svg { display: block; width: 100%; height: 100%; }
  .land { fill: #23333a; stroke: #40524f; stroke-width: .66; vector-effect: non-scaling-stroke; }
  .route { fill: none; stroke: #86e3ae; stroke-width: .85; stroke-linecap: round; opacity: .55; pointer-events: none; vector-effect: non-scaling-stroke; }
  .route.received { stroke: #e7be78; stroke-width: .65; stroke-dasharray: 2 7; opacity: .65; }
  .route.moving { stroke: #baf5cd; stroke-width: 1.6; stroke-dasharray: 3 14; opacity: .9; animation: route-flow 1.8s linear infinite; }
  /* Other LAN devices, seen by the router: blue dashes instead of solid green. */
  .router .route.sent { stroke: #8db4ff; stroke-dasharray: 6 4; }
  .router .route.moving { stroke: #d2e1ff; }
  @keyframes route-flow { to { stroke-dashoffset: -17; } }
  .leaving .route.moving { animation-play-state: paused; }
  @media (prefers-reduced-motion: reduce) { .route.moving { animation: none; } }
  .muted { opacity: .22; }
  .node-marker { position: absolute; z-index: 3; transform: translate(-50%, -50%); width: 9px; height: 9px; padding: 0; border: 1px solid #0d1a1f; border-radius: 50%; background: #a2edc1; box-shadow: 0 0 6px #8ee5ba88; cursor: pointer; }
  .node-marker.leaving { z-index: 2; pointer-events: none; }
  .node-marker::before { content: ''; position: absolute; inset: -3px; border-radius: 50%; }
  .node-marker.multi { width: 12px; height: 12px; background: #a2edc1; box-shadow: 0 0 0 2px #a2edc155, 0 0 6px #8ee5ba88; }
  .node-marker.router { border-radius: 1px; background: #8db4ff; box-shadow: 0 0 6px #8db4ff88; transform: translate(-50%, -50%) rotate(45deg); }
  .node-marker.router.multi { box-shadow: 0 0 0 2px #8db4ff55, 0 0 6px #8db4ff88; }
  .node-marker.mixed { box-shadow: 0 0 0 2px #8db4ffaa, 0 0 6px #8ee5ba88; }
  .node-marker:hover, .node-marker:focus-visible, .node-marker.active { z-index: 4; background: #fff2ce; box-shadow: 0 0 0 3px #f6d39855; }
  .node-marker.selected { background: #fff2ce; box-shadow: 0 0 0 3px #f6d39866, 0 0 8px #f6d398aa; }
  .node-label { position: absolute; z-index: 2; display: flex; flex-direction: column; justify-content: center; padding: 3px 6px; overflow: hidden; border: 1px solid #a2edc140; border-radius: 4px; color: #a9cbbb; background: #11222ae6; font: 10px/13px ui-monospace, SFMono-Regular, Consolas, monospace; white-space: nowrap; cursor: default; }
  .node-label span { overflow: hidden; text-overflow: ellipsis; }
  .node-label .head { color: #d5ede0; font-weight: 700; }
  .node-label.compact .head { font-weight: 400; }
  .node-label .bytes { color: #a4dcb9; }
  .node-label.router { border-color: #8db4ff55; }
  .node-label.router .head { color: #dce7ff; }
  .node-popup { position: absolute; z-index: 5; overflow-y: auto; overscroll-behavior: contain; padding: 10px; border: 1px solid #a3d8b670; border-radius: 9px; color: #d5ede0; background: #12232b; box-shadow: 0 8px 30px #060f13dd; cursor: auto; user-select: text; }
  .popup-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 7px; font-size: 12px; }
  .popup-heading span { flex: none; color: #a4dcb9; font: 10px ui-monospace, monospace; }
  .popup-flows { display: grid; gap: 4px; }
  .popup-flows button { min-width: 0; padding: 7px 8px; border: 1px solid transparent; border-radius: 5px; color: #d5ede0; background: #1c3034; text-align: left; cursor: pointer; }
  .popup-flows button:hover, .popup-flows button:focus-visible, .popup-flows button.selected { border-color: #a2e1b0; background: #203b38; }
  .popup-flows strong { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 10px; }
  .popup-flows strong span { color: #9abbb0; font-family: ui-monospace, monospace; font-weight: 400; }
  .popup-flows small { display: block; margin-top: 3px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #a7d7b9; font-size: 9px; }
  .popup-detail { border-bottom: 1px solid #a3d8b638; margin-bottom: 8px; padding-bottom: 8px; color: #b5d2c0; font-size: 10px; line-height: 1.5; overflow-wrap: anywhere; }
  .map-label { position: absolute; z-index: 1; color: #a0b7af; background: #142229d6; border: 1px solid #ffffff18; border-radius: 6px; padding: 8px 11px; font: 600 10px/1.2 ui-monospace, monospace; letter-spacing: .13em; }
  .crt-toggle { position: absolute; top: 18px; right: 18px; z-index: 4; border: 1px solid #ffffff35; border-radius: 6px; padding: 8px 11px; color: #a0b7af; background: #142229e8; font: 600 10px/1.2 ui-monospace, monospace; letter-spacing: .1em; cursor: pointer; }
  .crt-toggle:hover, .crt-toggle:focus-visible { border-color: #8ee5ba; color: #d5ede0; }
  .crt-toggle[aria-pressed='true'] { border-color: #8ee5ba99; color: #baf5cd; box-shadow: 0 0 12px #8ee5ba33; }
  .map-count { position: absolute; right: 18px; bottom: 18px; z-index: 1; color: #a3bdb0; background: #142229d6; border: 1px solid #ffffff18; border-radius: 6px; padding: 8px 11px; font: 10px ui-monospace, monospace; }
  .top { top: 18px; left: 18px; } .bottom { bottom: 18px; left: 18px; letter-spacing: .04em; text-transform: none; }
  .pin { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #8ee5ba; margin-right: 8px; }
  .map-notice { position: absolute; z-index: 1; left: 50%; top: 50%; transform: translate(-50%, -50%); background: #101b21ee; color: #d9e5df; border: 1px solid #66827560; border-radius: 9px; padding: 14px 20px; width: max-content; max-width: 80%; text-align: center; font-size: 13px; }
  code { color: #a8e4bf; }
  .vlan { color: #a9c4ff; font: 10px ui-monospace, monospace; }
  .socket { font: 10px ui-monospace, monospace; }
  @media (max-width: 700px) {
    .map-label, .map-count { font-size: 9px; }
  }
</style>
