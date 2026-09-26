<script lang="ts">
  import type { Snippet } from 'svelte';

  type View = 'live' | 'history' | 'names';
  let { view, count, router, switchView, children }: {
    view: View;
    router: boolean;
    count: number;
    switchView: (view: View) => void;
    children: Snippet;
  } = $props();

  // Collapsed sidebar shows only logo and icons; remembered in this browser.
  let collapsed = $state(false);
  try { collapsed = localStorage.getItem('networker.sidebar') === 'collapsed'; } catch { /* storage unavailable */ }
  function toggleSidebar() {
    collapsed = !collapsed;
    try { localStorage.setItem('networker.sidebar', collapsed ? 'collapsed' : 'expanded'); } catch { /* storage unavailable */ }
  }
</script>

<div class="shell">
  <aside class="sidebar" class:collapsed>
    <div class="brand"><span class="logo">N<span class="logo-dot">.</span></span><span class="brand-copy">NETWORKER<small>TRAFFIC OVERVIEW</small></span></div>
    <p class="nav-heading">OVERVIEW</p>
    <nav aria-label="Main navigation">
      <button class:active={view === 'live'} onclick={() => switchView('live')} title="Live" aria-label={`Live, ${count} active`}><span class="nav-icon">◉</span> <span class="nav-text">Live</span> <span class="nav-count">{count}</span></button>
      <button class:active={view === 'history'} onclick={() => switchView('history')} title="History" aria-label="History"><span class="nav-icon">◷</span> <span class="nav-text">History</span></button>
      <button class:active={view === 'names'} onclick={() => switchView('names')} title="Names" aria-label="Names"><span class="nav-icon">✎</span> <span class="nav-text">Names</span></button>
    </nav>
    <button class="collapse-toggle" onclick={toggleSidebar} aria-expanded={!collapsed} aria-label={collapsed ? 'Show menu' : 'Hide menu'} title={collapsed ? 'Show menu' : 'Hide menu'}>{collapsed ? '»' : '« Hide menu'}</button>
    <div class="sidebar-foot" title="Local instance · 127.0.0.1"><span class="sidebar-pulse"></span><span class="nav-text"> LOCAL INSTANCE</span> <small class="nav-text">127.0.0.1 · No cloud service</small></div>
  </aside>

  <main>
    <div class="content">

      {@render children()}
      <footer>NETWORKER <span>·</span> {router ? 'This machine and router connection table' : 'Local traffic only'} <span>·</span> Domain names are stored, not packet contents</footer>
    </div>
  </main>
</div>
