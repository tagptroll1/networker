import { getConfig, getFlows, type Config, type Flow } from './api';
import { subscribeFlows, type LiveState } from './live';

export class TrafficStore {
  config = $state<Config | null>(null);
  flows = $state<Flow[]>([]);
  liveState = $state<LiveState>('connecting');
  liveError = $state('');
  configError = $state('');
  liveLoading = $state(true);

  start(fetcher: typeof fetch = fetch, subscribe = subscribeFlows): () => void {
    let active = true;
    let receivedEvent = false;
    const configRequest = new AbortController();
    const flowRequest = new AbortController();
    getConfig((url, init) => fetcher(url, { ...init, signal: configRequest.signal }))
      .then((value) => { if (active) this.config = value; })
      .catch((error) => { if (active) this.configError = String(error); });
    getFlows((url, init) => fetcher(url, { ...init, signal: flowRequest.signal }))
      .then((value) => { if (active && !receivedEvent) { this.flows = value; this.liveLoading = false; } })
      .catch((error) => { if (active && !receivedEvent) { this.liveError = String(error); this.liveLoading = false; } });
    const stop = subscribe(
      (value) => {
        if (!active) return;
        receivedEvent = true;
        flowRequest.abort();
        this.flows = value;
        this.liveLoading = false;
        this.liveError = '';
      },
      (state, error) => {
        if (!active) return;
        this.liveState = state;
        if (error) this.liveError = error;
        else if (state === 'connected') this.liveError = '';
      }
    );
    return () => { active = false; configRequest.abort(); flowRequest.abort(); stop(); };
  }
}
