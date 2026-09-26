import { parseFlows, type Flow } from './api';

export type LiveState = 'connecting' | 'connected' | 'reconnecting';

export function subscribeFlows(
  update: (flows: Flow[]) => void,
  status: (state: LiveState, error?: string) => void,
  create: (url: string) => EventSource = (url) => new EventSource(url)
): () => void {
  const source = create('/api/events');
  const onFlows = (event: MessageEvent) => {
    try {
      update(parseFlows(JSON.parse(event.data)));
      status('connected');
    } catch {
      status('reconnecting', 'Invalid stream response');
    }
  };
  const onOpen = () => status('connected');
  const onError = () => status('reconnecting', 'Live stream interrupted. Retrying.');
  source.addEventListener('flows', onFlows);
  source.addEventListener('open', onOpen);
  source.addEventListener('error', onError);
  return () => {
    source.removeEventListener('flows', onFlows);
    source.removeEventListener('open', onOpen);
    source.removeEventListener('error', onError);
    source.close();
  };
}
