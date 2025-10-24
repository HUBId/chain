import { useCallback, useMemo, useState } from 'react';
import { useEventStream } from '../hooks/useEventStream';
import { parsePipelineEvent } from '../lib/api';
import type { PipelineErrorPayload, PipelineEvent } from '../types';

const MAX_ALERTS = 8;

function formatStage(stage: string): string {
  return stage.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatHash(hash: string | null | undefined): string {
  if (!hash) return '—';
  if (hash.length <= 12) return hash;
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
}

function formatObservedTime(timestamp: number): { label: string; iso: string } {
  try {
    const date = new Date(timestamp);
    return {
      label: date.toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      iso: date.toISOString(),
    };
  } catch (err) {
    return { label: 'Unknown', iso: new Date().toISOString() };
  }
}

function classifySeverity(error: PipelineErrorPayload): 'critical' | 'warning' {
  const message = error.message.toLowerCase();
  if (message.includes('timeout') || message.includes('slash') || message.includes('penalty')) {
    return 'critical';
  }
  return 'warning';
}

export function PipelineAlertsPanel() {
  const [alerts, setAlerts] = useState<PipelineErrorPayload[]>([]);

  const handleEvent = useCallback((event: PipelineEvent) => {
    if (event.type === 'error') {
      setAlerts((current) => {
        const next = [event.error, ...current];
        return next.slice(0, MAX_ALERTS);
      });
    }
  }, []);

  const stream = useEventStream<PipelineEvent>('/wallet/pipeline/stream', {
    parser: (message) => parsePipelineEvent(message.data),
    onEvent: handleEvent,
    maxEvents: 0,
  });

  const statusMessage = useMemo(() => {
    if (stream.status === 'connecting') return 'Connecting to pipeline stream…';
    if (stream.status === 'reconnecting') return 'Reconnecting to pipeline stream…';
    if (stream.status === 'error' && stream.error) {
      return `Event stream unavailable: ${stream.error.message}`;
    }
    return undefined;
  }, [stream.error, stream.status]);

  return (
    <section className="card pipeline-alerts" role="log" aria-live="polite">
      <h2>Pipeline Alerts</h2>
      {statusMessage ? <p className="pipeline-stream-status">{statusMessage}</p> : null}
      {alerts.length === 0 ? (
        <p className="empty">No pipeline issues detected.</p>
      ) : (
        <ul className="alert-list">
          {alerts.map((alert, index) => {
            const severity = classifySeverity(alert);
            const { label, iso } = formatObservedTime(alert.observed_at_ms);
            return (
              <li
                key={`${alert.stage}-${alert.observed_at_ms}-${index}`}
                className={`alert alert--${severity}`}
              >
                <header className="alert-header">
                  <span className="alert-stage">{formatStage(alert.stage)}</span>
                  <time dateTime={iso}>{label}</time>
                </header>
                <p className="alert-message">{alert.message}</p>
                <dl className="alert-meta">
                  <div>
                    <dt>Height</dt>
                    <dd>{alert.height}</dd>
                  </div>
                  <div>
                    <dt>Round</dt>
                    <dd>{alert.round}</dd>
                  </div>
                  <div>
                    <dt>Reason</dt>
                    <dd>{formatStage(alert.reason)}</dd>
                  </div>
                  <div>
                    <dt>Block</dt>
                    <dd>{formatHash(alert.block_hash ?? null)}</dd>
                  </div>
                </dl>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
