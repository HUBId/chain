import { useCallback, useMemo, useState } from 'react';
import { useEventStream } from '../hooks/useEventStream';
import { parsePipelineEvent } from '../lib/api';
import type {
  PipelineDashboardSnapshot,
  PipelineEvent,
  PipelineFlowSnapshot,
  PipelineStage,
} from '../types';
import { PIPELINE_STAGE_ORDER } from '../types';

const STAGE_LABELS: Record<PipelineStage, string> = {
  GossipReceived: 'Gossip received',
  MempoolAccepted: 'Mempool accepted',
  LeaderElected: 'VRF leadership',
  BftFinalised: 'BFT finalised',
  FirewoodCommitted: 'Firewood committed',
  RewardsDistributed: 'Rewards distributed',
};

function formatHash(hash: string): string {
  if (hash.length <= 12) return hash;
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
}

function formatTimestamp(value: number | undefined | null): string {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return 'Pending';
  }
  try {
    const date = new Date(value);
    return date.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch (err) {
    return 'Pending';
  }
}

function latestStageTimestamp(flow: PipelineFlowSnapshot): number | undefined {
  let latest: number | undefined;
  for (const stage of PIPELINE_STAGE_ORDER) {
    const value = flow.stages?.[stage];
    if (typeof value === 'number' && Number.isFinite(value)) {
      latest = latest === undefined ? value : Math.max(latest, value);
    }
  }
  return latest;
}

export function PipelineTimelineCard() {
  const [snapshot, setSnapshot] = useState<PipelineDashboardSnapshot | null>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);

  const handleEvent = useCallback((event: PipelineEvent) => {
    if (event.type === 'dashboard') {
      setSnapshot(event.snapshot);
      setLastUpdated(Date.now());
    }
  }, []);

  const stream = useEventStream<PipelineEvent>('/wallet/pipeline/stream', {
    parser: (message) => parsePipelineEvent(message.data),
    onEvent: handleEvent,
    maxEvents: 0,
  });

  const flows = snapshot?.flows ?? [];

  const sortedFlows = useMemo(() => {
    return [...flows]
      .sort((a, b) => {
        const timeA = latestStageTimestamp(a) ?? 0;
        const timeB = latestStageTimestamp(b) ?? 0;
        return timeB - timeA;
      })
      .slice(0, 5);
  }, [flows]);

  const statusMessage = useMemo(() => {
    if (stream.status === 'connecting') return 'Connecting to pipeline stream…';
    if (stream.status === 'reconnecting') return 'Reconnecting to pipeline stream…';
    return undefined;
  }, [stream.status]);

  const showUnavailable = stream.status === 'error';

  return (
    <section className="card pipeline-timeline" aria-live="polite">
      <h2>Pipeline Timeline</h2>
      {statusMessage ? <p className="pipeline-stream-status">{statusMessage}</p> : null}
      {showUnavailable && stream.error ? (
        <p className="pipeline-stream-status" role="alert">
          Event stream unavailable: {stream.error.message}
        </p>
      ) : null}
      {lastUpdated ? (
        <p className="pipeline-updated" aria-live="off">
          Last updated {new Date(lastUpdated).toLocaleTimeString()}
        </p>
      ) : null}

      {sortedFlows.length === 0 ? (
        <p className="empty">No orchestrated submissions observed yet.</p>
      ) : (
        <ul className="timeline-list">
          {sortedFlows.map((flow) => (
            <li key={flow.hash} className="timeline-flow">
              <header className="timeline-flow-header">
                <div className="timeline-flow-tags">
                  <span className="timeline-hash" title={flow.hash}>
                    {formatHash(flow.hash)}
                  </span>
                  <span className="badge">Nonce {flow.target_nonce}</span>
                  {flow.commit_height !== null && flow.commit_height !== undefined ? (
                    <span className="badge badge-outline">Height {flow.commit_height}</span>
                  ) : null}
                </div>
                <span className="timeline-last-stage">
                  {formatTimestamp(latestStageTimestamp(flow))}
                </span>
              </header>
              <div className="timeline-stages">
                {PIPELINE_STAGE_ORDER.map((stage) => {
                  const completedAt = flow.stages?.[stage];
                  const isComplete = typeof completedAt === 'number' && Number.isFinite(completedAt);
                  return (
                    <div
                      key={stage}
                      className={`timeline-stage ${isComplete ? 'timeline-stage--done' : 'timeline-stage--pending'}`}
                    >
                      <span className="timeline-stage-label">{STAGE_LABELS[stage]}</span>
                      <span className="timeline-stage-time">{formatTimestamp(completedAt ?? null)}</span>
                    </div>
                  );
                })}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
