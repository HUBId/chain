import type { NodeTelemetrySnapshot } from '../types';

interface TelemetryPanelProps {
  telemetry: NodeTelemetrySnapshot;
}

export function TelemetryPanel({ telemetry }: TelemetryPanelProps) {
  return (
    <section className="card" aria-label="Telemetry overview">
      <h2>Telemetry</h2>
      <div className="stat-grid">
        <div className="stat">
          <span>Release channel</span>
          <span>{telemetry.release_channel}</span>
        </div>
        <div className="stat">
          <span>Validator height</span>
          <span>{telemetry.node.height}</span>
        </div>
        <div className="stat">
          <span>Consensus leader changes</span>
          <span>{telemetry.consensus.leader_changes}</span>
        </div>
        <div className="stat">
          <span>Pending uptime proofs</span>
          <span>{telemetry.mempool.uptime_proofs.length}</span>
        </div>
      </div>
    </section>
  );
}
