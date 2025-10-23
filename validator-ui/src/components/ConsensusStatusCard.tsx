import type { ConsensusStatus } from '../types';

interface ConsensusStatusCardProps {
  status: ConsensusStatus;
}

function formatHash(hash: string | null) {
  if (!hash) return '—';
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

export function ConsensusStatusCard({ status }: ConsensusStatusCardProps) {
  return (
    <section className="card" aria-label="Consensus status">
      <h2>Consensus</h2>
      <div className="stat-grid">
        <div className="stat">
          <span>Height</span>
          <span>{status.height}</span>
        </div>
        <div className="stat">
          <span>Round</span>
          <span>{status.round}</span>
        </div>
        <div className="stat">
          <span>Quorum</span>
          <span>{status.quorum_reached ? 'Reached' : 'Pending'}</span>
        </div>
        <div className="stat">
          <span>Proposer</span>
          <span>{status.proposer ?? '—'}</span>
        </div>
        <div className="stat">
          <span>Block hash</span>
          <span>{formatHash(status.block_hash)}</span>
        </div>
        <div className="stat">
          <span>Pending votes</span>
          <span>{status.pending_votes}</span>
        </div>
      </div>
    </section>
  );
}
