import type { ValidatorProofQueueResponse } from '../types';

interface ProofQueuePanelProps {
  queue: ValidatorProofQueueResponse;
}

export function ProofQueuePanel({ queue }: ProofQueuePanelProps) {
  return (
    <section className="card" aria-label="Proof queue">
      <h2>Proof Queue</h2>
      <div className="stat-grid">
        <div className="stat">
          <span>Transactions</span>
          <span>{queue.totals.transactions}</span>
        </div>
        <div className="stat">
          <span>Identities</span>
          <span>{queue.totals.identities}</span>
        </div>
        <div className="stat">
          <span>Votes</span>
          <span>{queue.totals.votes}</span>
        </div>
        <div className="stat">
          <span>Uptime proofs</span>
          <span>{queue.totals.uptime_proofs}</span>
        </div>
      </div>

      <h3>Pending uptime proofs</h3>
      {queue.uptime_proofs.length === 0 ? (
        <p className="empty">No pending uptime proofs.</p>
      ) : (
        <ul className="list">
          {queue.uptime_proofs.map((proof) => (
            <li key={`${proof.identity}-${proof.window_start}`} className="stat">
              <span>{proof.identity}</span>
              <span>
                {new Date(proof.window_start * 1000).toLocaleString()} →{' '}
                {new Date(proof.window_end * 1000).toLocaleString()}
              </span>
              <span className="badge">{proof.credited_hours} h</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
