import { ConsensusStatusCard } from './components/ConsensusStatusCard';
import { PeerListCard } from './components/PeerListCard';
import { ProofQueuePanel } from './components/ProofQueuePanel';
import { TelemetryPanel } from './components/TelemetryPanel';
import { useApiData } from './hooks/useApiData';
import type {
  NodeTelemetrySnapshot,
  ValidatorPeerResponse,
  ValidatorProofQueueResponse,
  ValidatorStatusResponse,
} from './types';

function LoadingCard({ title }: { title: string }) {
  return (
    <section className="card" aria-busy="true">
      <h2>{title}</h2>
      <p>Loading…</p>
    </section>
  );
}

function ErrorCard({ title, error }: { title: string; error: Error }) {
  return (
    <section className="card" role="alert">
      <h2>{title}</h2>
      <p>Failed to load data.</p>
      <pre>{error.message}</pre>
    </section>
  );
}

export default function App() {
  const status = useApiData<ValidatorStatusResponse>('/validator/status');
  const proofs = useApiData<ValidatorProofQueueResponse>('/validator/proofs');
  const peers = useApiData<ValidatorPeerResponse>('/validator/peers');
  const telemetry = useApiData<NodeTelemetrySnapshot>('/validator/telemetry');

  return (
    <main className="dashboard">
      {status.status === 'ready' && status.data ? (
        <ConsensusStatusCard status={status.data.consensus} />
      ) : status.status === 'error' && status.error ? (
        <ErrorCard title="Consensus" error={status.error} />
      ) : (
        <LoadingCard title="Consensus" />
      )}

      {proofs.status === 'ready' && proofs.data ? (
        <ProofQueuePanel queue={proofs.data} />
      ) : proofs.status === 'error' && proofs.error ? (
        <ErrorCard title="Proof queue" error={proofs.error} />
      ) : (
        <LoadingCard title="Proof queue" />
      )}

      {peers.status === 'ready' && peers.data ? (
        <PeerListCard peers={peers.data} />
      ) : peers.status === 'error' && peers.error ? (
        <ErrorCard title="Peers" error={peers.error} />
      ) : (
        <LoadingCard title="Peers" />
      )}

      {telemetry.status === 'ready' && telemetry.data ? (
        <TelemetryPanel telemetry={telemetry.data} />
      ) : telemetry.status === 'error' && telemetry.error ? (
        <ErrorCard title="Telemetry" error={telemetry.error} />
      ) : (
        <LoadingCard title="Telemetry" />
      )}
    </main>
  );
}
