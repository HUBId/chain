import type { ValidatorPeerResponse } from '../types';

interface PeerListCardProps {
  peers: ValidatorPeerResponse;
}

export function PeerListCard({ peers }: PeerListCardProps) {
  return (
    <section className="card" aria-label="Peer list">
      <h2>Peers</h2>
      <p className="badge">Local: {peers.local_peer_id}</p>
      <p>Total peers: {peers.peer_count}</p>
      {peers.peers.length === 0 ? (
        <p className="empty">No connected peers.</p>
      ) : (
        <ul className="list">
          {peers.peers.map((peer) => (
            <li key={peer.peer} className="stat">
              <span>{peer.peer}</span>
              <span>Version {peer.version}</span>
              <span>Latency {peer.latency_ms} ms</span>
              <span>Last seen {new Date(peer.last_seen * 1000).toLocaleString()}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
