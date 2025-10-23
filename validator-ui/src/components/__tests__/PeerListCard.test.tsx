import { render, screen } from '@testing-library/react';
import { PeerListCard } from '../PeerListCard';
import type { ValidatorPeerResponse } from '../../types';

describe('PeerListCard', () => {
  it('lists peers', () => {
    const peers: ValidatorPeerResponse = {
      local_peer_id: 'local-peer',
      peer_count: 2,
      peers: [
        { peer: 'peer-1', version: '1.0.0', latency_ms: 42, last_seen: 1_700_000_000 },
        { peer: 'peer-2', version: '1.2.0', latency_ms: 100, last_seen: 1_700_000_500 },
      ],
    };

    render(<PeerListCard peers={peers} />);

    expect(screen.getByText('Peers')).toBeInTheDocument();
    expect(screen.getByText('Local: local-peer')).toBeInTheDocument();
    expect(screen.getByText('peer-1')).toBeInTheDocument();
    expect(screen.getByText('peer-2')).toBeInTheDocument();
  });
});
