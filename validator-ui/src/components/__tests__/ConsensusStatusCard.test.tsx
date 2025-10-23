import { render, screen } from '@testing-library/react';
import { ConsensusStatusCard } from '../ConsensusStatusCard';
import type { ConsensusStatus } from '../../types';

const mockStatus: ConsensusStatus = {
  height: 1024,
  block_hash: '0x1234567890abcdef1234567890abcdef12345678',
  proposer: 'rpp1validator',
  round: 7,
  total_power: '1000',
  quorum_threshold: '667',
  pre_vote_power: '900',
  pre_commit_power: '850',
  commit_power: '880',
  quorum_reached: true,
  observers: 3,
  epoch: 12,
  epoch_nonce: '0xabc',
  pending_votes: 2,
  round_latencies_ms: [100, 200],
  leader_changes: 1,
  quorum_latency_ms: 150,
  witness_events: 5,
  slashing_events: 0,
  failed_votes: 0,
};

describe('ConsensusStatusCard', () => {
  it('renders consensus metrics', () => {
    render(<ConsensusStatusCard status={mockStatus} />);

    expect(screen.getByText('Consensus')).toBeInTheDocument();
    expect(screen.getByText('Height')).toBeInTheDocument();
    expect(screen.getByText('1024')).toBeInTheDocument();
    expect(screen.getByText('Reached')).toBeInTheDocument();
  });
});
