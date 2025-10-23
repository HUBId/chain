import { render, screen } from '@testing-library/react';
import { ProofQueuePanel } from '../ProofQueuePanel';
import type { ValidatorProofQueueResponse } from '../../types';

describe('ProofQueuePanel', () => {
  it('renders pending proof summary', () => {
    const queue: ValidatorProofQueueResponse = {
      totals: { transactions: 3, identities: 1, votes: 2, uptime_proofs: 1 },
      uptime_proofs: [
        {
          identity: 'rpp1identity',
          window_start: 1_700_000_000,
          window_end: 1_700_003_600,
          credited_hours: 6,
        },
      ],
    };

    render(<ProofQueuePanel queue={queue} />);

    expect(screen.getByText('Proof Queue')).toBeInTheDocument();
    expect(screen.getByText('Transactions')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('6 h')).toBeInTheDocument();
  });

  it('renders empty state', () => {
    const queue: ValidatorProofQueueResponse = {
      totals: { transactions: 0, identities: 0, votes: 0, uptime_proofs: 0 },
      uptime_proofs: [],
    };

    render(<ProofQueuePanel queue={queue} />);

    expect(screen.getByText('No pending uptime proofs.')).toBeInTheDocument();
  });
});
