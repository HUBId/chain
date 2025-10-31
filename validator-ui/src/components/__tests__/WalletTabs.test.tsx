import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { WalletTabs } from '../WalletTabs';

const fetchJsonMock = vi.fn();

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return {
    ...actual,
    fetchJson: (path: string, init?: RequestInit) => fetchJsonMock(path, init),
  };
});

const historyContract = {
  version: 'wallet-ui.history.v1',
  entries: [
    {
      tx_hash: '0xabc',
      status: { Confirmed: { height: 42, timestamp: 1_700_000_000 } },
      reputation_delta: 2,
      proof_envelope: null,
      double_spend: null,
      conflict: null,
      pipeline: null,
    },
  ],
  script_metadata: [
    {
      script_hash: 'script1',
      confirmed_balance: 50,
      mempool_delta: 0,
      proof_envelopes: [],
    },
  ],
  tracker: {
    scripts: [{ script_hash: 'script1', status_digest: null }],
    mempool_fingerprint: null,
  },
};

const receiveContract = {
  version: 'wallet-ui.receive.v1',
  addresses: [
    { derivation_index: 0, address: 'rpp_receive0' },
    { derivation_index: 1, address: 'rpp_receive1' },
  ],
};

const nodeContract = {
  version: 'wallet-ui.node.v1',
  metrics: {
    reputation_score: 95.5,
    tier: 'Tl4',
    uptime_hours: 128,
    latest_block_height: 1024,
    latest_block_hash: '0xhash',
    total_blocks: 2048,
    slashing_alerts: [],
    pipeline_errors: [],
  },
  consensus: {
    height: 1024,
    block_hash: '0xhash',
    proposer: 'rpp_validator',
    round: 7,
    total_power: '1000',
    quorum_threshold: '667',
    pre_vote_power: '700',
    pre_commit_power: '690',
    commit_power: '680',
    observers: 3,
    quorum_reached: true,
  },
  pipeline: { flows: [] },
};

const sendContract = {
  version: 'wallet-ui.send.v1',
  preview: {
    from: 'rpp_from',
    to: 'rpp_to',
    amount: 5,
    fee: 1,
    memo: 'demo',
    nonce: 2,
    balance_before: 100,
    balance_after: 94,
  },
};

beforeEach(() => {
  fetchJsonMock.mockImplementation((path: string) => {
    if (path === '/wallet/ui/history') {
      return Promise.resolve(historyContract);
    }
    if (path.startsWith('/wallet/ui/receive')) {
      return Promise.resolve(receiveContract);
    }
    if (path === '/wallet/ui/node') {
      return Promise.resolve(nodeContract);
    }
    if (path === '/wallet/ui/send/preview') {
      return Promise.resolve(sendContract);
    }
    throw new Error(`Unexpected path ${path}`);
  });
});

afterEach(() => {
  fetchJsonMock.mockReset();
});

describe('WalletTabs', () => {
  it('renders snapshot once data is loaded', async () => {
    const { container } = render(<WalletTabs />);

    await waitFor(() => {
      expect(screen.getByText(/Contract: wallet-ui.history.v1/i)).toBeInTheDocument();
    });

    expect(container).toMatchSnapshot();
  });

  it('allows switching to the send tab and fetching a preview', async () => {
    const user = userEvent.setup();
    render(<WalletTabs />);

    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'History' })).toHaveAttribute('aria-selected', 'true');
    });

    await user.click(screen.getByRole('tab', { name: 'Send' }));

    await user.type(screen.getByLabelText('Recipient'), 'rpp_destination');
    await user.clear(screen.getByLabelText('Amount'));
    await user.type(screen.getByLabelText('Amount'), '5');
    await user.clear(screen.getByLabelText('Fee'));
    await user.type(screen.getByLabelText('Fee'), '1');
    await user.type(screen.getByLabelText('Memo'), 'demo');

    await user.click(screen.getByRole('button', { name: 'Preview transaction' }));

    await waitFor(() => {
      expect(fetchJsonMock).toHaveBeenCalledWith(
        '/wallet/ui/send/preview',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    await waitFor(() => {
      expect(screen.getByText('Preview')).toBeInTheDocument();
      expect(screen.getByText('rpp_to')).toBeInTheDocument();
    });
  });
});
