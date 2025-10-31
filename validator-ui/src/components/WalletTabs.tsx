import { FormEvent, useMemo, useState } from 'react';
import { useApiData } from '../hooks/useApiData';
import { fetchJson } from '../lib/api';
import type {
  WalletHistoryEntry,
  WalletHistoryStatus,
  WalletNodeContract,
  WalletReceiveContract,
  WalletSendContract,
  WalletUiHistoryResponse,
} from '../types';

const RECEIVE_DEFAULT_COUNT = 10;

type ApiState<T> =
  | { status: 'loading'; data: undefined; error: undefined }
  | { status: 'error'; data: undefined; error: Error }
  | { status: 'ready'; data: T; error: undefined };

type WalletTabKey = 'history' | 'send' | 'receive' | 'node';

interface TabDefinition {
  key: WalletTabKey;
  label: string;
}

const TABS: TabDefinition[] = [
  { key: 'history', label: 'History' },
  { key: 'send', label: 'Send' },
  { key: 'receive', label: 'Receive' },
  { key: 'node', label: 'Node' },
];

function statusKind(status: WalletHistoryStatus): string {
  if ('Pending' in status) {
    return 'pending';
  }
  if ('Confirmed' in status) {
    return 'confirmed';
  }
  return 'pruned';
}

function formatStatus(status: WalletHistoryStatus): string {
  if ('Pending' in status) {
    const submitted = new Date(status.Pending.submitted_at * 1000);
    return `Pending since ${submitted.toLocaleString()}`;
  }
  if ('Confirmed' in status) {
    const timestamp = new Date(status.Confirmed.timestamp * 1000);
    return `Confirmed at height ${status.Confirmed.height} on ${timestamp.toLocaleString()}`;
  }
  return `Pruned at height ${status.Pruned.pruned_height}`;
}

function HistoryPanel({ state }: { state: ApiState<WalletUiHistoryResponse> }) {
  if (state.status === 'loading') {
    return <p className="wallet-panel-status">Loading history…</p>;
  }
  if (state.status === 'error' && state.error) {
    return (
      <div className="wallet-panel-status" role="alert">
        Failed to load history: {state.error.message}
      </div>
    );
  }
  if (state.status !== 'ready' || !state.data) {
    return null;
  }

  const { version, entries, script_metadata, tracker } = state.data;

  return (
    <div className="wallet-history">
      <p className="wallet-contract-version">Contract: {version}</p>
      {entries.length === 0 ? (
        <p className="wallet-panel-status">No transactions yet.</p>
      ) : (
        <ul className="wallet-history-list">
          {entries.map((entry: WalletHistoryEntry) => {
            const kind = statusKind(entry.status);
            const statusLabel = formatStatus(entry.status);
            return (
              <li key={entry.tx_hash} className={`wallet-history-entry wallet-history-entry--${kind}`}>
                <div className="wallet-history-header">
                  <span className="wallet-history-hash">{entry.tx_hash}</span>
                  <span className={`wallet-status badge badge-outline wallet-status-${kind}`}>{statusLabel}</span>
                </div>
                <div className="wallet-history-body">
                  <span>Reputation: {entry.reputation_delta >= 0 ? '+' : ''}{entry.reputation_delta}</span>
                  {entry.pipeline?.timed_out ? <span className="wallet-history-alert">Pipeline timed out</span> : null}
                  {entry.double_spend ? <span className="wallet-history-alert">Double spend suspected</span> : null}
                  {entry.conflict ? <span className="wallet-history-alert">Conflict: {entry.conflict}</span> : null}
                </div>
                {entry.proof_envelope ? (
                  <div className="wallet-history-proof">Proof: {entry.proof_envelope}</div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {script_metadata && script_metadata.length > 0 ? (
        <div className="wallet-history-tracker">
          <h3>Tracked scripts</h3>
          <ul className="wallet-tracker-list">
            {script_metadata.map((script) => (
              <li key={script.script_hash}>
                <span className="wallet-tracker-hash">{script.script_hash}</span>
                <span className="wallet-tracker-balance">Balance: {script.confirmed_balance}</span>
                <span className="wallet-tracker-delta">Δ mempool: {script.mempool_delta}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {tracker ? (
        <div className="wallet-history-tracker">
          <h3>Tracker snapshot</h3>
          <p className="wallet-panel-status">Scripts: {tracker.scripts.length}</p>
          {tracker.mempool_fingerprint ? (
            <p className="wallet-panel-status">Mempool fingerprint: {tracker.mempool_fingerprint}</p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

interface SendFormState {
  to: string;
  amount: string;
  fee: string;
  memo: string;
}

const INITIAL_SEND_STATE: SendFormState = {
  to: '',
  amount: '',
  fee: '',
  memo: '',
};

function SendPanel() {
  const [form, setForm] = useState<SendFormState>(INITIAL_SEND_STATE);
  const [preview, setPreview] = useState<WalletSendContract | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const total = useMemo(() => {
    if (!preview) return null;
    return preview.preview.amount + preview.preview.fee;
  }, [preview]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const amount = Number(form.amount);
    const fee = Number(form.fee);

    if (!form.to.trim()) {
      setError('Recipient address is required');
      setSubmitting(false);
      return;
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      setError('Amount must be a positive number');
      setSubmitting(false);
      return;
    }

    if (!Number.isFinite(fee) || fee < 0) {
      setError('Fee must be zero or positive');
      setSubmitting(false);
      return;
    }

    try {
      const result = await fetchJson<WalletSendContract>('/wallet/ui/send/preview', {
        method: 'POST',
        body: JSON.stringify({
          to: form.to,
          amount,
          fee,
          memo: form.memo.trim() ? form.memo : null,
        }),
      });
      setPreview(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch send preview');
      setPreview(null);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="wallet-send">
      <form className="wallet-send-form" onSubmit={handleSubmit}>
        <div className="wallet-form-group">
          <label htmlFor="wallet-send-to">Recipient</label>
          <input
            id="wallet-send-to"
            name="to"
            type="text"
            value={form.to}
            onChange={(event) => setForm((current) => ({ ...current, to: event.target.value }))}
            required
          />
        </div>
        <div className="wallet-form-row">
          <label htmlFor="wallet-send-amount">Amount</label>
          <input
            id="wallet-send-amount"
            name="amount"
            type="number"
            min="0"
            step="any"
            value={form.amount}
            onChange={(event) => setForm((current) => ({ ...current, amount: event.target.value }))}
            required
          />
          <label htmlFor="wallet-send-fee">Fee</label>
          <input
            id="wallet-send-fee"
            name="fee"
            type="number"
            min="0"
            step="any"
            value={form.fee}
            onChange={(event) => setForm((current) => ({ ...current, fee: event.target.value }))}
            required
          />
        </div>
        <div className="wallet-form-group">
          <label htmlFor="wallet-send-memo">Memo</label>
          <input
            id="wallet-send-memo"
            name="memo"
            type="text"
            value={form.memo}
            onChange={(event) => setForm((current) => ({ ...current, memo: event.target.value }))}
            placeholder="Optional memo"
          />
        </div>
        <button type="submit" className="wallet-send-button" disabled={submitting}>
          {submitting ? 'Preparing…' : 'Preview transaction'}
        </button>
      </form>
      {error ? (
        <div className="wallet-panel-status" role="alert">
          {error}
        </div>
      ) : null}
      {preview ? (
        <div className="wallet-send-preview">
          <h3>Preview</h3>
          <dl>
            <div>
              <dt>From</dt>
              <dd>{preview.preview.from}</dd>
            </div>
            <div>
              <dt>To</dt>
              <dd>{preview.preview.to}</dd>
            </div>
            <div>
              <dt>Amount</dt>
              <dd>{preview.preview.amount}</dd>
            </div>
            <div>
              <dt>Fee</dt>
              <dd>{preview.preview.fee}</dd>
            </div>
            <div>
              <dt>Memo</dt>
              <dd>{preview.preview.memo ?? '—'}</dd>
            </div>
            <div>
              <dt>Nonce</dt>
              <dd>{preview.preview.nonce}</dd>
            </div>
            <div>
              <dt>Balance before</dt>
              <dd>{preview.preview.balance_before}</dd>
            </div>
            <div>
              <dt>Balance after</dt>
              <dd>{preview.preview.balance_after}</dd>
            </div>
            {total !== null ? (
              <div>
                <dt>Total</dt>
                <dd>{total}</dd>
              </div>
            ) : null}
          </dl>
        </div>
      ) : null}
    </div>
  );
}

function ReceivePanel({ state }: { state: ApiState<WalletReceiveContract> }) {
  if (state.status === 'loading') {
    return <p className="wallet-panel-status">Loading receive addresses…</p>;
  }
  if (state.status === 'error' && state.error) {
    return (
      <div className="wallet-panel-status" role="alert">
        Failed to load receive addresses: {state.error.message}
      </div>
    );
  }
  if (state.status !== 'ready' || !state.data) {
    return null;
  }

  return (
    <div className="wallet-receive">
      <p className="wallet-contract-version">Contract: {state.data.version}</p>
      <ul className="wallet-receive-list">
        {state.data.addresses.map((address) => {
          const qrUri = `rpp:${address.address}?index=${address.derivation_index}`;
          return (
            <li key={`${address.address}-${address.derivation_index}`} className="wallet-receive-item">
              <span className="wallet-receive-address">{address.address}</span>
              <span className="wallet-receive-index">Index #{address.derivation_index}</span>
              <code className="wallet-receive-qr">{qrUri}</code>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function NodePanel({ state }: { state: ApiState<WalletNodeContract> }) {
  if (state.status === 'loading') {
    return <p className="wallet-panel-status">Loading node metrics…</p>;
  }
  if (state.status === 'error' && state.error) {
    return (
      <div className="wallet-panel-status" role="alert">
        Failed to load node metrics: {state.error.message}
      </div>
    );
  }
  if (state.status !== 'ready' || !state.data) {
    return null;
  }

  const { version, metrics, consensus, pipeline } = state.data;

  return (
    <div className="wallet-node">
      <p className="wallet-contract-version">Contract: {version}</p>
      <div className="wallet-node-metrics">
        <div>
          <span className="wallet-node-label">Tier</span>
          <span className="wallet-node-value">{metrics.tier}</span>
        </div>
        <div>
          <span className="wallet-node-label">Reputation</span>
          <span className="wallet-node-value">{metrics.reputation_score.toFixed(2)}</span>
        </div>
        <div>
          <span className="wallet-node-label">Uptime (h)</span>
          <span className="wallet-node-value">{metrics.uptime_hours}</span>
        </div>
        <div>
          <span className="wallet-node-label">Latest block</span>
          <span className="wallet-node-value">{metrics.latest_block_height}</span>
        </div>
        <div>
          <span className="wallet-node-label">Total blocks</span>
          <span className="wallet-node-value">{metrics.total_blocks}</span>
        </div>
      </div>
      {metrics.latest_block_hash ? (
        <p className="wallet-panel-status">Latest hash: {metrics.latest_block_hash}</p>
      ) : null}
      {consensus ? (
        <div className="wallet-node-consensus">
          <h3>Latest consensus receipt</h3>
          <p>
            Height {consensus.height} · Round {consensus.round} · Proposer {consensus.proposer}
          </p>
          <p>
            Power {consensus.commit_power}/{consensus.total_power} · Observers {consensus.observers}
          </p>
        </div>
      ) : null}
      {pipeline ? (
        <div className="wallet-node-pipeline">
          <h3>Pipeline flows</h3>
          <p className="wallet-panel-status">Tracked flows: {pipeline.flows.length}</p>
        </div>
      ) : null}
    </div>
  );
}

export function WalletTabs() {
  const [activeTab, setActiveTab] = useState<WalletTabKey>('history');
  const history = useApiData<WalletUiHistoryResponse>('/wallet/ui/history');
  const receive = useApiData<WalletReceiveContract>(
    `/wallet/ui/receive?count=${RECEIVE_DEFAULT_COUNT}`,
  );
  const node = useApiData<WalletNodeContract>('/wallet/ui/node');

  return (
    <section className="card wallet-card" aria-labelledby="wallet-tabs-heading">
      <div className="wallet-header">
        <h2 id="wallet-tabs-heading">Wallet</h2>
        <nav className="wallet-tablist" role="tablist" aria-label="Wallet tabs">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              id={`wallet-tab-${tab.key}`}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.key}
              aria-controls={`wallet-panel-${tab.key}`}
              className={activeTab === tab.key ? 'wallet-tab wallet-tab--active' : 'wallet-tab'}
              onClick={() => setActiveTab(tab.key)}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="wallet-panels">
        {activeTab === 'history' ? (
          <div
            id="wallet-panel-history"
            role="tabpanel"
            aria-labelledby="wallet-tab-history"
            className="wallet-panel"
          >
            <HistoryPanel state={history as ApiState<WalletUiHistoryResponse>} />
          </div>
        ) : null}

        {activeTab === 'send' ? (
          <div
            id="wallet-panel-send"
            role="tabpanel"
            aria-labelledby="wallet-tab-send"
            className="wallet-panel"
          >
            <SendPanel />
          </div>
        ) : null}

        {activeTab === 'receive' ? (
          <div
            id="wallet-panel-receive"
            role="tabpanel"
            aria-labelledby="wallet-tab-receive"
            className="wallet-panel"
          >
            <ReceivePanel state={receive as ApiState<WalletReceiveContract>} />
          </div>
        ) : null}

        {activeTab === 'node' ? (
          <div
            id="wallet-panel-node"
            role="tabpanel"
            aria-labelledby="wallet-tab-node"
            className="wallet-panel"
          >
            <NodePanel state={node as ApiState<WalletNodeContract>} />
          </div>
        ) : null}
      </div>
    </section>
  );
}
