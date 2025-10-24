import { PIPELINE_STAGE_ORDER } from '../types';
import type {
  PipelineDashboardSnapshot,
  PipelineErrorPayload,
  PipelineEvent,
  PipelineFlowSnapshot,
  PipelineStage,
} from '../types';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? '';
export const API_TOKEN = import.meta.env.VITE_API_TOKEN;

type RequestInitExtras = Omit<RequestInit, 'headers'> & {
  headers?: HeadersInit;
};

export function buildApiUrl(
  path: string,
  params?: Record<string, string | number | undefined | null>,
): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const base = `${API_BASE_URL}${normalizedPath}`;
  if (!params) {
    return base;
  }

  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    searchParams.append(key, String(value));
  }

  const query = searchParams.toString();
  return query ? `${base}?${query}` : base;
}

export function createAuthHeaders(): Record<string, string> {
  if (!API_TOKEN) {
    return {};
  }

  return {
    Authorization: `Bearer ${API_TOKEN}`,
  };
}

export async function fetchJson<T>(path: string, init: RequestInitExtras = {}): Promise<T> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...createAuthHeaders(),
    ...init.headers,
  };

  const response = await fetch(buildApiUrl(path), {
    ...init,
    headers,
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`Request to ${path} failed: ${response.status} ${message}`);
  }

  return response.json() as Promise<T>;
}

function coerceNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
}

function coerceString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function parseStageMap(value: unknown): Partial<Record<PipelineStage, number>> {
  if (!value || typeof value !== 'object') {
    return {};
  }

  const stages: Partial<Record<PipelineStage, number>> = {};
  for (const stage of PIPELINE_STAGE_ORDER) {
    const rawValue = (value as Record<string, unknown>)[stage];
    const parsed = coerceNumber(rawValue);
    if (parsed !== undefined) {
      stages[stage] = parsed;
    }
  }
  return stages;
}

function parsePipelineFlowSnapshot(raw: unknown): PipelineFlowSnapshot {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid pipeline flow snapshot payload');
  }

  const hash = coerceString((raw as Record<string, unknown>).hash);
  const origin = coerceString((raw as Record<string, unknown>).origin);
  const nonce = coerceNumber((raw as Record<string, unknown>).target_nonce);
  const expectedBalance = (raw as Record<string, unknown>).expected_balance;
  const commitHeight = (raw as Record<string, unknown>).commit_height;

  if (!hash || !origin || nonce === undefined) {
    throw new Error('Incomplete pipeline flow snapshot payload');
  }

  const expectedBalanceString =
    typeof expectedBalance === 'string'
      ? expectedBalance
      : typeof expectedBalance === 'number' && Number.isFinite(expectedBalance)
        ? expectedBalance.toString()
        : '0';

  const stageMap = parseStageMap((raw as Record<string, unknown>).stages);
  const parsedCommitHeight =
    commitHeight === null || commitHeight === undefined
      ? undefined
      : coerceNumber(commitHeight);

  return {
    hash,
    origin,
    target_nonce: nonce,
    expected_balance: expectedBalanceString,
    stages: stageMap,
    commit_height: parsedCommitHeight ?? null,
  };
}

function parsePipelineDashboardSnapshot(raw: unknown): PipelineDashboardSnapshot {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid pipeline dashboard payload');
  }

  const flowsRaw = (raw as Record<string, unknown>).flows;
  if (!Array.isArray(flowsRaw)) {
    throw new Error('Pipeline dashboard payload missing flows');
  }

  return {
    flows: flowsRaw.map(parsePipelineFlowSnapshot),
  };
}

function parsePipelineErrorPayload(raw: unknown): PipelineErrorPayload {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid pipeline error payload');
  }

  const stage = coerceString((raw as Record<string, unknown>).stage);
  const reason = coerceString((raw as Record<string, unknown>).reason);
  const height = coerceNumber((raw as Record<string, unknown>).height);
  const round = coerceNumber((raw as Record<string, unknown>).round);
  const message = coerceString((raw as Record<string, unknown>).message);
  const observedAt = coerceNumber((raw as Record<string, unknown>).observed_at_ms);

  if (
    !stage ||
    !reason ||
    height === undefined ||
    round === undefined ||
    !message ||
    observedAt === undefined
  ) {
    throw new Error('Incomplete pipeline error payload');
  }

  const blockHashValue = (raw as Record<string, unknown>).block_hash;
  const blockHash =
    blockHashValue === null || blockHashValue === undefined
      ? null
      : coerceString(blockHashValue) ?? null;

  return {
    stage,
    reason,
    height,
    round,
    block_hash: blockHash,
    message,
    observed_at_ms: observedAt,
  };
}

export function parsePipelineEvent(payload: string): PipelineEvent {
  const raw = JSON.parse(payload) as unknown;
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid pipeline event payload');
  }

  const type = coerceString((raw as Record<string, unknown>).type);
  if (type === 'dashboard') {
    const snapshot = parsePipelineDashboardSnapshot(
      (raw as Record<string, unknown>).snapshot,
    );
    return { type, snapshot };
  }

  if (type === 'error') {
    const error = parsePipelineErrorPayload((raw as Record<string, unknown>).error);
    return { type, error };
  }

  throw new Error(`Unsupported pipeline event type: ${type ?? 'unknown'}`);
}
