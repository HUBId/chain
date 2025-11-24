export type SnapshotErrorCode =
  | "state_sync_plan_invalid"
  | "state_sync_metadata_mismatch"
  | "state_sync_proof_encoding_invalid"
  | "state_sync_verification_incomplete"
  | "state_sync_verifier_io"
  | "state_sync_pipeline_error"
  | "state_sync_pruner_state_error"
  | "transport"
  | "unknown";

export class SnapshotError extends Error {
  status: number;
  code: SnapshotErrorCode;
  retryAfter: number;

  constructor(message: string, status: number, code: SnapshotErrorCode, retryAfter: number) {
    super(message);
    this.name = "SnapshotError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }

  get retryable(): boolean {
    return (
      this.code === "state_sync_proof_encoding_invalid" ||
      this.code === "state_sync_verification_incomplete" ||
      this.code === "state_sync_verifier_io" ||
      this.code === "state_sync_pipeline_error" ||
      this.code === "transport"
    );
  }
}

function parseRetryAfter(headers: Headers, minDelayMs: number): number {
  const resetHeader = headers.get("X-RateLimit-Reset");
  if (resetHeader) {
    const asNumber = Number.parseInt(resetHeader, 10);
    if (!Number.isNaN(asNumber) && asNumber > 0) {
      return asNumber * 1000;
    }
  }

  const retryAfter = headers.get("Retry-After");
  if (retryAfter) {
    const asNumber = Number.parseInt(retryAfter, 10);
    if (!Number.isNaN(asNumber) && asNumber > 0) {
      return asNumber * 1000;
    }
  }

  return minDelayMs;
}

function mapCode(code?: string | null): SnapshotErrorCode {
  switch (code) {
    case "state_sync_plan_invalid":
    case "state_sync_metadata_mismatch":
    case "state_sync_proof_encoding_invalid":
    case "state_sync_verification_incomplete":
    case "state_sync_verifier_io":
    case "state_sync_pipeline_error":
    case "state_sync_pruner_state_error":
      return code;
    default:
      return code ? "unknown" : "unknown";
  }
}

export async function snapshotRequest(
  input: RequestInfo | URL,
  init: RequestInit = {},
  minDelayMs = 50,
): Promise<Response> {
  try {
    const response = await fetch(input, init);
    if (response.ok) {
      return response;
    }

    const retryAfter = parseRetryAfter(response.headers, minDelayMs);
    try {
      const payload = (await response.json()) as { error?: string; code?: string };
      throw new SnapshotError(payload.error ?? "snapshot RPC failed", response.status, mapCode(payload.code), retryAfter);
    } catch (err) {
      if (err instanceof SnapshotError) {
        throw err;
      }
      const text = await response.text();
      throw new SnapshotError(text || "snapshot RPC failed", response.status, "unknown", retryAfter);
    }
  } catch (err) {
    if (err instanceof SnapshotError) {
      throw err;
    }
    throw new SnapshotError((err as Error).message, 503, "transport", minDelayMs);
  }
}
