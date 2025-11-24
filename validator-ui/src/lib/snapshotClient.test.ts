import { afterEach, describe, expect, it, vi } from "vitest";
import { SnapshotError, snapshotRequest } from "./snapshotClient";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("snapshotRequest", () => {
  it("maps snapshot codes into typed errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      return new Response(
        JSON.stringify({ error: "state sync verification failed", code: "state_sync_verification_incomplete" }),
        {
          status: 503,
          headers: { "X-RateLimit-Reset": "1", "Content-Type": "application/json" },
        },
      );
    }));

    await expect(snapshotRequest("https://rpc.example/state-sync", {}, 10)).rejects.toMatchObject({
      code: "state_sync_verification_incomplete",
      status: 503,
    });
  });

  it("falls back to transport errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("dial failed");
    }));

    await expect(snapshotRequest("https://rpc.example/state-sync"))
      .rejects.toBeInstanceOf(SnapshotError);
  });

  it("derives retry delay from headers", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      return new Response(JSON.stringify({ error: "throttled", code: "state_sync_pipeline_error" }), {
        status: 500,
        headers: { "Retry-After": "2", "Content-Type": "application/json" },
      });
    }));

    try {
      await snapshotRequest("https://rpc.example/state-sync", {}, 10);
      throw new Error("expected failure");
    } catch (err) {
      const snapErr = err as SnapshotError;
      expect(snapErr.retryAfter).toBeGreaterThanOrEqual(2000);
      expect(snapErr.retryable).toBe(true);
    }
  });
});
