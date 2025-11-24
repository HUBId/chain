package ffi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSnapshotErrorMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Reset", "2")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"state sync verification failed","code":"state_sync_verification_incomplete"}`))
	}))
	defer server.Close()

	err := SnapshotGET(server.Client(), server.URL, 25*time.Millisecond)
	if err == nil {
		t.Fatalf("expected error")
	}

	snapErr, ok := err.(*SnapshotError)
	if !ok {
		t.Fatalf("expected SnapshotError, got %T", err)
	}

	if snapErr.Kind != SnapshotVerificationIncomplete {
		t.Fatalf("unexpected kind: %v", snapErr.Kind)
	}
	if snapErr.RetryAfter < 2*time.Second {
		t.Fatalf("expected retry_after to respect X-RateLimit-Reset")
	}
}

func TestSnapshotTransportWrapped(t *testing.T) {
	// Use a canceled context to force a transport error without dialing.
	client := &http.Client{Timeout: 10 * time.Millisecond}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/unreachable", nil)

	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected transport error")
	}

	snapErr := &SnapshotError{
		Status:     http.StatusServiceUnavailable,
		Message:    err.Error(),
		Kind:       SnapshotTransport,
		RetryAfter: 10 * time.Millisecond,
	}

	if !snapErr.IsRetryable() {
		t.Fatalf("transport errors are retryable")
	}
}

func TestSnapshotRequestValidatesClient(t *testing.T) {
	if err := SnapshotRequest(nil, "http://localhost", time.Second); err != ErrMissingClient {
		t.Fatalf("expected ErrMissingClient, got %v", err)
	}
}
