package ffi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SnapshotErrorKind enumerates the snapshot RPC error codes.
type SnapshotErrorKind string

const (
	SnapshotPlanInvalid            SnapshotErrorKind = "state_sync_plan_invalid"
	SnapshotMetadataMismatch       SnapshotErrorKind = "state_sync_metadata_mismatch"
	SnapshotProofEncodingInvalid   SnapshotErrorKind = "state_sync_proof_encoding_invalid"
	SnapshotVerificationIncomplete SnapshotErrorKind = "state_sync_verification_incomplete"
	SnapshotVerifierIO             SnapshotErrorKind = "state_sync_verifier_io"
	SnapshotPipelineError          SnapshotErrorKind = "state_sync_pipeline_error"
	SnapshotPrunerStateError       SnapshotErrorKind = "state_sync_pruner_state_error"
	SnapshotTransport              SnapshotErrorKind = "transport"
	SnapshotUnknown                SnapshotErrorKind = "unknown"
)

// SnapshotError wraps RPC failures with typed context.
type SnapshotError struct {
	Status     int
	Message    string
	Kind       SnapshotErrorKind
	RetryAfter time.Duration
}

func (e *SnapshotError) Error() string {
	return strings.TrimSpace(e.Message)
}

func parseRetryDelay(resp *http.Response, minBackoff time.Duration) time.Duration {
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		if secs, err := strconv.Atoi(reset); err == nil && secs >= 0 {
			if d := time.Duration(secs) * time.Second; d > 0 {
				return d
			}
		}
	}
	if after := resp.Header.Get("Retry-After"); after != "" {
		if secs, err := strconv.Atoi(after); err == nil && secs >= 0 {
			d := time.Duration(secs) * time.Second
			if d > 0 {
				return d
			}
		}
	}
	return minBackoff
}

// ClassifySnapshotResponse turns an HTTP response into a typed error when the
// server reports a snapshot failure. Successful responses pass through.
func ClassifySnapshotResponse(resp *http.Response, minBackoff time.Duration) error {
	if resp.StatusCode < 400 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var envelope struct {
		Error string  `json:"error"`
		Code  *string `json:"code"`
	}
	_ = json.Unmarshal(body, &envelope)

	kind := SnapshotUnknown
	if envelope.Code != nil {
		switch *envelope.Code {
		case string(SnapshotPlanInvalid):
			kind = SnapshotPlanInvalid
		case string(SnapshotMetadataMismatch):
			kind = SnapshotMetadataMismatch
		case string(SnapshotProofEncodingInvalid):
			kind = SnapshotProofEncodingInvalid
		case string(SnapshotVerificationIncomplete):
			kind = SnapshotVerificationIncomplete
		case string(SnapshotVerifierIO):
			kind = SnapshotVerifierIO
		case string(SnapshotPipelineError):
			kind = SnapshotPipelineError
		case string(SnapshotPrunerStateError):
			kind = SnapshotPrunerStateError
		default:
			kind = SnapshotUnknown
		}
	}

	return &SnapshotError{
		Status:     resp.StatusCode,
		Message:    envelope.Error,
		Kind:       kind,
		RetryAfter: parseRetryDelay(resp, minBackoff),
	}
}

// SnapshotGET executes an HTTP GET and maps snapshot RPC errors to typed failures.
func SnapshotGET(client *http.Client, url string, minBackoff time.Duration) error {
	resp, err := client.Get(url)
	if err != nil {
		return &SnapshotError{
			Status:     http.StatusServiceUnavailable,
			Message:    err.Error(),
			Kind:       SnapshotTransport,
			RetryAfter: minBackoff,
		}
	}
	defer resp.Body.Close()

	if err := ClassifySnapshotResponse(resp, minBackoff); err != nil {
		return err
	}
	return nil
}

// IsRetryable returns whether the error represents a transient snapshot condition.
func (e *SnapshotError) IsRetryable() bool {
	switch e.Kind {
	case SnapshotProofEncodingInvalid, SnapshotVerificationIncomplete, SnapshotVerifierIO, SnapshotPipelineError:
		return true
	default:
		return false
	}
}

// Ensure SnapshotError matches the standard error interface.
var _ error = (*SnapshotError)(nil)

var (
	ErrMissingClient = errors.New("http client is nil")
)

// SnapshotRequest validates the client and performs a GET.
func SnapshotRequest(client *http.Client, url string, minBackoff time.Duration) error {
	if client == nil {
		return ErrMissingClient
	}
	return SnapshotGET(client, url, minBackoff)
}
