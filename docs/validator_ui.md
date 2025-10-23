# Validator Dashboard UI

The validator dashboard is a lightweight React + Vite single-page application
located in [`validator-ui/`](../validator-ui/). It provides read-only views for
consensus status, proof queue saturation, connected peers, and runtime telemetry
exposed by the validator RPC service.

## Building locally

```bash
cd validator-ui
npm install
npm run build
```

The build output is emitted to `validator-ui/dist/` and can be hosted by any
static file server. At runtime the UI expects the following environment
variables:

- `VITE_API_BASE_URL` – Base URL for RPC requests (defaults to the current
  origin).
- `VITE_API_TOKEN` – Optional bearer token that will be attached to requests for
  secured deployments.

During development you can start the Vite dev server with `npm run dev`.

## RPC Endpoints

The dashboard consumes the following authenticated RPC endpoints:

- `GET /validator/status` → [ValidatorStatusResponse](interfaces/rpc/validator_status_response.jsonschema)
- `GET /validator/proofs` → [ValidatorProofQueueResponse](interfaces/rpc/validator_proof_queue_response.jsonschema)
- `GET /validator/peers` → [ValidatorPeerResponse](interfaces/rpc/validator_peer_response.jsonschema)
- `GET /validator/telemetry` → `NodeTelemetrySnapshot`

Refer to the JSON schema files under [`docs/interfaces/rpc/`](interfaces/rpc/)
for payload definitions and sample responses.

## Testing

The project uses [Vitest](https://vitest.dev/) together with
`@testing-library/react` to exercise the key UI components. Execute

```bash
npm test
```

to run the snapshot tests in headless mode.
