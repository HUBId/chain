# Alert manifest linting

The PrometheusRule manifests in this directory are validated in CI with the
[Spectral CLI](https://github.com/stoplightio/spectral). To run the same lints
locally:

```sh
npm install --global @stoplight/spectral-cli@6
spectral lint docs/observability/alerts/*.yaml \
  -r docs/observability/alerts/.spectral.yaml
```

The configuration in [`.spectral.yaml`](.spectral.yaml) enforces the required
metadata and alert rule fields. The command exits with a non-zero status when it
encounters YAML syntax errors or missing required keys, matching the CI gate.

For chaos-drill regressions caught by CI (for example, failures in
`telemetry_otlp_exporter_failures_surface_alerts`), follow the response steps in
the [observability chaos guide](../observability.md#ci-failure-response-for-chaos-drills)
to page the right responders and inspect the uploaded artifacts.
