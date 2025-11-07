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
