# Alert promotion workflow

This workflow keeps staging and production alert bundles in lockstep and
proves the staging configuration with probes before any production
promotion.

## Render environment-labelled bundles

1. Generate the staging bundle with explicit environment labels:
   ```bash
   python tools/alerts/render_environment_rules.py \
     --source ops/alerts \
     --output artifacts/alerts/staging \
     --environment staging
   ```
2. Repeat for production to prep the promotion payload:
   ```bash
   python tools/alerts/render_environment_rules.py \
     --source ops/alerts \
     --output artifacts/alerts/production \
     --environment production
   ```
3. Deploy the rendered `staging` bundle to the staging Prometheus/Alertmanager
   before testing dashboards or routing changes. Both bundles inherit
   environment labels even when the base rules omit them.

## Validate via probes before promoting

1. Run the CI probes locally when iterating on rules:
   ```bash
   python -m pytest tools/alerts/tests
   python tools/alerts/validate_alerts.py --artifacts artifacts/alert-probes
   ```
2. The `alert-probes` job in CI and the release pipeline re-run the same probe
   suite and publish artifacts, blocking promotion when probes fail.
3. In release builds, the staging bundle above is rendered and linted before
   promotion, ensuring the staged payload carries environment labels.

## Guard against staging/production drift

1. Compare rendered staging vs production bundles to ensure only the
   environment label differs:
   ```bash
   python tools/alerts/compare_environment_rules.py \
     --staging artifacts/alerts/staging \
     --production artifacts/alerts/production
   ```
2. The `alert-config-drift` CI job runs the same check on every PR and blocks
   merges when a file is missing or diverges across environments.
3. Keep the staging bundle deployed until the drift check is green and probe
   results are uploaded; only then promote the production bundle.
