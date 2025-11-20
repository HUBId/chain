# Helm-Beispiele für Prometheus/Grafana/OTLP

Diese Werte-Dateien zeigen, wie der `opentelemetry-collector` und der
`kube-prometheus-stack` mit rpp-Metriken verbunden werden können.

## Installation

```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm upgrade --install telemetry-collector open-telemetry/opentelemetry-collector \ 
  -f telemetry/helm/otel-collector-values.yaml

helm upgrade --install telemetry-prometheus prometheus-community/kube-prometheus-stack \ 
  -f telemetry/helm/prom-grafana-values.yaml
```

* Passe die Hostnamen in `prom-grafana-values.yaml` an den Namespace/Service-Namen
  deiner Installation an.
* Wenn `rollout.telemetry.metrics.auth_token` gesetzt ist, aktiviere den
  `authorization`-Block im Scrape-Job.
* Der Collector exponiert OTLP gRPC/HTTP auf 4317/4318 und einen Prometheus-
  Exporter auf 9464, der von Prometheus automatisch gescrapt wird.
