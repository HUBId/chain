# Electrs-Telemetrie im Wallet-Vendor

Dieses Dokument zeigt, wie die vendorten Electrs-Module ihre Metriken über das interne
`malachite::telemetry`-Subsystem bereitstellen und wie die Ereignisse über `rpp::telemetry`
analysiert werden können.

## Feature-Flags aktivieren

Die Telemetrie ist standardmäßig abgeschaltet. Für Builds mit Metriken müssen sowohl
`vendor_electrs` als auch das neue Feature `vendor_electrs_telemetry` aktiviert werden:

```bash
cargo test -p rpp-wallet --features "vendor_electrs,vendor_electrs_telemetry"
```

## Registrierung einer Gauge und Auslesen des Snapshots

Das folgende Beispiel registriert eine Gauge, schreibt einen Wert und liest den Snapshot
sowie das zugehörige Event wieder aus.

```rust
use rpp_wallet::vendor::electrs::metrics::malachite::telemetry;
use rpp_wallet::vendor::electrs::metrics::rpp;

fn demo_gauge() {
    let registry = telemetry::registry();
    let gauge = registry.register_gauge(
        "electrs_demo_gauge",
        "Beispiel-Gauge aus dem Docs-Beispiel",
        "scope",
    );

    gauge.set("demo", 1.0);

    let snapshot = registry
        .snapshot_gauge("electrs_demo_gauge")
        .expect("Gauge-Snapshot verfügbar");
    assert_eq!(snapshot.values.get("demo"), Some(&1.0));

    let events = rpp::telemetry::drain();
    assert!(events
        .iter()
        .any(|event| event.name == "electrs_demo_gauge" && (event.value - 1.0).abs() < f64::EPSILON));
}
```

Die selben Schritte funktionieren analog für Histogramme über
`registry.register_histogram(...)`. Die Wrapper `CacheTelemetry`, `Tracker` und `Daemon`
registrieren ihre Kennzahlen automatisch, sobald Telemetrie aktiviert ist.
