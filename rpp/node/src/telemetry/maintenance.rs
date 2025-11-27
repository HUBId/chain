use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Meter, UpDownCounter};
use opentelemetry::KeyValue;

use rpp_chain::config::MaintenanceWindow;

static METRICS: OnceLock<MaintenanceMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct MaintenanceMetrics {
    window_events_total: Counter<u64>,
    window_active: UpDownCounter<i64>,
}

impl MaintenanceMetrics {
    const METER_NAME: &'static str = "rpp-node.maintenance";

    fn new(meter: Meter) -> Self {
        let window_events_total = meter
            .u64_counter("rpp.node.maintenance.window_events_total")
            .with_description("Maintenance window transitions grouped by phase and scope")
            .with_unit("1")
            .build();
        let window_active = meter
            .i64_up_down_counter("rpp.node.maintenance.window_active")
            .with_description("Active maintenance windows grouped by scope")
            .with_unit("1")
            .build();

        Self {
            window_events_total,
            window_active,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_window_start(&self, window: &MaintenanceWindow) {
        for scope in window.scopes() {
            let attrs = [
                KeyValue::new("window", window.name.clone()),
                KeyValue::new("scope", scope),
                KeyValue::new("phase", "start"),
            ];
            self.window_events_total.add(1, &attrs);
            self.window_active.add(1, &attrs[..2]);
        }
    }

    pub fn record_window_end(&self, window: &MaintenanceWindow) {
        for scope in window.scopes() {
            let attrs = [
                KeyValue::new("window", window.name.clone()),
                KeyValue::new("scope", scope),
                KeyValue::new("phase", "end"),
            ];
            self.window_events_total.add(1, &attrs);
            self.window_active.add(-1, &attrs[..2]);
        }
    }
}
