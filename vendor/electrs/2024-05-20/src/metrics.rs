use anyhow::Result;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq)]
pub enum MetricEventKind {
    GaugeSet,
    HistogramObserved { bucket: Option<f64> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetricEvent {
    pub name: String,
    pub label: String,
    pub value: f64,
    pub kind: MetricEventKind,
}

#[cfg(feature = "vendor_electrs_telemetry")]
pub mod rpp {
    pub mod telemetry {
        use super::super::MetricEvent;
        use parking_lot::Mutex;
        use std::sync::OnceLock;

        fn event_log() -> &'static Mutex<Vec<MetricEvent>> {
            static LOG: OnceLock<Mutex<Vec<MetricEvent>>> = OnceLock::new();
            LOG.get_or_init(|| Mutex::new(Vec::new()))
        }

        pub fn publish(event: MetricEvent) {
            event_log().lock().push(event);
        }

        pub fn drain() -> Vec<MetricEvent> {
            event_log().lock().drain(..).collect()
        }

        pub fn len() -> usize {
            event_log().lock().len()
        }
    }
}

#[cfg(not(feature = "vendor_electrs_telemetry"))]
pub mod rpp {
    pub mod telemetry {
        use super::super::{MetricEvent, MetricEventKind};

        pub fn publish(_event: MetricEvent) {}

        pub fn drain() -> Vec<MetricEvent> {
            Vec::new()
        }

        pub fn len() -> usize {
            0
        }
    }
}

#[cfg(feature = "vendor_electrs_telemetry")]
pub mod malachite {
    pub mod telemetry {
        use super::super::{MetricEvent, MetricEventKind};
        use crate::vendor::electrs::metrics::rpp;
        use parking_lot::RwLock;
        use std::collections::HashMap;
        use std::sync::{Arc, OnceLock};
        use std::time::Duration;

        #[derive(Default)]
        pub struct Registry {
            gauges: RwLock<HashMap<String, GaugeEntry>>,
            histograms: RwLock<HashMap<String, HistogramEntry>>,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct GaugeSnapshot {
            pub description: String,
            pub label_key: String,
            pub values: HashMap<String, f64>,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct HistogramSeries {
            pub counts: Vec<u64>,
            pub sum: f64,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct HistogramSnapshot {
            pub description: String,
            pub label_key: String,
            pub buckets: Vec<f64>,
            pub values: HashMap<String, HistogramSeries>,
        }

        struct GaugeEntry {
            description: String,
            label_key: String,
            values: HashMap<String, f64>,
        }

        impl GaugeEntry {
            fn new(description: String, label_key: String) -> Self {
                Self {
                    description,
                    label_key,
                    values: HashMap::new(),
                }
            }

            fn set(&mut self, label: &str, value: f64) {
                self.values.insert(label.to_string(), value);
            }

            fn snapshot(&self) -> GaugeSnapshot {
                GaugeSnapshot {
                    description: self.description.clone(),
                    label_key: self.label_key.clone(),
                    values: self.values.clone(),
                }
            }
        }

        struct HistogramEntry {
            description: String,
            label_key: String,
            buckets: Vec<f64>,
            counts: HashMap<String, Vec<u64>>,
            sums: HashMap<String, f64>,
        }

        impl HistogramEntry {
            fn new(description: String, label_key: String, buckets: Vec<f64>) -> Self {
                Self {
                    description,
                    label_key,
                    buckets,
                    counts: HashMap::new(),
                    sums: HashMap::new(),
                }
            }

            fn observe(&mut self, label: &str, value: f64) -> Option<usize> {
                let counts = self
                    .counts
                    .entry(label.to_string())
                    .or_insert_with(|| vec![0; self.buckets.len() + 1]);
                let index = self
                    .buckets
                    .iter()
                    .position(|bucket| value <= *bucket)
                    .unwrap_or(self.buckets.len());
                counts[index] = counts[index].saturating_add(1);
                let entry = self.sums.entry(label.to_string()).or_insert(0.0);
                *entry += value;
                Some(index)
            }

            fn snapshot(&self) -> HistogramSnapshot {
                let values = self
                    .counts
                    .iter()
                    .map(|(label, counts)| {
                        let sum = self.sums.get(label).copied().unwrap_or_default();
                        (
                            label.clone(),
                            HistogramSeries {
                                counts: counts.clone(),
                                sum,
                            },
                        )
                    })
                    .collect();
                HistogramSnapshot {
                    description: self.description.clone(),
                    label_key: self.label_key.clone(),
                    buckets: self.buckets.clone(),
                    values,
                }
            }
        }

        #[derive(Clone)]
        pub struct GaugeHandle {
            registry: &'static Registry,
            name: Arc<String>,
            label_key: Arc<String>,
        }

        impl GaugeHandle {
            pub fn set(&self, label: &str, value: f64) {
                self.registry.set_gauge(&self.name, label, value);
                rpp::telemetry::publish(MetricEvent {
                    name: self.name.as_ref().clone(),
                    label: label.to_string(),
                    value,
                    kind: MetricEventKind::GaugeSet,
                });
            }
        }

        #[derive(Clone)]
        pub struct HistogramHandle {
            registry: &'static Registry,
            name: Arc<String>,
            label_key: Arc<String>,
            buckets: Arc<Vec<f64>>,
        }

        impl HistogramHandle {
            pub fn observe(&self, label: &str, value: f64) {
                let bucket_index = self.registry.observe_histogram(&self.name, label, value);
                let bucket = bucket_index
                    .and_then(|idx| self.buckets.get(idx).copied());
                rpp::telemetry::publish(MetricEvent {
                    name: self.name.as_ref().clone(),
                    label: label.to_string(),
                    value,
                    kind: MetricEventKind::HistogramObserved { bucket },
                });
            }
        }

        impl Registry {
            pub fn register_gauge(
                &'static self,
                name: &str,
                description: &str,
                label_key: &str,
            ) -> GaugeHandle {
                let mut gauges = self.gauges.write();
                gauges
                    .entry(name.to_string())
                    .or_insert_with(|| GaugeEntry::new(description.to_string(), label_key.to_string()));
                GaugeHandle {
                    registry: self,
                    name: Arc::new(name.to_string()),
                    label_key: Arc::new(label_key.to_string()),
                }
            }

            pub fn register_histogram(
                &'static self,
                name: &str,
                description: &str,
                label_key: &str,
                buckets: Vec<f64>,
            ) -> HistogramHandle {
                let mut histograms = self.histograms.write();
                histograms
                    .entry(name.to_string())
                    .or_insert_with(|| HistogramEntry::new(description.to_string(), label_key.to_string(), buckets.clone()));
                HistogramHandle {
                    registry: self,
                    name: Arc::new(name.to_string()),
                    label_key: Arc::new(label_key.to_string()),
                    buckets: Arc::new(buckets),
                }
            }

            pub fn snapshot_gauge(&self, name: &str) -> Option<GaugeSnapshot> {
                let gauges = self.gauges.read();
                gauges.get(name).map(GaugeEntry::snapshot)
            }

            pub fn snapshot_histogram(&self, name: &str) -> Option<HistogramSnapshot> {
                let histograms = self.histograms.read();
                histograms.get(name).map(HistogramEntry::snapshot)
            }

            fn set_gauge(&self, name: &str, label: &str, value: f64) {
                let mut gauges = self.gauges.write();
                if let Some(entry) = gauges.get_mut(name) {
                    entry.set(label, value);
                }
            }

            fn observe_histogram(&self, name: &str, label: &str, value: f64) -> Option<usize> {
                let mut histograms = self.histograms.write();
                let Some(entry) = histograms.get_mut(name) else {
                    return None;
                };
                entry.observe(label, value)
            }

            pub fn observe_duration(&self, name: &str, label: &str, duration: Duration) {
                let seconds = duration.as_secs_f64();
                self.observe_histogram(name, label, seconds);
            }
        }

        pub fn registry() -> &'static Registry {
            static REGISTRY: OnceLock<Registry> = OnceLock::new();
            REGISTRY.get_or_init(Registry::default)
        }
    }
}

#[cfg(not(feature = "vendor_electrs_telemetry"))]
pub mod malachite {
    pub mod telemetry {
        use std::collections::HashMap;
        use std::sync::OnceLock;

        #[derive(Default)]
        pub struct Registry;

        #[derive(Clone, Debug, PartialEq)]
        pub struct GaugeSnapshot {
            pub description: String,
            pub label_key: String,
            pub values: HashMap<String, f64>,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct HistogramSeries {
            pub counts: Vec<u64>,
            pub sum: f64,
        }

        #[derive(Clone, Debug, PartialEq)]
        pub struct HistogramSnapshot {
            pub description: String,
            pub label_key: String,
            pub buckets: Vec<f64>,
            pub values: HashMap<String, HistogramSeries>,
        }

        #[derive(Clone)]
        pub struct GaugeHandle;

        impl GaugeHandle {
            pub fn set(&self, _label: &str, _value: f64) {}
        }

        #[derive(Clone)]
        pub struct HistogramHandle;

        impl HistogramHandle {
            pub fn observe(&self, _label: &str, _value: f64) {}
        }

        pub fn registry() -> &'static Registry {
            static REGISTRY: OnceLock<Registry> = OnceLock::new();
            REGISTRY.get_or_init(Registry::default)
        }

        impl Registry {
            pub fn register_gauge(
                &'static self,
                _name: &str,
                _description: &str,
                _label_key: &str,
            ) -> GaugeHandle {
                GaugeHandle
            }

            pub fn register_histogram(
                &'static self,
                _name: &str,
                _description: &str,
                _label_key: &str,
                _buckets: Vec<f64>,
            ) -> HistogramHandle {
                HistogramHandle
            }

            pub fn snapshot_gauge(&self, _name: &str) -> Option<GaugeSnapshot> {
                None
            }

            pub fn snapshot_histogram(&self, _name: &str) -> Option<HistogramSnapshot> {
                None
            }

            pub fn observe_duration(&self, _name: &str, _label: &str, _duration: std::time::Duration) {}
        }
    }
}

#[cfg(feature = "vendor_electrs_telemetry")]
mod enabled {
    use super::malachite::telemetry;
    use anyhow::Result;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    pub struct Metrics {
        registry: &'static telemetry::Registry,
    }

    impl Metrics {
        pub fn new(_addr: SocketAddr) -> Result<Self> {
            let registry = telemetry::registry();
            Ok(Self { registry })
        }

        pub fn histogram_vec(
            &self,
            name: &str,
            description: &str,
            label: &str,
            buckets: Vec<f64>,
        ) -> Histogram {
            let full_name = format!("electrs_{}", name);
            let handle = self
                .registry
                .register_histogram(&full_name, description, label, buckets);
            Histogram {
                handle: Arc::new(handle),
            }
        }

        pub fn gauge(&self, name: &str, description: &str, label: &str) -> Gauge {
            let full_name = format!("electrs_{}", name);
            let handle = self
                .registry
                .register_gauge(&full_name, description, label);
            Gauge {
                handle: Arc::new(handle),
            }
        }
    }

    #[derive(Clone)]
    pub struct Gauge {
        handle: Arc<telemetry::GaugeHandle>,
    }

    impl Gauge {
        pub fn set(&self, label: &str, value: f64) {
            self.handle.set(label, value);
        }
    }

    #[derive(Clone)]
    pub struct Histogram {
        handle: Arc<telemetry::HistogramHandle>,
    }

    impl Histogram {
        pub fn observe(&self, label: &str, value: f64) {
            self.handle.observe(label, value);
        }

        pub fn observe_duration<F, T>(&self, label: &str, func: F) -> T
        where
            F: FnOnce() -> T,
        {
            let start = Instant::now();
            let result = func();
            let duration = start.elapsed();
            self.handle.observe(label, duration.as_secs_f64());
            result
        }
    }
}

#[cfg(not(feature = "vendor_electrs_telemetry"))]
mod disabled {
    use anyhow::Result;
    use std::net::SocketAddr;

    #[derive(Clone)]
    pub struct Metrics;

    impl Metrics {
        pub fn new(_addr: SocketAddr) -> Result<Self> {
            Ok(Self)
        }

        pub fn histogram_vec(
            &self,
            _name: &str,
            _description: &str,
            _label: &str,
            _buckets: Vec<f64>,
        ) -> Histogram {
            Histogram
        }

        pub fn gauge(&self, _name: &str, _description: &str, _label: &str) -> Gauge {
            Gauge
        }
    }

    #[derive(Clone)]
    pub struct Gauge;

    impl Gauge {
        pub fn set(&self, _label: &str, _value: f64) {}
    }

    #[derive(Clone)]
    pub struct Histogram;

    impl Histogram {
        pub fn observe(&self, _label: &str, _value: f64) {}

        pub fn observe_duration<F, T>(&self, _label: &str, func: F) -> T
        where
            F: FnOnce() -> T,
        {
            func()
        }
    }
}

#[cfg(feature = "vendor_electrs_telemetry")]
pub use enabled::{Gauge, Histogram, Metrics};
#[cfg(not(feature = "vendor_electrs_telemetry"))]
pub use disabled::{Gauge, Histogram, Metrics};

pub fn default_duration_buckets() -> Vec<f64> {
    vec![
        1e-6, 2e-6, 5e-6, 1e-5, 2e-5, 5e-5, 1e-4, 2e-4, 5e-4, 1e-3, 2e-3, 5e-3, 1e-2,
        2e-2, 5e-2, 1e-1, 2e-1, 5e-1, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0,
    ]
}

pub fn default_size_buckets() -> Vec<f64> {
    vec![
        1.0, 2.0, 5.0, 1e1, 2e1, 5e1, 1e2, 2e2, 5e2, 1e3, 2e3, 5e3, 1e4, 2e4, 5e4,
        1e5, 2e5, 5e5, 1e6, 2e6, 5e6, 1e7,
    ]
}

