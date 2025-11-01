use proptest::prelude::*;

use rpp_chain::config::QueueWeightsConfig;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

fn normalized_weights() -> impl Strategy<Value = (f64, f64)> {
    (0.0f64..=1.0f64, -5e-7f64..=5e-7f64).prop_map(|(priority, jitter)| {
        let mut fee = (1.0 - priority) + jitter;
        if fee < 0.0 {
            fee = 0.0;
        }
        if fee > 1.0 {
            fee = 1.0;
        }
        let priority = 1.0 - fee;
        (priority, fee)
    })
}

fn invalid_weights() -> impl Strategy<Value = (f64, f64)> {
    prop_oneof![
        // Sum differs from 1.0 beyond the tolerance.
        (0.0f64..=1.0f64, -0.2f64..=-0.01f64)
            .prop_map(|(priority, offset)| { (priority, (1.0 - priority) + offset) }),
        (0.0f64..=1.0f64, 0.01f64..=0.2f64)
            .prop_map(|(priority, offset)| { (priority, (1.0 - priority) + offset) }),
        // Negative priorities or fees are invalid regardless of the sum.
        (-1.0f64..=-0.001f64, 0.0f64..=1.0f64),
        (0.0f64..=1.0f64, -1.0f64..=-0.001f64),
        // Non-finite values must be rejected.
        Just((f64::NAN, 0.5f64)),
        Just((0.5f64, f64::NAN)),
    ]
}

proptest! {
    #![proptest_config(proptest_config())]
    fn normalized_weights_validate((priority, fee) in normalized_weights()) {
        let config = QueueWeightsConfig { priority, fee };
        prop_assert!(config.validate().is_ok());
        let sum = priority + fee;
        prop_assert!((sum - 1.0).abs() <= 1e-6 + f64::EPSILON);
    }
}

proptest! {
    #![proptest_config(proptest_config())]
    fn invalid_weights_rejected((priority, fee) in invalid_weights()) {
        let config = QueueWeightsConfig { priority, fee };
        prop_assert!(config.validate().is_err());
    }
}
