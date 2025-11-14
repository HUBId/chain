#![cfg(all(
    feature = "runtime",
    feature = "vendor_electrs",
    feature = "vendor_electrs_test_support"
))]

use anyhow::Result;
use tokio::runtime::Runtime;

use rpp::runtime::supervisor::Supervisor;
use rpp_wallet::vendor::electrs::signals::{Signal, TestSignal};

#[test]
fn simulated_signals_toggle_exit_flag() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async {
        let supervisor = Supervisor::new();
        let signals = Signal::new(&supervisor);
        let mut receiver = signals.subscribe();
        let exit_flag = signals.exit_flag();

        signals.simulate(TestSignal::Reload);
        receiver
            .recv()
            .await
            .expect("reload notification should be delivered");
        assert!(
            exit_flag.poll().is_ok(),
            "reload notifications must not set the exit flag"
        );

        signals.simulate(TestSignal::Exit);
        receiver
            .recv()
            .await
            .expect("exit notification should be delivered");
        assert!(
            exit_flag.poll().is_err(),
            "exit notifications should flip the exit flag"
        );

        supervisor.shutdown().await;
    });
    Ok(())
}
