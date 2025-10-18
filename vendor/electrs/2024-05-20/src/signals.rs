use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{error, fmt};

use anyhow::Context;
use log::info;
use rpp::runtime::supervisor::Supervisor;
use tokio::sync::{broadcast, Notify};

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[derive(Debug)]
pub struct ExitError;

impl fmt::Display for ExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exiting due to signal")
    }
}

impl error::Error for ExitError {}

#[derive(Clone, Debug)]
pub struct ExitFlag {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ExitFlag {
    fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn poll(&self) -> Result<(), ExitError> {
        if self.flag.load(Ordering::Acquire) {
            Err(ExitError)
        } else {
            Ok(())
        }
    }

    pub fn is_set(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    fn set(&self) {
        if !self.flag.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        if self.is_set() {
            return;
        }
        self.notify.notified().await;
    }
}

#[derive(Debug)]
pub struct Signal {
    tx: broadcast::Sender<()>,
    exit: ExitFlag,
}

impl Signal {
    pub fn new(supervisor: &Supervisor) -> Self {
        let (tx, _) = broadcast::channel(16);
        let exit = ExitFlag::new();
        let signal = Self {
            tx: tx.clone(),
            exit: exit.clone(),
        };

        #[cfg(unix)]
        Self::spawn_unix_listener(supervisor, exit, tx);

        #[cfg(windows)]
        Self::spawn_windows_listener(supervisor, exit, tx);

        signal
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    pub fn exit_flag(&self) -> ExitFlag {
        self.exit.clone()
    }

    fn notify_reload(tx: &broadcast::Sender<()>) {
        let _ = tx.send(());
    }

    fn notify_exit(exit: &ExitFlag, tx: &broadcast::Sender<()>) {
        exit.set();
        let _ = tx.send(());
    }

    #[cfg(unix)]
    fn spawn_unix_listener(supervisor: &Supervisor, exit: ExitFlag, tx: broadcast::Sender<()>) {
        let supervisor = supervisor.clone();
        supervisor.spawn("electrs-signals", async move {
            let mut sigint = signal(SignalKind::interrupt()).context("register SIGINT handler")?;
            let mut sigterm = signal(SignalKind::terminate()).context("register SIGTERM handler")?;
            let mut sigusr1 = signal(SignalKind::user_defined1()).context("register SIGUSR1 handler")?;
            loop {
                tokio::select! {
                    _ = exit.cancelled() => {
                        break;
                    }
                    result = sigusr1.recv() => {
                        if result.is_none() {
                            break;
                        }
                        info!("notified via SIGUSR1");
                        Self::notify_reload(&tx);
                    }
                    result = sigint.recv() => {
                        if result.is_none() {
                            break;
                        }
                        info!("notified via SIGINT");
                        Self::notify_exit(&exit, &tx);
                        break;
                    }
                    result = sigterm.recv() => {
                        if result.is_none() {
                            break;
                        }
                        info!("notified via SIGTERM");
                        Self::notify_exit(&exit, &tx);
                        break;
                    }
                }
            }
            Ok(())
        });
    }

    #[cfg(windows)]
    fn spawn_windows_listener(supervisor: &Supervisor, exit: ExitFlag, tx: broadcast::Sender<()>) {
        let supervisor = supervisor.clone();
        supervisor.spawn("electrs-signals", async move {
            loop {
                tokio::select! {
                    _ = exit.cancelled() => {
                        break;
                    }
                    result = tokio::signal::ctrl_c() => {
                        result.context("await Ctrl-C signal")?;
                        info!("notified via Ctrl-C");
                        Self::notify_exit(&exit, &tx);
                        break;
                    }
                }
            }
            Ok(())
        });
    }

    #[cfg(any(test, feature = "vendor_electrs_test_support"))]
    pub fn simulate(&self, signal: TestSignal) {
        match signal {
            TestSignal::Exit => Self::notify_exit(&self.exit, &self.tx),
            TestSignal::Reload => Self::notify_reload(&self.tx),
        }
    }
}

#[cfg(any(test, feature = "vendor_electrs_test_support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestSignal {
    Exit,
    Reload,
}
