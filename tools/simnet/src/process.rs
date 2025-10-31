use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use futures::future::try_join_all;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::config::{ProcessConfig, SimnetConfig};

const STDOUT_TAG: &str = "stdout";
const STDERR_TAG: &str = "stderr";

pub struct ProcessHandle {
    label: String,
    child: Child,
    log_path: PathBuf,
    ready: Option<oneshot::Receiver<()>>,
    stream_tasks: Vec<JoinHandle<Result<()>>>,
    log_task: JoinHandle<Result<()>>,
}

impl ProcessHandle {
    pub async fn wait_ready(&mut self, timeout_duration: Duration) -> Result<()> {
        if let Some(ready) = self.ready.take() {
            timeout(timeout_duration, ready)
                .await
                .map_err(|_| anyhow!("process {} failed to report readiness", self.label))?
                .map_err(|err| anyhow!("readiness channel closed for {}: {err}", self.label))?;
        }
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(id) = self.child.id() {
            info!(target = "simnet::process", label = %self.label, pid = id, "terminating process");
        }

        if let Err(err) = self.child.start_kill() {
            warn!(
                target = "simnet::process",
                label = %self.label,
                "failed to signal termination: {err:#}"
            );
        }

        let status = self.child.wait().await.context("await process exit")?;
        info!(
            target = "simnet::process",
            label = %self.label,
            status = ?status,
            "process exited"
        );

        let mut tasks = self.stream_tasks;
        tasks.push(self.log_task);
        if let Err(err) = try_join_all(tasks).await {
            return Err(err.context(format!("I/O task failed for {}", self.label)));
        }

        Ok(())
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

pub async fn spawn_process(
    config: &SimnetConfig,
    process: &ProcessConfig,
    artifacts_dir: &Path,
) -> Result<ProcessHandle> {
    let log_dir = artifacts_dir.join("logs");
    tokio::fs::create_dir_all(&log_dir)
        .await
        .with_context(|| format!("create log dir {}", log_dir.display()))?;
    let sanitized_label = sanitize_label(&process.label);
    let log_path = log_dir.join(format!("{}.log", sanitized_label));

    let (line_tx, line_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let ready_pattern = process.ready_log.clone();
    let log_path_clone = log_path.clone();
    let label = process.label.clone();

    let log_task =
        tokio::spawn(
            async move { write_log(log_path_clone, line_rx, ready_pattern, ready_tx).await },
        );

    let mut command = Command::new(&process.program);
    command.args(&process.args);
    command.envs(&config.env);
    command.envs(&process.env);
    if let Some(dir) = config.resolve_working_dir(&process.working_dir) {
        command.current_dir(dir);
    }
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    info!(
        target = "simnet::process",
        label = %process.label,
        program = %process.program,
        args = ?process.args,
        "spawning process"
    );

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn process {}", process.label))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("{} missing stdout pipe", process.label))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("{} missing stderr pipe", process.label))?;

    let mut stream_tasks = Vec::with_capacity(2);
    stream_tasks.push(spawn_stream_forwarder(
        stdout,
        line_tx.clone(),
        process.label.clone(),
        STDOUT_TAG,
    ));
    stream_tasks.push(spawn_stream_forwarder(
        stderr,
        line_tx,
        process.label.clone(),
        STDERR_TAG,
    ));

    Ok(ProcessHandle {
        label,
        child,
        log_path,
        ready: Some(ready_rx),
        stream_tasks,
        log_task,
    })
}

fn spawn_stream_forwarder(
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    tx: mpsc::UnboundedSender<String>,
    label: String,
    tag: &str,
) -> JoinHandle<Result<()>> {
    let tag = tag.to_string();
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream).lines();
        while let Some(line) = reader.next_line().await? {
            let formatted = format!("[{}][{}] {}", label, tag, line);
            tx.send(formatted).unwrap_or_else(|err| {
                warn!(
                    target = "simnet::process",
                    label = %label,
                    "failed to forward log line: {err}"
                );
            });
        }
        Ok(())
    })
}

async fn write_log(
    path: PathBuf,
    mut rx: mpsc::UnboundedReceiver<String>,
    ready_pattern: Option<String>,
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .await
        .with_context(|| format!("open log file {}", path.display()))?;

    let mut ready_signaled = false;
    if ready_pattern.is_none() {
        let _ = ready_tx.send(());
        ready_signaled = true;
    }

    while let Some(line) = rx.recv().await {
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        if let Some(pattern) = ready_pattern.as_ref() {
            if !ready_signaled && line.contains(pattern) {
                let _ = ready_tx.send(());
                ready_signaled = true;
            }
        }
    }

    file.flush().await?;

    if !ready_signaled {
        let _ = ready_tx.send(());
    }

    Ok(())
}

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect()
}
