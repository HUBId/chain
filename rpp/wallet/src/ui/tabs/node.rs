use iced::widget::{button, column, container, row, text, text_input, Column, Rule};
use iced::{Alignment, Command, Element, Length};

use crate::config::WalletConfig;
use crate::rpc::client::WalletRpcClient;
use crate::rpc::dto::{
    BlockFeeSummaryDto, ListPendingLocksResponse, MempoolInfoResponse, PendingLockDto,
    RecentBlocksResponse, ReleasePendingLocksResponse, RescanParams, RescanResponse, SyncModeDto,
    SyncStatusResponse, TelemetryCountersResponse,
};

use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::{modal, ConfirmDialog};
use crate::ui::telemetry;

const RECENT_BLOCK_SAMPLE: u32 = 8;

#[derive(Debug, Clone, PartialEq)]
enum Snapshot<T> {
    Idle,
    Loading,
    Loaded(T),
    Error(String),
}

impl<T> Default for Snapshot<T> {
    fn default() -> Self {
        Snapshot::Idle
    }
}

impl<T> Snapshot<T> {
    fn set_loading(&mut self) {
        *self = Snapshot::Loading;
    }

    fn set_loaded(&mut self, value: T) {
        *self = Snapshot::Loaded(value);
    }

    fn set_error(&mut self, error: &RpcCallError) {
        *self = Snapshot::Error(format_rpc_error(error));
    }

    fn as_loaded(&self) -> Option<&T> {
        match self {
            Snapshot::Loaded(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
enum RescanPrompt {
    Birthday { height: u64 },
    Explicit { height: u64 },
}

impl RescanPrompt {
    fn params(&self) -> RescanParams {
        match self {
            RescanPrompt::Birthday { height } | RescanPrompt::Explicit { height } => RescanParams {
                from_height: Some(*height),
                lookback_blocks: None,
            },
        }
    }

    fn description(&self) -> String {
        match self {
            RescanPrompt::Birthday { height } => {
                format!("Start rescan from wallet birthday height {height}?")
            }
            RescanPrompt::Explicit { height } => {
                format!("Start rescan from block height {height}?")
            }
        }
    }

    fn metric_label(&self) -> &'static str {
        match self {
            RescanPrompt::Birthday { .. } => "birthday",
            RescanPrompt::Explicit { .. } => "explicit",
        }
    }
}

#[derive(Debug, Default)]
pub struct State {
    config: Option<WalletConfig>,
    sync_status: Option<SyncStatusResponse>,
    mempool_info: Snapshot<MempoolInfoResponse>,
    recent_blocks: Snapshot<Vec<BlockFeeSummaryDto>>,
    pending_locks: Snapshot<Vec<PendingLockDto>>,
    telemetry: Snapshot<TelemetryCountersResponse>,
    refresh_inflight: bool,
    refresh_pending: usize,
    rescan_inflight: bool,
    release_inflight: bool,
    pending_rescan: Option<RescanPrompt>,
    release_confirmation: bool,
    rescan_height_input: String,
    rescan_height_error: Option<String>,
    feedback: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Message {
    Refresh,
    SyncStatusUpdated(SyncStatusResponse),
    PendingLocksLoaded(Result<Vec<PendingLockDto>, RpcCallError>),
    MempoolInfoLoaded(Result<MempoolInfoResponse, RpcCallError>),
    RecentBlocksLoaded(Result<Vec<BlockFeeSummaryDto>, RpcCallError>),
    TelemetryLoaded(Result<TelemetryCountersResponse, RpcCallError>),
    RescanHeightChanged(String),
    RequestRescanFromBirthday,
    RequestRescanFromHeight,
    ConfirmRescan,
    CancelRescan,
    RescanSubmitted(Result<RescanResponse, RpcCallError>),
    ReleaseLocksRequested,
    ConfirmReleaseLocks,
    CancelReleaseLocks,
    ReleaseLocksSubmitted(Result<ReleasePendingLocksResponse, RpcCallError>),
}

impl State {
    pub fn reset(&mut self) {
        self.mempool_info = Snapshot::Idle;
        self.recent_blocks = Snapshot::Idle;
        self.pending_locks = Snapshot::Idle;
        self.telemetry = Snapshot::Idle;
        self.refresh_inflight = false;
        self.refresh_pending = 0;
        self.rescan_inflight = false;
        self.release_inflight = false;
        self.pending_rescan = None;
        self.release_confirmation = false;
        self.rescan_height_input.clear();
        self.rescan_height_error = None;
        self.feedback = None;
    }

    pub fn set_config(&mut self, config: Option<WalletConfig>) {
        self.config = config;
    }

    pub fn activate(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.refresh(client)
    }

    pub fn update(&mut self, client: WalletRpcClient, message: Message) -> Command<Message> {
        match message {
            Message::Refresh => self.refresh(client),
            Message::SyncStatusUpdated(status) => {
                self.sync_status = Some(status);
                Command::none()
            }
            Message::PendingLocksLoaded(result) => {
                match result {
                    Ok(locks) => self.pending_locks.set_loaded(locks),
                    Err(error) => self.pending_locks.set_error(&error),
                }
                self.finish_refresh();
                Command::none()
            }
            Message::MempoolInfoLoaded(result) => {
                match result {
                    Ok(info) => self.mempool_info.set_loaded(info),
                    Err(error) => self.mempool_info.set_error(&error),
                }
                self.finish_refresh();
                Command::none()
            }
            Message::RecentBlocksLoaded(result) => {
                match result {
                    Ok(blocks) => self.recent_blocks.set_loaded(blocks),
                    Err(error) => self.recent_blocks.set_error(&error),
                }
                self.finish_refresh();
                Command::none()
            }
            Message::TelemetryLoaded(result) => {
                match result {
                    Ok(counters) => self.telemetry.set_loaded(counters),
                    Err(error) => self.telemetry.set_error(&error),
                }
                self.finish_refresh();
                Command::none()
            }
            Message::RescanHeightChanged(value) => {
                self.rescan_height_input = value;
                self.rescan_height_error = None;
                Command::none()
            }
            Message::RequestRescanFromBirthday => {
                if self.rescan_blocked() {
                    return Command::none();
                }
                let Some(config) = &self.config else {
                    self.feedback = Some("Wallet configuration unavailable.".into());
                    return Command::none();
                };
                let Some(height) = config.engine.birthday_height else {
                    self.feedback = Some("Wallet birthday height is not configured.".into());
                    return Command::none();
                };
                self.pending_rescan = Some(RescanPrompt::Birthday { height });
                Command::none()
            }
            Message::RequestRescanFromHeight => {
                if self.rescan_blocked() {
                    return Command::none();
                }
                match parse_height(&self.rescan_height_input) {
                    Ok(height) => {
                        self.pending_rescan = Some(RescanPrompt::Explicit { height });
                        self.rescan_height_error = None;
                    }
                    Err(error) => {
                        self.rescan_height_error = Some(error);
                    }
                }
                Command::none()
            }
            Message::ConfirmRescan => {
                if self.rescan_inflight {
                    return Command::none();
                }
                let Some(prompt) = self.pending_rescan.take() else {
                    return Command::none();
                };
                self.rescan_inflight = true;
                self.feedback = None;
                let origin = prompt.metric_label();
                telemetry::global().record_rescan_trigger(origin);
                let params = prompt.params();
                commands::rpc(
                    "rescan",
                    client,
                    move |client| async move { client.rescan(&params).await },
                    |result| Message::RescanSubmitted(result),
                )
            }
            Message::CancelRescan => {
                self.pending_rescan = None;
                Command::none()
            }
            Message::RescanSubmitted(result) => {
                self.rescan_inflight = false;
                match result {
                    Ok(response) => {
                        self.feedback = Some(format!(
                            "Rescan scheduled from height {}.",
                            response.from_height
                        ));
                        Command::none()
                    }
                    Err(error) => {
                        self.feedback = Some(format!(
                            "Failed to schedule rescan: {}",
                            format_rpc_error(&error)
                        ));
                        Command::none()
                    }
                }
            }
            Message::ReleaseLocksRequested => {
                if self.release_inflight {
                    return Command::none();
                }
                self.release_confirmation = true;
                Command::none()
            }
            Message::ConfirmReleaseLocks => {
                if self.release_inflight {
                    return Command::none();
                }
                self.release_confirmation = false;
                self.release_inflight = true;
                self.feedback = None;
                commands::rpc(
                    "release_pending_locks",
                    client,
                    |client| async move { client.release_pending_locks().await },
                    |result| Message::ReleaseLocksSubmitted(result),
                )
            }
            Message::CancelReleaseLocks => {
                self.release_confirmation = false;
                Command::none()
            }
            Message::ReleaseLocksSubmitted(result) => {
                self.release_inflight = false;
                match result {
                    Ok(response) => {
                        let count = response.released.len();
                        self.feedback = Some(match count {
                            0 => "No pending locks were released.".into(),
                            1 => "Released 1 pending lock.".into(),
                            _ => format!("Released {count} pending locks."),
                        });
                        if self.refresh_inflight {
                            Command::none()
                        } else {
                            self.refresh(client)
                        }
                    }
                    Err(error) => {
                        self.feedback = Some(format!(
                            "Failed to release pending locks: {}",
                            format_rpc_error(&error)
                        ));
                        Command::none()
                    }
                }
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        if let Some(prompt) = &self.pending_rescan {
            let dialog = ConfirmDialog {
                title: "Schedule rescan",
                body: prompt.description(),
                confirm_label: "Confirm",
                cancel_label: "Cancel",
                on_confirm: Message::ConfirmRescan,
                on_cancel: Message::CancelRescan,
            };
            return modal(column![dialog.view()]);
        }

        if self.release_confirmation {
            let dialog = ConfirmDialog {
                title: "Release pending locks",
                body: "Release all pending locks tracked by the wallet engine?",
                confirm_label: "Release",
                cancel_label: "Cancel",
                on_confirm: Message::ConfirmReleaseLocks,
                on_cancel: Message::CancelReleaseLocks,
            };
            return modal(column![dialog.view()]);
        }

        let mut content: Column<'_, Message> = column![self.summary_view(), self.actions_view()]
            .spacing(16)
            .width(Length::Fill);

        if let Some(feedback) = &self.feedback {
            content = content.push(container(text(feedback).size(16)).width(Length::Fill));
        }

        content = content
            .push(self.pending_locks_view())
            .push(Rule::horizontal(1))
            .push(self.recent_blocks_view())
            .push(Rule::horizontal(1))
            .push(self.prover_config_view());

        container(content).width(Length::Fill).into()
    }

    fn summary_view(&self) -> Element<Message> {
        let sync_card = summary_card(
            "Sync status",
            match &self.sync_status {
                Some(status) => {
                    let mode = match status.mode.as_ref() {
                        Some(SyncModeDto::Rescan { from_height }) => {
                            format!("Rescanning from {from_height}")
                        }
                        Some(SyncModeDto::Full { start_height }) => {
                            format!("Full sync from {start_height}")
                        }
                        Some(SyncModeDto::Resume { from_height }) => {
                            format!("Resuming from {from_height}")
                        }
                        None => "Idle".into(),
                    };
                    let mut lines = vec![mode];
                    if let Some(height) = status.latest_height {
                        lines.push(format!("Latest height: {height}"));
                    }
                    if !status.pending_ranges.is_empty() {
                        lines.push(format!("Pending ranges: {}", status.pending_ranges.len()));
                    }
                    column_from(lines)
                }
                None => column![text("No sync snapshot available")],
            },
        );

        let mempool_card = summary_card(
            "Mempool",
            match &self.mempool_info {
                Snapshot::Idle | Snapshot::Loading => column![text("Loading mempool info...")],
                Snapshot::Loaded(info) => {
                    let utilization = if info.vsize_limit == 0 {
                        0.0
                    } else {
                        (info.vsize_in_use as f64 / info.vsize_limit as f64) * 100.0
                    };
                    let mut lines = vec![format!("Transactions: {}", info.tx_count)];
                    lines.push(format!("Utilization: {:.1}%", utilization));
                    if let Some(min) = info.min_fee_rate {
                        lines.push(format!("Min fee: {min} sat/vB"));
                    }
                    if let Some(max) = info.max_fee_rate {
                        lines.push(format!("Max fee: {max} sat/vB"));
                    }
                    column_from(lines)
                }
                Snapshot::Error(error) => column![text(format!("{error}"))],
            },
        );

        let telemetry_card = summary_card(
            "Telemetry",
            match &self.telemetry {
                Snapshot::Idle | Snapshot::Loading => column![text("Loading telemetry...")],
                Snapshot::Loaded(counters) => {
                    if !counters.enabled {
                        column![text("Telemetry disabled")]
                    } else if counters.counters.is_empty() {
                        column![text("No counters reported yet")]
                    } else {
                        let mut values = counters.counters.clone();
                        values.sort_by(|a, b| b.value.cmp(&a.value));
                        let lines = values
                            .into_iter()
                            .take(3)
                            .map(|counter| format!("{}: {}", counter.name, counter.value))
                            .collect::<Vec<_>>();
                        column_from(lines)
                    }
                }
                Snapshot::Error(error) => column![text(format!("{error}"))],
            },
        );

        row![sync_card, mempool_card, telemetry_card]
            .spacing(16)
            .width(Length::Fill)
            .into()
    }

    fn actions_view(&self) -> Element<Message> {
        let mut row = row![]
            .spacing(12)
            .align_items(Alignment::Center)
            .width(Length::Fill);

        let mut birthday_button = button(text("Rescan from birthday")).padding(12);
        if !self.rescan_blocked()
            && self
                .config
                .as_ref()
                .and_then(|cfg| cfg.engine.birthday_height)
                .is_some()
        {
            birthday_button = birthday_button.on_press(Message::RequestRescanFromBirthday);
        }
        row = row.push(birthday_button);

        let height_input = text_input("Height", &self.rescan_height_input)
            .on_input(Message::RescanHeightChanged)
            .on_submit(Message::RequestRescanFromHeight)
            .padding(10)
            .size(16);

        let mut height_button = button(text("Rescan from height")).padding(12);
        if !self.rescan_blocked() {
            height_button = height_button.on_press(Message::RequestRescanFromHeight);
        }

        row = row.push(height_input).push(height_button);

        if let Some(error) = &self.rescan_height_error {
            row = row.push(text(error).size(14));
        }

        let mut release_button = button(text("Release pending locks")).padding(12);
        if !self.release_inflight {
            release_button = release_button.on_press(Message::ReleaseLocksRequested);
        }

        row.push(release_button).into()
    }

    fn pending_locks_view(&self) -> Element<Message> {
        match &self.pending_locks {
            Snapshot::Idle | Snapshot::Loading => container(text("Loading pending locks..."))
                .width(Length::Fill)
                .into(),
            Snapshot::Error(error) => {
                container(text(format!("Unable to load pending locks: {error}")))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Loaded(locks) => {
                if locks.is_empty() {
                    container(text("No pending locks to display."))
                        .width(Length::Fill)
                        .into()
                } else {
                    let header = row![
                        text("Outpoint").width(Length::FillPortion(3)),
                        text("Locked at").width(Length::FillPortion(2)),
                        text("Backend").width(Length::FillPortion(2)),
                        text("Status").width(Length::FillPortion(3)),
                    ]
                    .spacing(12)
                    .align_items(Alignment::Center);

                    let rows = locks
                        .iter()
                        .fold(column![header, Rule::horizontal(1)], |column, lock| {
                            column.push(lock_row(lock))
                        });

                    container(rows.spacing(8)).width(Length::Fill).into()
                }
            }
        }
    }

    fn recent_blocks_view(&self) -> Element<Message> {
        match &self.recent_blocks {
            Snapshot::Idle | Snapshot::Loading => container(text("Loading recent blocks..."))
                .width(Length::Fill)
                .into(),
            Snapshot::Error(error) => {
                container(text(format!("Unable to load block samples: {error}")))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Loaded(blocks) => {
                if blocks.is_empty() {
                    container(text("No recent block samples available."))
                        .width(Length::Fill)
                        .into()
                } else {
                    let items = blocks.iter().map(|block| {
                        let median = block
                            .median_fee_rate
                            .map(|rate| format!("median {rate} sat/vB"))
                            .unwrap_or_else(|| "median n/a".into());
                        let max = block
                            .max_fee_rate
                            .map(|rate| format!("max {rate} sat/vB"))
                            .unwrap_or_else(|| "max n/a".into());
                        container(
                            row![
                                text(format!("Height {}", block.height))
                                    .width(Length::FillPortion(2)),
                                text(median).width(Length::FillPortion(2)),
                                text(max).width(Length::FillPortion(2)),
                            ]
                            .spacing(12)
                            .align_items(Alignment::Center),
                        )
                        .width(Length::Fill)
                    });

                    container(column(items).spacing(8))
                        .width(Length::Fill)
                        .into()
                }
            }
        }
    }

    fn prover_config_view(&self) -> Element<Message> {
        let Some(config) = &self.config else {
            return container(text("Wallet configuration unavailable."))
                .width(Length::Fill)
                .into();
        };

        let prover = &config.prover;
        let lines = [
            format!("Backend enabled: {}", format_bool(prover.enabled)),
            format!("Mock fallback: {}", format_bool(prover.mock_fallback)),
            format!("Job timeout: {}s", prover.job_timeout_secs),
            format!("Max witness bytes: {}", prover.max_witness_bytes),
            format!("Max concurrency: {}", prover.max_concurrency),
        ];

        container(column_from(lines)).width(Length::Fill).into()
    }

    fn refresh(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.refresh_inflight {
            return Command::none();
        }

        self.refresh_inflight = true;
        self.refresh_pending = 0;

        let mut commands = Vec::new();

        self.pending_locks.set_loading();
        self.refresh_pending += 1;
        commands.push(commands::rpc(
            "list_pending_locks",
            client.clone(),
            |client| async move { client.list_pending_locks().await },
            map_pending_locks,
        ));

        self.mempool_info.set_loading();
        self.refresh_pending += 1;
        commands.push(commands::rpc(
            "mempool_info",
            client.clone(),
            |client| async move { client.mempool_info().await },
            Message::MempoolInfoLoaded,
        ));

        self.recent_blocks.set_loading();
        self.refresh_pending += 1;
        commands.push(commands::rpc(
            "recent_blocks",
            client.clone(),
            move |client| async move { client.recent_blocks(RECENT_BLOCK_SAMPLE).await },
            map_recent_blocks,
        ));

        self.telemetry.set_loading();
        self.refresh_pending += 1;
        commands.push(commands::rpc(
            "telemetry_counters",
            client,
            |client| async move { client.telemetry_counters().await },
            Message::TelemetryLoaded,
        ));

        Command::batch(commands)
    }

    fn finish_refresh(&mut self) {
        if self.refresh_pending > 0 {
            self.refresh_pending -= 1;
        }
        if self.refresh_pending == 0 {
            self.refresh_inflight = false;
        }
    }

    fn rescan_blocked(&self) -> bool {
        if self.rescan_inflight || self.pending_rescan.is_some() {
            return true;
        }
        if let Some(status) = &self.sync_status {
            if status.syncing {
                if matches!(status.mode, Some(SyncModeDto::Rescan { .. }))
                    || !status.pending_ranges.is_empty()
                {
                    return true;
                }
            }
        }
        false
    }
}

fn map_pending_locks(result: Result<ListPendingLocksResponse, RpcCallError>) -> Message {
    Message::PendingLocksLoaded(result.map(|response| response.locks))
}

fn map_recent_blocks(result: Result<RecentBlocksResponse, RpcCallError>) -> Message {
    Message::RecentBlocksLoaded(result.map(|response| response.blocks))
}

fn column_from(lines: Vec<String>) -> Column<'static, Message> {
    lines
        .into_iter()
        .fold(column![], |column, line| column.push(text(line)))
}

fn lock_row(lock: &PendingLockDto) -> Element<Message> {
    let status = lock
        .spending_txid
        .as_ref()
        .map(|txid| format!("spending {txid}"))
        .unwrap_or_else(|| "available".into());
    row![
        text(format!("{}:{}", lock.utxo_txid, lock.utxo_index)).width(Length::FillPortion(3)),
        text(lock.locked_at_ms.to_string()).width(Length::FillPortion(2)),
        text(&lock.backend).width(Length::FillPortion(2)),
        text(status).width(Length::FillPortion(3)),
    ]
    .spacing(12)
    .align_items(Alignment::Center)
    .into()
}

fn summary_card(title: &str, body: Column<'_, Message>) -> Element<Message> {
    container(
        column![text(title).size(18), body.spacing(4)]
            .spacing(8)
            .align_items(Alignment::Start),
    )
    .width(Length::FillPortion(1))
    .style(iced::theme::Container::Box)
    .padding(12)
    .into()
}

fn parse_height(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a block height".into());
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| "Invalid block height".into())
}

fn format_bool(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_rpc_error(error: &RpcCallError) -> String {
    match error {
        RpcCallError::Timeout(duration) => {
            format!("Request timed out after {}s", duration.as_secs())
        }
        RpcCallError::Client(inner) => inner.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dummy_client() -> WalletRpcClient {
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, Duration::from_secs(1)).unwrap()
    }

    fn config_with_birthday(height: u64) -> WalletConfig {
        let mut config = WalletConfig::default();
        config.engine.birthday_height = Some(height);
        config
    }

    #[test]
    fn rescan_requires_confirmation() {
        let mut state = State::default();
        state.set_config(Some(config_with_birthday(10)));
        let _ = state.update(dummy_client(), Message::RequestRescanFromBirthday);
        assert!(state.pending_rescan.is_some());
        assert!(!state.rescan_inflight);
    }

    #[test]
    fn rescan_inflight_blocks_duplicates() {
        let mut state = State::default();
        state.set_config(Some(config_with_birthday(10)));
        let client = dummy_client();
        let _ = state.update(client.clone(), Message::RequestRescanFromBirthday);
        let _ = state.update(client.clone(), Message::ConfirmRescan);
        assert!(state.rescan_inflight);
        assert!(state.pending_rescan.is_none());
        let _ = state.update(client, Message::ConfirmRescan);
        assert!(state.rescan_inflight);
    }

    #[test]
    fn release_requires_confirmation_and_blocks_duplicates() {
        let mut state = State::default();
        let client = dummy_client();
        let _ = state.update(client.clone(), Message::ReleaseLocksRequested);
        assert!(state.release_confirmation);
        let _ = state.update(client.clone(), Message::ConfirmReleaseLocks);
        assert!(state.release_inflight);
        assert!(!state.release_confirmation);
        let _ = state.update(client, Message::ConfirmReleaseLocks);
        assert!(state.release_inflight);
    }

    #[test]
    fn release_success_triggers_refresh() {
        let mut state = State::default();
        state.release_inflight = true;
        let response = ReleasePendingLocksResponse { released: vec![] };
        let command = state.update(dummy_client(), Message::ReleaseLocksSubmitted(Ok(response)));
        assert!(state.refresh_inflight);
        assert!(!state.release_inflight);
        // Ensure a command was produced to drive the refresh RPCs.
        let _ = command;
    }

    #[test]
    fn syncing_status_blocks_new_rescan_requests() {
        let mut state = State::default();
        state.sync_status = Some(SyncStatusResponse {
            syncing: true,
            mode: Some(SyncModeDto::Rescan { from_height: 5 }),
            latest_height: None,
            scanned_scripthashes: None,
            pending_ranges: vec![(0, 10)],
            checkpoints: None,
            last_rescan_timestamp: None,
            last_error: None,
            node_issue: None,
            hints: Vec::new(),
        });

        let command = state.update(dummy_client(), Message::RequestRescanFromHeight);
        assert!(state.pending_rescan.is_none());
        assert!(command.actions().is_empty());
    }
}
