use iced::widget::{button, column, container, row, text};
use iced::{Alignment, Command, Element, Length};

use crate::rpc::client::WalletRpcClient;
use crate::rpc::dto::{
    BalanceResponse, ListTransactionsResponse, SyncStatusResponse, TransactionEntryDto,
};

use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::progress_bar::{self, ProgressBarState};
use crate::ui::routes::Route;

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

    fn should_refresh(&self) -> bool {
        matches!(self, Snapshot::Idle | Snapshot::Error(_))
    }
}

#[derive(Debug, Default)]
pub struct State {
    balance: Snapshot<BalanceResponse>,
    transactions: Snapshot<Vec<TransactionEntryDto>>,
    sync_status: Option<SyncStatusResponse>,
}

#[derive(Debug, Clone)]
pub enum Message {
    LoadBalance,
    LoadTransactions,
    BalanceLoaded(Result<BalanceResponse, RpcCallError>),
    TransactionsLoaded(Result<Vec<TransactionEntryDto>, RpcCallError>),
    SyncStatusUpdated(SyncStatusResponse),
    NavigateToHistory,
}

impl State {
    pub fn reset(&mut self) {
        self.balance = Snapshot::Idle;
        self.transactions = Snapshot::Idle;
        self.sync_status = None;
    }

    pub fn activate(&mut self, client: WalletRpcClient) -> Command<Message> {
        let mut commands = Vec::new();
        if self.balance.should_refresh() {
            commands.push(self.load_balance(client.clone()));
        }
        if self.transactions.should_refresh() {
            commands.push(self.load_transactions(client));
        }
        Command::batch(commands)
    }

    pub fn update(
        &mut self,
        client: WalletRpcClient,
        message: Message,
    ) -> (Command<Message>, Option<Route>) {
        match message {
            Message::LoadBalance => {
                let command = self.load_balance(client);
                (command, None)
            }
            Message::LoadTransactions => {
                let command = self.load_transactions(client);
                (command, None)
            }
            Message::BalanceLoaded(result) => {
                match result {
                    Ok(balance) => self.balance.set_loaded(balance),
                    Err(error) => self.balance.set_error(&error),
                }
                (Command::none(), None)
            }
            Message::TransactionsLoaded(result) => {
                match result {
                    Ok(entries) => self.transactions.set_loaded(entries),
                    Err(error) => self.transactions.set_error(&error),
                }
                (Command::none(), None)
            }
            Message::SyncStatusUpdated(status) => {
                let should_refresh = self
                    .sync_status
                    .as_ref()
                    .map(|current| {
                        current.latest_height != status.latest_height
                            || current.syncing != status.syncing
                            || current.pending_ranges != status.pending_ranges
                    })
                    .unwrap_or(true);
                self.sync_status = Some(status);
                if should_refresh {
                    let mut commands = Vec::new();
                    commands.push(self.load_balance(client.clone()));
                    commands.push(self.load_transactions(client));
                    (Command::batch(commands), None)
                } else {
                    (Command::none(), None)
                }
            }
            Message::NavigateToHistory => (Command::none(), Some(Route::Activity)),
        }
    }

    fn load_balance(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.balance.set_loading();
        commands::rpc(
            "get_balance",
            client,
            |client| async move { client.get_balance().await },
            map_balance,
        )
    }

    fn load_transactions(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.transactions.set_loading();
        commands::rpc(
            "list_txs",
            client,
            |client| async move { client.list_transactions().await },
            map_transactions,
        )
    }

    pub fn view(&self) -> Element<Message> {
        let content = column![
            self.balance_view(),
            self.sync_view(),
            self.transactions_view()
        ]
        .spacing(16)
        .width(Length::Fill);

        container(content).width(Length::Fill).into()
    }

    fn balance_view(&self) -> Element<Message> {
        match &self.balance {
            Snapshot::Idle | Snapshot::Loading => container(text("Loading balance...").size(16))
                .width(Length::Fill)
                .into(),
            Snapshot::Loaded(balance) => {
                let confirmed = amount_column("Confirmed", balance.confirmed);
                let pending = amount_column("Pending", balance.pending);
                let total = amount_column("Total", balance.total);
                container(row![confirmed, pending, total].spacing(24))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Error(error) => {
                container(text(format!("Failed to load balance: {error}")).size(16))
                    .width(Length::Fill)
                    .into()
            }
        }
    }

    fn sync_view(&self) -> Element<Message> {
        if let Some(status) = &self.sync_status {
            let progress = calculate_progress(status);
            let label = format!("{:.1}% synced", progress * 100.0);
            let mut column = column![
                progress_bar::progress_bar(ProgressBarState {
                    progress,
                    label: Some(label.as_str()),
                }),
                text(match status.latest_height {
                    Some(height) => format!("Chain height: {height}"),
                    None => "Chain height: unknown".to_string(),
                })
                .size(16),
            ]
            .spacing(8);

            if !status.pending_ranges.is_empty() {
                let ranges = status.pending_ranges.iter().map(|(start, end)| {
                    text(format!("Pending range: {} → {}", start, end)).size(14)
                });
                for range in ranges {
                    column = column.push(range);
                }
            }

            container(column).width(Length::Fill).into()
        } else {
            container(text("Sync status unavailable").size(16))
                .width(Length::Fill)
                .into()
        }
    }

    fn transactions_view(&self) -> Element<Message> {
        match &self.transactions {
            Snapshot::Idle | Snapshot::Loading => {
                container(text("Loading recent transactions...").size(16))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Loaded(entries) => {
                if entries.is_empty() {
                    return container(text("No recent transactions").size(16))
                        .width(Length::Fill)
                        .into();
                }
                let rows = entries.iter().take(5).fold(column![], |column, entry| {
                    column.push(transaction_row(entry))
                });
                let button_row = row![button(text("View history").size(16))
                    .on_press(Message::NavigateToHistory)
                    .padding(8)]
                .align_items(Alignment::Center);
                container(column![rows.spacing(12), button_row].spacing(16))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Error(error) => {
                container(text(format!("Failed to load transactions: {error}")).size(16))
                    .width(Length::Fill)
                    .into()
            }
        }
    }
}

fn map_balance(result: Result<BalanceResponse, RpcCallError>) -> Message {
    Message::BalanceLoaded(result)
}

fn map_transactions(result: Result<ListTransactionsResponse, RpcCallError>) -> Message {
    Message::TransactionsLoaded(result.map(|response| response.entries))
}

fn amount_column<'a>(label: &'a str, value: u128) -> Element<'a, Message> {
    column![text(label).size(14), text(format_amount(value)).size(22)]
        .spacing(4)
        .into()
}

fn format_amount(value: u128) -> String {
    format!("{value}")
}

fn transaction_row(entry: &TransactionEntryDto) -> Element<Message> {
    let txid = if entry.txid.len() > 12 {
        format!("{}…", &entry.txid[..12])
    } else {
        entry.txid.clone()
    };

    let row = row![
        text(txid).size(16),
        text(format!("Height: {}", entry.height)).size(14),
        text(format!("Timestamp: {}", entry.timestamp_ms)).size(14),
    ]
    .spacing(12)
    .align_items(Alignment::Center);

    container(row).width(Length::Fill).into()
}

fn calculate_progress(status: &SyncStatusResponse) -> f32 {
    if !status.syncing {
        return 1.0;
    }
    if status.pending_ranges.is_empty() {
        return 1.0;
    }
    let latest_height = status
        .latest_height
        .or_else(|| status.pending_ranges.iter().map(|(_, end)| *end).max())
        .unwrap_or(0);
    let min_start = status
        .pending_ranges
        .iter()
        .map(|(start, _)| *start)
        .min()
        .unwrap_or(0);
    let pending_total: u64 = status
        .pending_ranges
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum();
    let span = latest_height.saturating_sub(min_start).max(1);
    let progress = 1.0 - (pending_total as f32 / span as f32);
    progress.clamp(0.0, 1.0)
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

    fn sample_sync_status() -> SyncStatusResponse {
        SyncStatusResponse {
            syncing: true,
            mode: None,
            latest_height: Some(100),
            scanned_scripthashes: None,
            pending_ranges: vec![(50, 100)],
            checkpoints: None,
            last_rescan_timestamp: None,
            last_error: None,
            node_issue: None,
            hints: Vec::new(),
        }
    }

    #[test]
    fn applies_balance_snapshot() {
        let mut state = State::default();
        let balance = BalanceResponse {
            confirmed: 10,
            pending: 2,
            total: 12,
        };
        let _ = state.update(dummy_client(), Message::BalanceLoaded(Ok(balance.clone())));
        match &state.balance {
            Snapshot::Loaded(value) => {
                assert_eq!(value.confirmed, balance.confirmed);
                assert_eq!(value.pending, balance.pending);
                assert_eq!(value.total, balance.total);
            }
            other => panic!("unexpected snapshot: {other:?}"),
        }
    }

    #[test]
    fn records_balance_error() {
        let mut state = State::default();
        let error = RpcCallError::Timeout(Duration::from_secs(3));
        let _ = state.update(dummy_client(), Message::BalanceLoaded(Err(error.clone())));
        assert!(matches!(state.balance, Snapshot::Error(ref message) if message.contains("3")));
    }

    #[test]
    fn refreshes_on_sync_update() {
        let mut state = State::default();
        let status = sample_sync_status();
        let _ = state.update(dummy_client(), Message::SyncStatusUpdated(status));
        // Ensure the state entered loading mode.
        assert!(matches!(state.balance, Snapshot::Loading));
        assert!(matches!(state.transactions, Snapshot::Loading));
    }
}
