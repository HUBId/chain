use std::fmt;

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Command, Element, Length};

use crate::rpc::client::WalletRpcClient;
use crate::rpc::dto::{
    ListTransactionsPageResponse, ListTransactionsParams, TransactionConfirmationDto,
    TransactionDirectionDto, TransactionHistoryEntryDto, TransactionHistoryStatusDto,
};
use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::error_banner::{self, ErrorBannerState};
use crate::ui::components::progress_bar::{self, ProgressBarState};

const DEFAULT_PAGE_SIZE: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionFilter {
    All,
    Incoming,
    Outgoing,
}

impl DirectionFilter {
    const OPTIONS: [DirectionFilter; 3] = [
        DirectionFilter::All,
        DirectionFilter::Incoming,
        DirectionFilter::Outgoing,
    ];

    fn to_param(self) -> Option<TransactionDirectionDto> {
        match self {
            DirectionFilter::All => None,
            DirectionFilter::Incoming => Some(TransactionDirectionDto::Incoming),
            DirectionFilter::Outgoing => Some(TransactionDirectionDto::Outgoing),
        }
    }

    fn label(self) -> &'static str {
        match self {
            DirectionFilter::All => "All",
            DirectionFilter::Incoming => "Incoming",
            DirectionFilter::Outgoing => "Outgoing",
        }
    }
}

impl fmt::Display for DirectionFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationFilter {
    All,
    Pending,
    Confirmed,
    Pruned,
}

impl ConfirmationFilter {
    const OPTIONS: [ConfirmationFilter; 4] = [
        ConfirmationFilter::All,
        ConfirmationFilter::Pending,
        ConfirmationFilter::Confirmed,
        ConfirmationFilter::Pruned,
    ];

    fn to_param(self) -> Option<TransactionConfirmationDto> {
        match self {
            ConfirmationFilter::All => None,
            ConfirmationFilter::Pending => Some(TransactionConfirmationDto::Pending),
            ConfirmationFilter::Confirmed => Some(TransactionConfirmationDto::Confirmed),
            ConfirmationFilter::Pruned => Some(TransactionConfirmationDto::Pruned),
        }
    }

    fn label(self) -> &'static str {
        match self {
            ConfirmationFilter::All => "All",
            ConfirmationFilter::Pending => "Pending",
            ConfirmationFilter::Confirmed => "Confirmed",
            ConfirmationFilter::Pruned => "Pruned",
        }
    }
}

impl fmt::Display for ConfirmationFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Filters {
    direction: DirectionFilter,
    confirmation: ConfirmationFilter,
    start_input: String,
    end_input: String,
    start_timestamp: Option<u64>,
    end_timestamp: Option<u64>,
    search_input: String,
}

impl Default for Filters {
    fn default() -> Self {
        Self {
            direction: DirectionFilter::All,
            confirmation: ConfirmationFilter::All,
            start_input: String::new(),
            end_input: String::new(),
            start_timestamp: None,
            end_timestamp: None,
            search_input: String::new(),
        }
    }
}

impl Filters {
    fn set_start(&mut self, value: String) {
        self.start_timestamp = parse_timestamp(&value);
        self.start_input = value;
    }

    fn set_end(&mut self, value: String) {
        self.end_timestamp = parse_timestamp(&value);
        self.end_input = value;
    }

    fn search_param(&self) -> Option<String> {
        let trimmed = self.search_input.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

#[derive(Debug, Clone)]
struct HistoryPage {
    entries: Vec<HistoryEntry>,
    page: u32,
    page_size: u32,
    total: u64,
}

impl From<ListTransactionsPageResponse> for HistoryPage {
    fn from(value: ListTransactionsPageResponse) -> Self {
        let entries = value.entries.into_iter().map(HistoryEntry::from).collect();
        Self {
            entries,
            page: value.page,
            page_size: value.page_size,
            total: value.total,
        }
    }
}

#[derive(Debug, Clone)]
struct HistoryEntry {
    txid: String,
    timestamp_ms: u64,
    height: Option<u64>,
    confirmations: Option<u32>,
    fee: Option<u128>,
    direction: HistoryDirection,
    status: HistoryStatus,
    inputs: Vec<HistoryIo>,
    outputs: Vec<HistoryIo>,
}

impl From<TransactionHistoryEntryDto> for HistoryEntry {
    fn from(value: TransactionHistoryEntryDto) -> Self {
        let inputs = value
            .inputs
            .into_iter()
            .map(|party| HistoryIo {
                address: party.address,
                value: party.value,
            })
            .collect();
        let outputs = value
            .outputs
            .into_iter()
            .map(|party| HistoryIo {
                address: party.address,
                value: party.value,
            })
            .collect();
        Self {
            txid: value.txid,
            timestamp_ms: value.timestamp_ms,
            height: value.height,
            confirmations: value.confirmations,
            fee: value.fee,
            direction: HistoryDirection::from(value.direction),
            status: HistoryStatus::from(value.status),
            inputs,
            outputs,
        }
    }
}

impl HistoryEntry {
    fn confirmation_label(&self) -> String {
        match self.confirmations {
            Some(value) => value.to_string(),
            None => "—".to_string(),
        }
    }

    fn fee_label(&self) -> String {
        match self.fee {
            Some(value) => format_amount(value),
            None => "—".to_string(),
        }
    }

    fn timestamp_label(&self) -> String {
        format_timestamp(self.timestamp_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryDirection {
    Incoming,
    Outgoing,
}

impl HistoryDirection {
    fn label(self) -> &'static str {
        match self {
            HistoryDirection::Incoming => "Incoming",
            HistoryDirection::Outgoing => "Outgoing",
        }
    }
}

impl From<TransactionDirectionDto> for HistoryDirection {
    fn from(value: TransactionDirectionDto) -> Self {
        match value {
            TransactionDirectionDto::Incoming => HistoryDirection::Incoming,
            TransactionDirectionDto::Outgoing => HistoryDirection::Outgoing,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryStatus {
    Pending,
    Confirmed,
    Pruned,
}

impl HistoryStatus {
    fn label(self) -> &'static str {
        match self {
            HistoryStatus::Pending => "Pending",
            HistoryStatus::Confirmed => "Confirmed",
            HistoryStatus::Pruned => "Pruned",
        }
    }
}

impl From<TransactionHistoryStatusDto> for HistoryStatus {
    fn from(value: TransactionHistoryStatusDto) -> Self {
        match value {
            TransactionHistoryStatusDto::Pending => HistoryStatus::Pending,
            TransactionHistoryStatusDto::Confirmed => HistoryStatus::Confirmed,
            TransactionHistoryStatusDto::Pruned => HistoryStatus::Pruned,
        }
    }
}

#[derive(Debug, Clone)]
struct HistoryIo {
    address: String,
    value: u128,
}

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

    fn set_error(&mut self, message: String) {
        *self = Snapshot::Error(message);
    }

    fn should_refresh(&self) -> bool {
        matches!(self, Snapshot::Idle | Snapshot::Error(_))
    }

    fn as_loaded(&self) -> Option<&T> {
        match self {
            Snapshot::Loaded(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct State {
    filters: Filters,
    entries: Snapshot<Vec<HistoryEntry>>,
    page: u32,
    page_size: u32,
    default_page_size: u32,
    total: Option<u64>,
    selected: Option<String>,
    last_request: Option<ListTransactionsParams>,
    error_banner: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            filters: Filters::default(),
            entries: Snapshot::default(),
            page: 0,
            page_size: DEFAULT_PAGE_SIZE,
            default_page_size: DEFAULT_PAGE_SIZE,
            total: None,
            selected: None,
            last_request: None,
            error_banner: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Refresh,
    TransactionsLoaded(Result<HistoryPage, RpcCallError>),
    DirectionChanged(DirectionFilter),
    ConfirmationChanged(ConfirmationFilter),
    StartDateChanged(String),
    EndDateChanged(String),
    SearchChanged(String),
    ApplyFilters,
    ResetFilters,
    PreviousPage,
    NextPage,
    ToggleDetails(String),
    CloseDetails,
    DismissError,
}

impl State {
    pub fn reset(&mut self) {
        self.filters = Filters::default();
        self.entries = Snapshot::Idle;
        self.page = 0;
        self.page_size = self.default_page_size;
        self.total = None;
        self.selected = None;
        self.last_request = None;
        self.error_banner = None;
    }

    pub fn set_default_page_size(&mut self, page_size: u32) {
        let clamped = page_size.max(1);
        self.default_page_size = clamped;
        self.page_size = clamped;
    }

    pub fn activate(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.entries.should_refresh() {
            self.page = 0;
            self.load_page(client)
        } else {
            Command::none()
        }
    }

    pub fn update(&mut self, client: WalletRpcClient, message: Message) -> Command<Message> {
        match message {
            Message::Refresh => self.load_page(client),
            Message::TransactionsLoaded(result) => {
                match result {
                    Ok(page) => {
                        let HistoryPage {
                            entries,
                            page,
                            page_size,
                            total,
                        } = page;
                        self.entries.set_loaded(entries);
                        self.page = page;
                        self.page_size = page_size;
                        self.total = Some(total);
                        if let Some(selected) = &self.selected {
                            if !self
                                .entries
                                .as_loaded()
                                .map(|entries| entries.iter().any(|entry| &entry.txid == selected))
                                .unwrap_or(false)
                            {
                                self.selected = None;
                            }
                        }
                        self.error_banner = None;
                    }
                    Err(error) => {
                        let message = format_rpc_error(&error);
                        self.entries.set_error(message.clone());
                        self.error_banner = Some(message);
                    }
                }
                Command::none()
            }
            Message::DirectionChanged(direction) => {
                if self.filters.direction != direction {
                    self.filters.direction = direction;
                    self.page = 0;
                    self.selected = None;
                    return self.load_page(client);
                }
                Command::none()
            }
            Message::ConfirmationChanged(confirmation) => {
                if self.filters.confirmation != confirmation {
                    self.filters.confirmation = confirmation;
                    self.page = 0;
                    self.selected = None;
                    return self.load_page(client);
                }
                Command::none()
            }
            Message::StartDateChanged(value) => {
                self.filters.set_start(value);
                Command::none()
            }
            Message::EndDateChanged(value) => {
                self.filters.set_end(value);
                Command::none()
            }
            Message::SearchChanged(value) => {
                self.filters.search_input = value;
                Command::none()
            }
            Message::ApplyFilters => {
                self.page = 0;
                self.selected = None;
                self.load_page(client)
            }
            Message::ResetFilters => {
                self.filters = Filters::default();
                self.page = 0;
                self.selected = None;
                self.load_page(client)
            }
            Message::PreviousPage => {
                if self.page > 0 {
                    self.page -= 1;
                    self.selected = None;
                    self.load_page(client)
                } else {
                    Command::none()
                }
            }
            Message::NextPage => {
                if self.has_next_page() {
                    self.page += 1;
                    self.selected = None;
                    self.load_page(client)
                } else {
                    Command::none()
                }
            }
            Message::ToggleDetails(txid) => {
                if self.selected.as_deref() == Some(txid.as_str()) {
                    self.selected = None;
                } else {
                    self.selected = Some(txid);
                }
                Command::none()
            }
            Message::CloseDetails => {
                self.selected = None;
                Command::none()
            }
            Message::DismissError => {
                self.error_banner = None;
                Command::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        let filters = self.filters_view();
        let list = self.list_content();
        let pagination = self.pagination_controls();

        let list_column = column![filters, list, pagination].spacing(16);
        let list_container = container(list_column)
            .width(Length::FillPortion(2))
            .height(Length::Fill);

        let detail_container = container(self.detail_panel())
            .width(Length::FillPortion(1))
            .height(Length::Fill)
            .style(iced::theme::Container::Box)
            .padding(16);

        let layout = row![list_container, detail_container]
            .spacing(16)
            .align_items(Alignment::Start)
            .width(Length::Fill)
            .height(Length::Fill);

        let mut column = column![]
            .spacing(16)
            .width(Length::Fill)
            .height(Length::Fill);

        if let Some(message) = &self.error_banner {
            column = column.push(error_banner::error_banner(
                ErrorBannerState {
                    message,
                    detail: None,
                },
                Message::DismissError,
            ));
        }

        column = column.push(layout);

        container(column)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    #[cfg(test)]
    fn last_request(&self) -> Option<&ListTransactionsParams> {
        self.last_request.as_ref()
    }

    #[cfg(test)]
    fn selected_txid(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    fn load_page(&mut self, client: WalletRpcClient) -> Command<Message> {
        let params = self.build_params();
        self.entries.set_loading();
        self.last_request = Some(params.clone());
        commands::rpc(
            "list_txs",
            client,
            move |client| async move { client.list_transactions_filtered(&params).await },
            map_history,
        )
    }

    fn build_params(&self) -> ListTransactionsParams {
        ListTransactionsParams {
            page: Some(self.page),
            page_size: Some(self.page_size),
            direction: self.filters.direction.to_param(),
            confirmation: self.filters.confirmation.to_param(),
            start_timestamp_ms: self.filters.start_timestamp,
            end_timestamp_ms: self.filters.end_timestamp,
            txid: self.filters.search_param(),
        }
    }

    fn has_next_page(&self) -> bool {
        match (self.total, self.page_size) {
            (Some(total), page_size) if page_size > 0 => {
                let shown = ((self.page + 1) as u64) * page_size as u64;
                shown < total
            }
            _ => false,
        }
    }

    fn filters_view(&self) -> Element<Message> {
        let direction = DirectionFilter::OPTIONS.iter().fold(
            row![text("Direction:").size(14)].spacing(8),
            |row, option| {
                row.push(filter_button(
                    option.label(),
                    self.filters.direction == *option,
                    Message::DirectionChanged(*option),
                ))
            },
        );

        let confirmation = ConfirmationFilter::OPTIONS.iter().fold(
            row![text("Status:").size(14)].spacing(8),
            |row, option| {
                row.push(filter_button(
                    option.label(),
                    self.filters.confirmation == *option,
                    Message::ConfirmationChanged(*option),
                ))
            },
        );

        let filters_row = row![direction, confirmation]
            .spacing(24)
            .align_items(Alignment::Center)
            .width(Length::Fill);

        let date_inputs = row![
            text_input("Start (ms)", &self.filters.start_input)
                .on_input(Message::StartDateChanged)
                .padding(8)
                .width(Length::Fixed(160.0)),
            text_input("End (ms)", &self.filters.end_input)
                .on_input(Message::EndDateChanged)
                .padding(8)
                .width(Length::Fixed(160.0)),
            text_input("Search txid", &self.filters.search_input)
                .on_input(Message::SearchChanged)
                .padding(8)
                .width(Length::Fill),
            button(text("Apply filters"))
                .on_press(Message::ApplyFilters)
                .padding(8),
            button(text("Reset"))
                .on_press(Message::ResetFilters)
                .padding(8),
            button(text("Refresh"))
                .on_press(Message::Refresh)
                .padding(8),
        ]
        .spacing(12)
        .align_items(Alignment::Center)
        .width(Length::Fill);

        column![filters_row, date_inputs]
            .spacing(12)
            .width(Length::Fill)
            .into()
    }

    fn list_content(&self) -> Element<Message> {
        match &self.entries {
            Snapshot::Idle => container(text("Transaction history has not been loaded yet."))
                .width(Length::Fill)
                .into(),
            Snapshot::Loading => container(progress_bar::progress_bar(ProgressBarState {
                progress: 0.2,
                label: Some("Loading transaction history..."),
            }))
            .width(Length::Fill)
            .into(),
            Snapshot::Loaded(entries) => {
                if entries.is_empty() {
                    container(text("No transactions matched the selected filters.").size(16))
                        .width(Length::Fill)
                        .into()
                } else {
                    let rows = entries.iter().fold(column![].spacing(12), |column, entry| {
                        column.push(self.summary_row(entry))
                    });
                    scrollable(rows).height(Length::Fill).into()
                }
            }
            Snapshot::Error(error) => {
                container(text(format!("Failed to load transaction history: {error}")).size(16))
                    .width(Length::Fill)
                    .into()
            }
        }
    }

    fn summary_row(&self, entry: &HistoryEntry) -> Element<Message> {
        let txid = if entry.txid.len() > 18 {
            format!("{}…", &entry.txid[..18])
        } else {
            entry.txid.clone()
        };

        let status = entry.status.label();
        let direction = entry.direction.label();
        let confirmations = entry.confirmation_label();
        let timestamp = entry.timestamp_label();

        let view_button = button(text(if self.selected.as_deref() == Some(&entry.txid) {
            "Hide details"
        } else {
            "View details"
        }))
        .on_press(Message::ToggleDetails(entry.txid.clone()))
        .padding(6);

        let row = row![
            container(text(txid).size(16))
                .width(Length::FillPortion(3))
                .align_x(Alignment::Start),
            container(text(direction).size(14))
                .width(Length::FillPortion(2))
                .align_x(Alignment::Start),
            container(text(status).size(14))
                .width(Length::FillPortion(2))
                .align_x(Alignment::Start),
            container(text(format!("Conf: {confirmations}")).size(14))
                .width(Length::FillPortion(2))
                .align_x(Alignment::Start),
            container(text(timestamp).size(14))
                .width(Length::FillPortion(3))
                .align_x(Alignment::Start),
            view_button,
        ]
        .spacing(12)
        .align_items(Alignment::Center);

        container(row)
            .padding(12)
            .width(Length::Fill)
            .style(if self.selected.as_deref() == Some(&entry.txid) {
                iced::theme::Container::Box
            } else {
                iced::theme::Container::Transparent
            })
            .into()
    }

    fn detail_panel(&self) -> Element<Message> {
        if let Some(entry) = self.selected_entry() {
            self.detail_view(entry)
        } else {
            column![text("Select a transaction to view details.").size(16)]
                .spacing(8)
                .width(Length::Fill)
                .into()
        }
    }

    fn detail_view(&self, entry: &HistoryEntry) -> Element<Message> {
        let header = column![text("Transaction").size(20), text(&entry.txid).size(16),].spacing(4);

        let summary = column![
            text(format!("Status: {}", entry.status.label())).size(14),
            text(format!("Direction: {}", entry.direction.label())).size(14),
            text(format!("Confirmations: {}", entry.confirmation_label())).size(14),
            text(format!("Timestamp: {}", entry.timestamp_label())).size(14),
            text(format!(
                "Height: {}",
                entry.height.map_or("—".to_string(), |h| h.to_string())
            ))
            .size(14),
            text(format!("Fee: {}", entry.fee_label())).size(14),
        ]
        .spacing(6);

        let inputs = io_list("Inputs", &entry.inputs);
        let outputs = io_list("Outputs", &entry.outputs);

        let close = button(text("Close"))
            .on_press(Message::CloseDetails)
            .padding(8);

        column![
            header,
            summary,
            scrollable(column![inputs, outputs].spacing(12)).height(Length::FillPortion(1)),
            row![Space::with_width(Length::Fill), close]
                .align_items(Alignment::Center)
                .spacing(8),
        ]
        .spacing(16)
        .width(Length::Fill)
        .into()
    }

    fn pagination_controls(&self) -> Element<Message> {
        let prev_button = if self.page == 0 {
            button(text("Previous")).padding(8)
        } else {
            button(text("Previous"))
                .on_press(Message::PreviousPage)
                .padding(8)
        };

        let next_button = if self.has_next_page() {
            button(text("Next")).on_press(Message::NextPage).padding(8)
        } else {
            button(text("Next")).padding(8)
        };

        let page_info = match (self.total, self.page_size) {
            (Some(total), page_size) if page_size > 0 => {
                let total_pages = (total + page_size as u64 - 1) / page_size as u64;
                format!("Page {} of {}", self.page + 1, total_pages.max(1))
            }
            _ => format!("Page {}", self.page + 1),
        };

        row![prev_button, text(page_info).size(14), next_button]
            .spacing(12)
            .align_items(Alignment::Center)
            .width(Length::Fill)
            .into()
    }

    fn selected_entry(&self) -> Option<&HistoryEntry> {
        let selected = self.selected.as_deref()?;
        self.entries
            .as_loaded()
            .and_then(|entries| entries.iter().find(|entry| entry.txid == selected))
    }
}

fn io_list(title: &str, entries: &[HistoryIo]) -> Element<Message> {
    let mut column = column![text(title).size(16)].spacing(8);
    if entries.is_empty() {
        column = column.push(text("None").size(14));
    } else {
        for entry in entries {
            column = column.push(
                row![
                    container(text(entry.address.clone()).size(14))
                        .width(Length::FillPortion(3))
                        .align_x(Alignment::Start),
                    container(text(format_amount(entry.value)).size(14))
                        .width(Length::FillPortion(1))
                        .align_x(Alignment::End),
                ]
                .spacing(8),
            );
        }
    }
    column.width(Length::Fill).into()
}

fn filter_button(label: &str, active: bool, message: Message) -> Element<Message> {
    let mut button = button(text(label)).padding(6);
    if !active {
        button = button.style(iced::theme::Button::Secondary);
    }
    button.on_press(message).into()
}

fn map_history(result: Result<ListTransactionsPageResponse, RpcCallError>) -> Message {
    Message::TransactionsLoaded(result.map(HistoryPage::from))
}

fn parse_timestamp(input: &str) -> Option<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

fn format_amount(value: u128) -> String {
    format!("{value}")
}

fn format_timestamp(ms: u64) -> String {
    let seconds = ms / 1000;
    format!("{seconds}s")
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
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, None, Duration::from_secs(1))
            .unwrap()
    }

    fn sample_entry(txid: &str) -> HistoryEntry {
        let dto = TransactionHistoryEntryDto {
            txid: txid.to_string(),
            timestamp_ms: 1_700_000_000_000,
            height: Some(10),
            confirmations: Some(2),
            fee: Some(100),
            direction: TransactionDirectionDto::Incoming,
            status: TransactionHistoryStatusDto::Confirmed,
            inputs: vec![],
            outputs: vec![],
        };
        HistoryEntry::from(dto)
    }

    #[test]
    fn direction_filter_updates_request_params() {
        let mut state = State::default();
        let _ = state.update(
            dummy_client(),
            Message::DirectionChanged(DirectionFilter::Incoming),
        );
        let params = state
            .last_request()
            .expect("request parameters recorded after update");
        assert_eq!(params.direction, Some(TransactionDirectionDto::Incoming));
    }

    #[test]
    fn confirmation_filter_updates_request_params() {
        let mut state = State::default();
        let _ = state.update(
            dummy_client(),
            Message::ConfirmationChanged(ConfirmationFilter::Confirmed),
        );
        let params = state
            .last_request()
            .expect("request parameters recorded after confirmation change");
        assert_eq!(
            params.confirmation,
            Some(TransactionConfirmationDto::Confirmed)
        );
    }

    #[test]
    fn search_term_applied_on_filter_submission() {
        let mut state = State::default();
        let _ = state.update(dummy_client(), Message::SearchChanged("abc".to_string()));
        let _ = state.update(dummy_client(), Message::ApplyFilters);
        let params = state
            .last_request()
            .expect("request parameters recorded after applying filters");
        assert_eq!(params.txid.as_deref(), Some("abc"));
    }

    #[test]
    fn toggling_details_updates_selection() {
        let mut state = State::default();
        state.entries = Snapshot::Loaded(vec![sample_entry("tx1"), sample_entry("tx2")]);

        let _ = state.update(dummy_client(), Message::ToggleDetails("tx1".to_string()));
        assert_eq!(state.selected_txid(), Some("tx1"));

        let _ = state.update(dummy_client(), Message::ToggleDetails("tx2".to_string()));
        assert_eq!(state.selected_txid(), Some("tx2"));

        let _ = state.update(dummy_client(), Message::ToggleDetails("tx2".to_string()));
        assert_eq!(state.selected_txid(), None);
    }

    #[test]
    fn load_error_sets_banner_and_snapshot() {
        let mut state = State::default();
        state.entries = Snapshot::Loading;
        let error = RpcCallError::Timeout(Duration::from_secs(4));
        let _ = state.update(dummy_client(), Message::TransactionsLoaded(Err(error)));
        assert!(matches!(state.entries, Snapshot::Error(message) if message.contains("4")));
        assert!(state.error_banner.is_some());
    }
}
