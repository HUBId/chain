use iced::widget::{button, column, container, row, text, Space};
use iced::{clipboard, Alignment, Command, Element, Length};

use crate::rpc::client::WalletRpcClient;
use crate::rpc::dto::DeriveAddressResponse;

use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::{copyable_text, modal, qr_view, ConfirmDialog, QrViewState};

const MAX_HISTORY_ENTRIES: usize = 50;
const HISTORY_PAGE_SIZE: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
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

    fn is_error(&self) -> bool {
        matches!(self, Snapshot::Error(_))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardTarget {
    Address,
    Descriptor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressStatus {
    Unused,
    Used,
}

impl AddressStatus {
    fn label(&self) -> &'static str {
        match self {
            AddressStatus::Unused => "Unused",
            AddressStatus::Used => "Used",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddressHistoryEntry {
    pub address: String,
    pub status: AddressStatus,
    pub first_seen_height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CurrentAddress {
    pub address: String,
    pub descriptor: String,
}

impl From<DeriveAddressResponse> for CurrentAddress {
    fn from(value: DeriveAddressResponse) -> Self {
        // Until descriptors are surfaced by the daemon, render a pseudo descriptor derived from
        // the address to provide additional context in the UI.
        let descriptor = format!("addr({})", value.address);
        Self {
            address: value.address,
            descriptor,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct PendingClipboard {
    label: String,
    value: String,
}

#[derive(Debug, Default)]
pub struct State {
    current: Snapshot<CurrentAddress>,
    history: Vec<AddressHistoryEntry>,
    clipboard_opt_in: bool,
    pending_clipboard: Option<PendingClipboard>,
    history_page: usize,
}

#[derive(Debug, Clone)]
pub enum Message {
    LoadCurrentAddress,
    CurrentAddressLoaded(Result<DeriveAddressResponse, RpcCallError>),
    RotateAddress,
    CopyToClipboard(ClipboardTarget),
    ClipboardOptInConfirmed,
    ClipboardOptInRejected,
    NextHistoryPage,
    PreviousHistoryPage,
}

impl State {
    pub fn reset(&mut self) {
        self.current = Snapshot::Idle;
        self.history.clear();
        self.clipboard_opt_in = false;
        self.pending_clipboard = None;
        self.history_page = 0;
    }

    pub fn activate(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.current.should_refresh() {
            return self.load_current_address(client);
        }
        Command::none()
    }

    pub fn set_clipboard_opt_in(&mut self, enabled: bool) {
        self.clipboard_opt_in = enabled;
        if !enabled {
            self.pending_clipboard = None;
        }
    }

    pub fn update(&mut self, client: WalletRpcClient, message: Message) -> Command<Message> {
        match message {
            Message::LoadCurrentAddress | Message::RotateAddress => {
                self.load_current_address(client)
            }
            Message::CurrentAddressLoaded(result) => {
                match result {
                    Ok(response) => {
                        let next_address = CurrentAddress::from(response);
                        if let Some(previous) = self.current.as_loaded().cloned() {
                            self.push_history(previous);
                        }
                        self.current.set_loaded(next_address);
                    }
                    Err(error) => {
                        self.current.set_error(&error);
                    }
                }
                Command::none()
            }
            Message::CopyToClipboard(target) => {
                if let Some(content) = self.clipboard_payload(target) {
                    if self.clipboard_opt_in {
                        Command::clipboard(clipboard::Action::Copy(content.value))
                    } else {
                        self.pending_clipboard = Some(content);
                        Command::none()
                    }
                } else {
                    Command::none()
                }
            }
            Message::ClipboardOptInConfirmed => {
                if let Some(pending) = self.pending_clipboard.take() {
                    self.clipboard_opt_in = true;
                    Command::clipboard(clipboard::Action::Copy(pending.value))
                } else {
                    Command::none()
                }
            }
            Message::ClipboardOptInRejected => {
                self.pending_clipboard = None;
                Command::none()
            }
            Message::NextHistoryPage => {
                if !self.history.is_empty() {
                    let max_page = (self.history.len() - 1) / HISTORY_PAGE_SIZE;
                    self.history_page = self.history_page.min(max_page);
                    if self.history_page < max_page {
                        self.history_page += 1;
                    }
                }
                Command::none()
            }
            Message::PreviousHistoryPage => {
                if self.history_page > 0 {
                    self.history_page -= 1;
                }
                Command::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        if let Some(pending) = &self.pending_clipboard {
            let dialog = ConfirmDialog {
                title: "Copy to clipboard?",
                body: format!(
                    "Allow the wallet to copy the {} to your clipboard?",
                    pending.label
                ),
                confirm_label: "Allow",
                cancel_label: "Cancel",
                on_confirm: Message::ClipboardOptInConfirmed,
                on_cancel: Message::ClipboardOptInRejected,
            };
            return modal(column![dialog.view()]);
        }

        let mut content = column![self.current_address_view(), self.history_view(),]
            .spacing(24)
            .width(Length::Fill);

        if let Snapshot::Error(error) = &self.current {
            content = content.push(
                container(text(format!("Unable to load a receive address: {error}")))
                    .width(Length::Fill),
            );
        }

        container(content).width(Length::Fill).into()
    }

    fn load_current_address(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.current.set_loading();
        commands::rpc(
            "derive_address",
            client,
            |client| async move { client.derive_address(false).await },
            Message::CurrentAddressLoaded,
        )
    }

    fn clipboard_payload(&self, target: ClipboardTarget) -> Option<PendingClipboard> {
        match self.current.as_loaded() {
            Some(current) => match target {
                ClipboardTarget::Address => Some(PendingClipboard {
                    label: "address".to_string(),
                    value: current.address.clone(),
                }),
                ClipboardTarget::Descriptor => Some(PendingClipboard {
                    label: "descriptor".to_string(),
                    value: current.descriptor.clone(),
                }),
            },
            None => None,
        }
    }

    fn push_history(&mut self, previous: CurrentAddress) {
        let entry = AddressHistoryEntry {
            address: previous.address,
            status: AddressStatus::Unused,
            first_seen_height: None,
        };
        self.history.insert(0, entry);
        if self.history.len() > MAX_HISTORY_ENTRIES {
            self.history.truncate(MAX_HISTORY_ENTRIES);
        }
        self.history_page = 0;
    }

    fn current_address_view(&self) -> Element<Message> {
        match &self.current {
            Snapshot::Idle | Snapshot::Loading => {
                container(text("Fetching receive address...").size(16))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Error(error) => container(text(format!("Failed to load address: {error}")))
                .width(Length::Fill)
                .into(),
            Snapshot::Loaded(current) => {
                let qr = qr_view(QrViewState {
                    payload: &current.address,
                    caption: Some("Scan to receive funds"),
                });
                let address_row = copyable_text(
                    "Address",
                    &current.address,
                    Message::CopyToClipboard(ClipboardTarget::Address),
                );
                let descriptor_row = copyable_text(
                    "Descriptor",
                    &current.descriptor,
                    Message::CopyToClipboard(ClipboardTarget::Descriptor),
                );
                let rotate = button(text("New address"))
                    .on_press(Message::RotateAddress)
                    .padding(12);

                column![
                    qr,
                    address_row,
                    descriptor_row,
                    row![Space::with_width(Length::Fill), rotate]
                        .align_items(Alignment::Center)
                        .width(Length::Fill)
                ]
                .spacing(16)
                .width(Length::Fill)
                .into()
            }
        }
    }

    fn history_view(&self) -> Element<Message> {
        if self.history.is_empty() {
            return container(
                text("No derived addresses yet. Derive a new address to populate the list.")
                    .size(16),
            )
            .width(Length::Fill)
            .into();
        }

        let header = row![
            container(text("Address").size(14))
                .width(Length::FillPortion(3))
                .align_x(Alignment::Start),
            container(text("Status").size(14))
                .width(Length::FillPortion(1))
                .align_x(Alignment::Start),
            container(text("First seen height").size(14))
                .width(Length::FillPortion(1))
                .align_x(Alignment::Start),
        ]
        .spacing(12)
        .width(Length::Fill);

        let start = self.history_page * HISTORY_PAGE_SIZE;
        let end = (start + HISTORY_PAGE_SIZE).min(self.history.len());
        let entries = &self.history[start..end];

        let mut rows = column![header].spacing(8);
        for entry in entries {
            let status = entry.status.label().to_string();
            let first_seen = entry
                .first_seen_height
                .map(|height| height.to_string())
                .unwrap_or_else(|| "—".to_string());
            rows = rows.push(
                row![
                    container(text(&entry.address).size(14))
                        .width(Length::FillPortion(3))
                        .align_x(Alignment::Start),
                    container(text(status).size(14))
                        .width(Length::FillPortion(1))
                        .align_x(Alignment::Start),
                    container(text(first_seen).size(14))
                        .width(Length::FillPortion(1))
                        .align_x(Alignment::Start),
                ]
                .spacing(12)
                .width(Length::Fill),
            );
        }

        let prev_button = if self.history_page == 0 {
            button(text("Previous")).padding(8)
        } else {
            button(text("Previous"))
                .on_press(Message::PreviousHistoryPage)
                .padding(8)
        };

        let max_page = (self.history.len() - 1) / HISTORY_PAGE_SIZE;
        let next_button = if self.history_page >= max_page {
            button(text("Next")).padding(8)
        } else {
            button(text("Next"))
                .on_press(Message::NextHistoryPage)
                .padding(8)
        };

        let controls = row![
            prev_button,
            text(format!(
                "Page {} of {}",
                self.history_page + 1,
                max_page + 1
            ))
            .size(14),
            next_button,
        ]
        .spacing(12)
        .align_items(Alignment::Center);

        container(column![rows, controls].spacing(12))
            .width(Length::Fill)
            .into()
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
    use iced::command::Action;
    use std::time::Duration;

    fn dummy_client() -> WalletRpcClient {
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, Duration::from_secs(1)).unwrap()
    }

    fn response(address: &str) -> DeriveAddressResponse {
        DeriveAddressResponse {
            address: address.to_string(),
        }
    }

    #[test]
    fn address_rotation_appends_to_history() {
        let client = dummy_client();
        let mut state = State::default();

        state.update(
            client.clone(),
            Message::CurrentAddressLoaded(Ok(response("addr1"))),
        );
        assert_eq!(state.current.as_loaded().unwrap().address, "addr1");
        assert!(state.history.is_empty());

        state.update(
            client.clone(),
            Message::CurrentAddressLoaded(Ok(response("addr2"))),
        );
        assert_eq!(state.current.as_loaded().unwrap().address, "addr2");
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.history[0].address, "addr1");
    }

    #[test]
    fn clipboard_confirmation_flow_writes_after_opt_in() {
        let client = dummy_client();
        let mut state = State::default();
        state.update(
            client.clone(),
            Message::CurrentAddressLoaded(Ok(response("addr1"))),
        );

        let command = state.update(
            client.clone(),
            Message::CopyToClipboard(ClipboardTarget::Address),
        );
        assert!(state.pending_clipboard.is_some());
        assert!(!state.clipboard_opt_in);
        assert!(command.into_iter().next().is_none());

        let command = state.update(client, Message::ClipboardOptInConfirmed);
        assert!(state.clipboard_opt_in);
        assert!(state.pending_clipboard.is_none());

        let actions: Vec<_> = command.into_iter().collect();
        assert!(matches!(actions.as_slice(),
            [Action::Clipboard(clipboard::Action::Copy(value))] if value == "addr1"));
    }
}
