use std::collections::HashMap;

use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{clipboard, Alignment, Command, Element, Length};

use crate::rpc::client::WalletRpcClient;
use crate::rpc::dto::{
    AddressBranchDto, AddressStatusDto, DeriveAddressResponse, ListBranchAddressesParams,
    ListBranchAddressesResponse, UpdateAddressMetadataParams, UpdateAddressMetadataResponse,
    WalletAddressDto,
};

use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::{copyable_text, modal, qr_view, ConfirmDialog, QrViewState};

const ADDRESS_PAGE_SIZE: u32 = 5;

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

impl From<AddressStatusDto> for AddressStatus {
    fn from(value: AddressStatusDto) -> Self {
        match value {
            AddressStatusDto::Unused => AddressStatus::Unused,
            AddressStatusDto::Used => AddressStatus::Used,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddressRow {
    pub address: String,
    pub status: AddressStatus,
    pub label: Option<String>,
    pub note: Option<String>,
    pub derived_at_ms: Option<u64>,
    pub first_seen_at_ms: Option<u64>,
    pub label_input: String,
    pub saving: bool,
}

impl AddressRow {
    fn from_dto(dto: WalletAddressDto, label_input: Option<String>, saving: bool) -> Self {
        let label = dto.label.clone();
        Self {
            address: dto.address,
            status: dto.status.into(),
            label: label.clone(),
            note: dto.note,
            derived_at_ms: dto.derived_at_ms,
            first_seen_at_ms: dto.first_seen_at_ms,
            label_input: label_input.unwrap_or_else(|| label.unwrap_or_default()),
            saving,
        }
    }

    fn is_label_dirty(&self) -> bool {
        let trimmed = self.label_input.trim();
        match &self.label {
            Some(current) => current != trimmed,
            None => !trimmed.is_empty(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddressPage {
    pub entries: Vec<AddressRow>,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub prev_cursor: Option<String>,
    pub page_number: u32,
}

impl AddressPage {
    fn new(
        cursor: Option<String>,
        entries: Vec<AddressRow>,
        next_cursor: Option<String>,
        prev_cursor: Option<String>,
        page_number: u32,
    ) -> Self {
        Self {
            entries,
            cursor,
            next_cursor,
            prev_cursor,
            page_number,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor {
    pub cursor: Option<String>,
    pub page_number: u32,
}

impl PageCursor {
    pub fn root() -> Self {
        Self {
            cursor: None,
            page_number: 1,
        }
    }
}

impl Default for PageCursor {
    fn default() -> Self {
        Self::root()
    }
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
    addresses: Snapshot<AddressPage>,
    clipboard_opt_in: bool,
    pending_clipboard: Option<PendingClipboard>,
    addresses_error: Option<String>,
    pending_cursor: Option<PageCursor>,
}

#[derive(Debug, Clone)]
pub enum Message {
    LoadCurrentAddress,
    CurrentAddressLoaded(Result<DeriveAddressResponse, RpcCallError>),
    RotateAddress,
    CopyToClipboard(ClipboardTarget),
    ClipboardOptInConfirmed,
    ClipboardOptInRejected,
    LoadAddresses(PageCursor),
    AddressesLoaded(Result<ListBranchAddressesResponse, RpcCallError>),
    PollAddresses,
    NextHistoryPage,
    PreviousHistoryPage,
    LabelChanged { address: String, value: String },
    PersistLabel(String),
    LabelUpdated(Result<UpdateAddressMetadataResponse, RpcCallError>),
}

impl State {
    pub fn reset(&mut self) {
        self.current = Snapshot::Idle;
        self.addresses = Snapshot::Idle;
        self.clipboard_opt_in = false;
        self.pending_clipboard = None;
        self.addresses_error = None;
        self.pending_cursor = None;
    }

    pub fn activate(&mut self, client: WalletRpcClient) -> Command<Message> {
        let mut commands = Vec::new();

        if self.current.should_refresh() {
            commands.push(self.load_current_address(client.clone()));
        }

        if self.addresses.should_refresh() {
            commands.push(self.load_addresses(client, PageCursor::root()));
        }

        Command::batch(commands)
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
                let follow_up = match result {
                    Ok(response) => {
                        let next_address = CurrentAddress::from(response);
                        self.current.set_loaded(next_address);
                        Some(self.load_addresses(client, PageCursor::root()))
                    }
                    Err(error) => {
                        self.current.set_error(&error);
                        None
                    }
                };
                follow_up.unwrap_or_else(Command::none)
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
            Message::LoadAddresses(cursor) => self.load_addresses(client, cursor),
            Message::PollAddresses => self.refresh_addresses(client),
            Message::AddressesLoaded(result) => {
                self.addresses_error = None;
                let cursor = self.pending_cursor.take().unwrap_or_else(PageCursor::root);
                match result {
                    Ok(response) => self.apply_address_page(cursor, response),
                    Err(error) => {
                        self.addresses.set_error(&error);
                        self.addresses_error = Some(format_rpc_error(&error));
                    }
                }
                Command::none()
            }
            Message::NextHistoryPage => {
                if let Some(cursor) = self
                    .addresses
                    .as_loaded()
                    .and_then(|page| page.next_cursor.clone())
                {
                    let next_page = PageCursor {
                        cursor: Some(cursor),
                        page_number: self
                            .addresses
                            .as_loaded()
                            .map(|page| page.page_number + 1)
                            .unwrap_or(1),
                    };
                    return self.load_addresses(client, next_page);
                }
                Command::none()
            }
            Message::PreviousHistoryPage => {
                if let Some(cursor) = self
                    .addresses
                    .as_loaded()
                    .and_then(|page| page.prev_cursor.clone())
                {
                    let prev_page = PageCursor {
                        cursor: Some(cursor),
                        page_number: self
                            .addresses
                            .as_loaded()
                            .map(|page| page.page_number.saturating_sub(1).max(1))
                            .unwrap_or(1),
                    };
                    return self.load_addresses(client, prev_page);
                }
                Command::none()
            }
            Message::LabelChanged { address, value } => {
                self.update_label_input(&address, value);
                Command::none()
            }
            Message::PersistLabel(address) => self.persist_label(client, address),
            Message::LabelUpdated(result) => {
                self.handle_label_updated(result);
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

    fn load_addresses(&mut self, client: WalletRpcClient, cursor: PageCursor) -> Command<Message> {
        self.addresses.set_loading();
        self.pending_cursor = Some(cursor.clone());
        let params = ListBranchAddressesParams {
            branch: AddressBranchDto::Receive,
            cursor: cursor.cursor.clone(),
            page_size: Some(ADDRESS_PAGE_SIZE),
        };
        commands::rpc(
            "addresses.list",
            client,
            move |client| async move { client.list_branch_addresses(&params).await },
            Message::AddressesLoaded,
        )
    }

    fn refresh_addresses(&mut self, client: WalletRpcClient) -> Command<Message> {
        let cursor = self
            .addresses
            .as_loaded()
            .map(|page| PageCursor {
                cursor: page.cursor.clone(),
                page_number: page.page_number,
            })
            .unwrap_or_else(PageCursor::root);
        self.load_addresses(client, cursor)
    }

    fn apply_address_page(&mut self, cursor: PageCursor, response: ListBranchAddressesResponse) {
        let previous: HashMap<_, _> = self
            .addresses
            .as_loaded()
            .map(|page| {
                page.entries
                    .iter()
                    .map(|entry| {
                        (
                            entry.address.clone(),
                            (entry.label_input.clone(), entry.saving),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        let ListBranchAddressesResponse {
            addresses,
            next_cursor,
            prev_cursor,
        } = response;

        let entries: Vec<AddressRow> = addresses
            .into_iter()
            .filter(|dto| dto.branch == AddressBranchDto::Receive)
            .map(|dto| {
                let preserved = previous.get(&dto.address);
                let label_input = preserved
                    .map(|(input, _)| input.clone())
                    .or_else(|| dto.label.clone());
                let saving = preserved.map(|(_, saving)| *saving).unwrap_or(false);
                AddressRow::from_dto(dto, label_input, saving)
            })
            .collect();

        self.addresses.set_loaded(AddressPage::new(
            cursor.cursor,
            entries,
            next_cursor,
            prev_cursor,
            cursor.page_number,
        ));
    }

    fn update_label_input(&mut self, address: &str, value: String) {
        if let Snapshot::Loaded(page) = &mut self.addresses {
            for entry in &mut page.entries {
                if entry.address == address {
                    entry.label_input = value;
                    break;
                }
            }
        }
    }

    fn persist_label(&mut self, client: WalletRpcClient, address: String) -> Command<Message> {
        if let Snapshot::Loaded(page) = &mut self.addresses {
            if let Some(entry) = page
                .entries
                .iter_mut()
                .find(|entry| entry.address == address)
            {
                if entry.saving || !entry.is_label_dirty() {
                    return Command::none();
                }
                entry.saving = true;
                let params = UpdateAddressMetadataParams {
                    address: entry.address.clone(),
                    label: Some(entry.label_input.trim().to_string()),
                    note: None,
                };
                return commands::rpc(
                    "addresses.update_metadata",
                    client,
                    move |client| async move { client.update_address_metadata(&params).await },
                    Message::LabelUpdated,
                );
            }
        }
        Command::none()
    }

    fn handle_label_updated(
        &mut self,
        result: Result<UpdateAddressMetadataResponse, RpcCallError>,
    ) {
        match result {
            Ok(response) => {
                self.addresses_error = None;
                if let Snapshot::Loaded(page) = &mut self.addresses {
                    for entry in &mut page.entries {
                        if entry.address == response.address.address {
                            entry.label = response.address.label.clone();
                            entry.note = response.address.note.clone();
                            entry.label_input = response.address.label.clone().unwrap_or_default();
                            entry.saving = false;
                        }
                    }
                }
            }
            Err(error) => {
                self.addresses_error = Some(format_rpc_error(&error));
                if let Snapshot::Loaded(page) = &mut self.addresses {
                    for entry in &mut page.entries {
                        if entry.saving {
                            entry.saving = false;
                        }
                    }
                }
            }
        }
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
        match &self.addresses {
            Snapshot::Idle | Snapshot::Loading => {
                container(text("Loading derived addresses...").size(16))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Error(error) => {
                container(text(format!("Failed to load address history: {error}")))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Loaded(page) => {
                if page.entries.is_empty() {
                    return container(
                        text(
                            "No derived addresses yet. Derive a new address to populate the list.",
                        )
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
                    container(text("Label").size(14))
                        .width(Length::FillPortion(3))
                        .align_x(Alignment::Start),
                    container(text("Note").size(14))
                        .width(Length::FillPortion(3))
                        .align_x(Alignment::Start),
                    container(text("Actions").size(14))
                        .width(Length::Shrink)
                        .align_x(Alignment::Start),
                ]
                .spacing(12)
                .width(Length::Fill);

                let mut rows = column![header].spacing(8);
                for entry in &page.entries {
                    let status = entry.status.label().to_string();
                    let note = entry.note.clone().unwrap_or_else(|| "—".to_string());
                    let address = entry.address.clone();
                    let label_editor = text_input("Label", &entry.label_input)
                        .padding(8)
                        .on_input(move |value| Message::LabelChanged {
                            address: address.clone(),
                            value,
                        })
                        .size(14);

                    let save_button = if entry.saving || !entry.is_label_dirty() {
                        button(text("Save")).padding(8)
                    } else {
                        button(text("Save"))
                            .on_press(Message::PersistLabel(entry.address.clone()))
                            .padding(8)
                    };

                    rows = rows.push(
                        row![
                            container(text(&entry.address).size(14))
                                .width(Length::FillPortion(3))
                                .align_x(Alignment::Start),
                            container(text(status).size(14))
                                .width(Length::FillPortion(1))
                                .align_x(Alignment::Start),
                            container(label_editor)
                                .width(Length::FillPortion(3))
                                .align_x(Alignment::Start),
                            container(text(note).size(14))
                                .width(Length::FillPortion(3))
                                .align_x(Alignment::Start),
                            save_button,
                        ]
                        .spacing(12)
                        .width(Length::Fill),
                    );
                }

                let prev_button = if page.prev_cursor.is_some() {
                    button(text("Previous"))
                        .on_press(Message::PreviousHistoryPage)
                        .padding(8)
                } else {
                    button(text("Previous")).padding(8)
                };

                let next_button = if page.next_cursor.is_some() {
                    button(text("Next"))
                        .on_press(Message::NextHistoryPage)
                        .padding(8)
                } else {
                    button(text("Next")).padding(8)
                };

                let mut controls = row![
                    prev_button,
                    text(format!("Page {}", page.page_number)).size(14),
                    next_button,
                ]
                .spacing(12)
                .align_items(Alignment::Center);

                if let Some(error) = &self.addresses_error {
                    controls = controls.push(text(error).size(14));
                }

                container(column![rows, controls].spacing(12))
                    .width(Length::Fill)
                    .into()
            }
        }
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
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, None, Duration::from_secs(1))
            .unwrap()
    }

    fn response(address: &str) -> DeriveAddressResponse {
        DeriveAddressResponse {
            address: address.to_string(),
        }
    }

    fn address(address: &str, label: Option<&str>, note: Option<&str>) -> WalletAddressDto {
        WalletAddressDto {
            address: address.to_string(),
            branch: AddressBranchDto::Receive,
            index: 0,
            status: AddressStatusDto::Unused,
            label: label.map(|value| value.to_string()),
            note: note.map(|value| value.to_string()),
            derived_at_ms: None,
            first_seen_at_ms: None,
        }
    }

    fn address_page(addresses: Vec<WalletAddressDto>) -> ListBranchAddressesResponse {
        ListBranchAddressesResponse {
            addresses,
            next_cursor: None,
            prev_cursor: None,
        }
    }

    #[test]
    fn activate_triggers_address_fetch() {
        let mut state = State::default();
        let _command = state.activate(dummy_client());
        assert!(matches!(state.current, Snapshot::Loading));
        assert!(matches!(state.addresses, Snapshot::Loading));
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
        assert!(command.actions().is_empty());

        let command = state.update(client, Message::ClipboardOptInConfirmed);
        assert!(state.clipboard_opt_in);
        assert!(state.pending_clipboard.is_none());

        let actions = command.actions();
        assert_eq!(actions.len(), 1);
        let debug = format!("{:?}", actions[0]);
        assert!(debug.contains("Action::Clipboard"));
        assert!(debug.contains("addr1"));
    }

    #[test]
    fn clipboard_rejection_clears_pending_request() {
        let client = dummy_client();
        let mut state = State::default();
        state.update(
            client.clone(),
            Message::CurrentAddressLoaded(Ok(response("addr1"))),
        );

        let _ = state.update(
            client.clone(),
            Message::CopyToClipboard(ClipboardTarget::Address),
        );
        assert!(state.pending_clipboard.is_some());

        let command = state.update(client, Message::ClipboardOptInRejected);
        assert!(state.pending_clipboard.is_none());
        assert!(command.actions().is_empty());
    }

    #[test]
    fn load_error_sets_snapshot_failure() {
        let mut state = State::default();
        state.current = Snapshot::Loading;
        let error = RpcCallError::Timeout(Duration::from_secs(4));
        state.update(dummy_client(), Message::CurrentAddressLoaded(Err(error)));
        assert!(matches!(state.current, Snapshot::Error(message) if message.contains("4")));
    }

    #[test]
    fn address_page_loads_from_rpc_response() {
        let mut state = State::default();
        state.apply_address_page(
            PageCursor::root(),
            address_page(vec![address("addr1", None, None)]),
        );

        match &state.addresses {
            Snapshot::Loaded(page) => {
                assert_eq!(page.entries.len(), 1);
                assert_eq!(page.entries[0].address, "addr1");
                assert_eq!(page.entries[0].status, AddressStatus::Unused);
            }
            _ => panic!("addresses not loaded"),
        }
    }

    #[test]
    fn label_updates_apply_rpc_changes() {
        let mut state = State::default();
        state.apply_address_page(
            PageCursor::root(),
            address_page(vec![address("addr1", None, None)]),
        );

        state.update(
            dummy_client(),
            Message::LabelChanged {
                address: "addr1".to_string(),
                value: "home".to_string(),
            },
        );

        let response = UpdateAddressMetadataResponse {
            address: address("addr1", Some("home"), Some("note")),
        };
        state.handle_label_updated(Ok(response));

        match &state.addresses {
            Snapshot::Loaded(page) => {
                assert_eq!(page.entries[0].label.as_deref(), Some("home"));
                assert_eq!(page.entries[0].note.as_deref(), Some("note"));
                assert_eq!(page.entries[0].label_input, "home");
                assert!(!page.entries[0].saving);
            }
            _ => panic!("addresses not loaded"),
        }
    }
}
