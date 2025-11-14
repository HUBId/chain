use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use iced::event;
use iced::executor::Default;
use iced::keyboard;
use iced::time;
use iced::widget::{button, column, container, row, text, text_input};
use iced::window;
use iced::{Alignment, Application, Command, Element, Event, Length, Subscription, Theme};
use serde::Deserialize;
use serde_json::Value;
use tokio::task;

use crate::config::WalletConfig;
use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};
use crate::rpc::dto::SyncStatusResponse;
use crate::rpc::error::WalletRpcErrorCode;

use super::commands::{self, RpcCallError};
use super::components::{
    error_banner, modal, progress_bar as progress_bar_view, ErrorBannerState, ProgressBarState,
};
use super::error_map::{describe_rpc_error, technical_details};
use super::routes::{self, NavigationIntent, Route};
use super::tabs::{dashboard, receive, send};
use super::WalletGuiFlags;

const MIN_SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// Top-level iced [`Application`] coordinating wallet UI state.
pub struct WalletApp {
    model: Model,
}

/// Messages driving the wallet UI state machine.
#[derive(Debug, Clone)]
pub enum Message {
    ConfigLoaded(Result<WalletConfig, AppError>),
    KeystoreStatusDetected(Result<KeystoreStatus, AppError>),
    PassphraseChanged(String),
    PassphraseSubmitted,
    UnlockCompleted(Result<(), AppError>),
    SyncTick,
    SyncStatusLoaded(Result<SyncStatusResponse, AppError>),
    Navigate(Route),
    KeyboardShortcut(NavigationIntent),
    Dashboard(dashboard::Message),
    Receive(receive::Message),
    Send(send::Message),
    DismissError,
    Shutdown,
}

impl Application for WalletApp {
    type Executor = Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = WalletGuiFlags;

    fn new(flags: Self::Flags) -> (Self, Command<Self::Message>) {
        let mut model = Model::new(flags);
        model.queue_async(AsyncAction::LoadConfig {
            path: model.config_path.clone(),
        });
        let command = model.dispatch_next_async();
        (Self { model }, command)
    }

    fn title(&self) -> String {
        "RPP Wallet".to_owned()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        let mut update = Update::new();

        match message {
            Message::ConfigLoaded(result) => {
                self.model.mark_async_complete();
                match result {
                    Ok(config) => {
                        self.model.keystore_path = Some(config.engine.keystore_path.clone());
                        self.model.config = Some(config);
                        self.model.queue_async(AsyncAction::DetectKeystore {
                            keystore_path: self.model.keystore_path.clone(),
                        });
                    }
                    Err(error) => {
                        self.model.push_error(error);
                        self.model.queue_async(AsyncAction::DetectKeystore {
                            keystore_path: None,
                        });
                    }
                }
            }
            Message::KeystoreStatusDetected(result) => {
                self.model.mark_async_complete();
                match result {
                    Ok(status) => self.model.apply_keystore_status(status),
                    Err(error) => self.model.push_error(error),
                }
            }
            Message::PassphraseChanged(value) => {
                self.model.passphrase_input = value;
            }
            Message::PassphraseSubmitted => {
                if self.model.can_attempt_unlock() && !self.model.passphrase_input.is_empty() {
                    let passphrase = std::mem::take(&mut self.model.passphrase_input);
                    self.model.set_session_unlocking();
                    self.model.queue_async(AsyncAction::Unlock { passphrase });
                }
            }
            Message::UnlockCompleted(result) => {
                self.model.mark_async_complete();
                match result {
                    Ok(()) => {
                        self.model.session = SessionState::Unlocked(UnlockedSession::new());
                        self.model.sync_status = None;
                        self.model.sync_inflight = false;
                        self.model.passphrase_input.clear();
                        self.model.dashboard.reset();
                        self.model.receive.reset();
                        self.model.send.reset();
                    }
                    Err(error) => {
                        self.model.set_session_locked();
                        self.model.passphrase_input.clear();
                        self.model.push_error(error);
                    }
                }
            }
            Message::SyncTick => {
                if self.model.session.is_unlocked() && !self.model.sync_inflight {
                    self.model.sync_inflight = true;
                    self.model.queue_async(AsyncAction::FetchSyncStatus);
                }
            }
            Message::SyncStatusLoaded(result) => {
                self.model.mark_async_complete();
                match result {
                    Ok(status) => {
                        let status_clone = status.clone();
                        self.model.sync_status = Some(status);
                        let (command, route) = self.model.dashboard.update(
                            self.model.client.clone(),
                            dashboard::Message::SyncStatusUpdated(status_clone),
                        );
                        if let Some(route) = route {
                            self.model.active_route = route;
                            self.route_changed(&mut update);
                        }
                        update.push(command.map(Message::Dashboard));
                    }
                    Err(error) => self.model.push_error(error),
                }
                self.model.sync_inflight = false;
            }
            Message::Navigate(route) => {
                self.model.active_route = route;
                self.route_changed(&mut update);
            }
            Message::KeyboardShortcut(intent) => match intent {
                NavigationIntent::Activate(route) => {
                    self.model.active_route = route;
                    self.route_changed(&mut update);
                }
                NavigationIntent::Next => {
                    self.model.active_route = self.model.active_route.next();
                    self.route_changed(&mut update);
                }
                NavigationIntent::Previous => {
                    self.model.active_route = self.model.active_route.previous();
                    self.route_changed(&mut update);
                }
            },
            Message::Dashboard(message) => {
                let (command, route) = self
                    .model
                    .dashboard
                    .update(self.model.client.clone(), message);
                if let Some(route) = route {
                    self.model.active_route = route;
                    self.route_changed(&mut update);
                }
                update.push(command.map(Message::Dashboard));
            }
            Message::Receive(message) => {
                let command = self
                    .model
                    .receive
                    .update(self.model.client.clone(), message)
                    .map(Message::Receive);
                update.push(command);
            }
            Message::Send(message) => {
                let command = self
                    .model
                    .send
                    .update(self.model.client.clone(), message)
                    .map(Message::Send);
                update.push(command);
            }
            Message::DismissError => {
                self.model.global_error = None;
            }
            Message::Shutdown => {
                update.push(Command::exit());
            }
        }

        if self.model.session.is_unlocked()
            && self.model.sync_status.is_none()
            && !self.model.sync_inflight
        {
            self.model.sync_inflight = true;
            self.model.queue_async(AsyncAction::FetchSyncStatus);
        }

        if self.model.session.is_unlocked() {
            if self.model.active_route == Route::Overview {
                let command = self
                    .model
                    .dashboard
                    .activate(self.model.client.clone())
                    .map(Message::Dashboard);
                update.push(command);
            }
            if self.model.active_route == Route::Receive {
                let command = self
                    .model
                    .receive
                    .activate(self.model.client.clone())
                    .map(Message::Receive);
                update.push(command);
            }
            if self.model.active_route == Route::Send {
                let command = self
                    .model
                    .send
                    .activate(self.model.client.clone())
                    .map(Message::Send);
                update.push(command);
            }
        }

        update.push(self.model.dispatch_next_async());
        update.into_command()
    }

    fn view(&self) -> Element<Self::Message> {
        let header = text("RPP Wallet").size(28);
        let mut layout = column![header].spacing(16).padding(20);

        if let Some(error) = &self.model.global_error {
            layout = layout.push(error_banner(error.banner_state(), Message::DismissError));
        }

        layout = layout.push(self.view_navigation());
        layout = layout.push(self.view_content());

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .into()
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        let mut subscriptions = Vec::new();

        subscriptions.push(event::listen_with(|event, status| {
            if status == event::Status::Captured {
                return None;
            }

            match event {
                Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
                    routes::navigation_intent(key, modifiers).map(Message::KeyboardShortcut)
                }
                Event::Window(window::Event::CloseRequested) => Some(Message::Shutdown),
                _ => None,
            }
        }));

        if self.model.session.is_unlocked() {
            subscriptions
                .push(time::every(self.model.sync_poll_interval).map(|_| Message::SyncTick));
        }

        Subscription::batch(subscriptions)
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

impl WalletApp {
    fn view_navigation(&self) -> Element<Message> {
        let buttons = Route::ALL.iter().fold(row![], |row, route| {
            let mut button = button(text(route.title()).size(16)).padding(8);
            if *route == self.model.active_route {
                button = button.style(iced::theme::Button::Primary);
            }
            row.push(button.on_press(Message::Navigate(*route)))
        });
        let buttons = buttons.spacing(8).align_items(Alignment::Center);
        container(buttons).width(Length::Fill).into()
    }

    fn view_content(&self) -> Element<Message> {
        match &self.model.session {
            SessionState::Initializing => self.view_loading_state(),
            SessionState::Locked(session) => self.view_locked_state(session),
            SessionState::Unlocking(session) => self.view_unlocking_state(session),
            SessionState::Unlocked(_) => self.view_unlocked_state(),
        }
    }

    fn view_loading_state(&self) -> Element<Message> {
        container(text("Initialising wallet session...").size(18))
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }

    fn view_locked_state(&self, session: &LockedSession) -> Element<Message> {
        let mut unlock_button = button(text("Unlock"))
            .padding(10)
            .style(iced::theme::Button::Primary);
        if session.keystore_present && !self.model.passphrase_input.is_empty() {
            unlock_button = unlock_button.on_press(Message::PassphraseSubmitted);
        }

        let content = column![
            text("Wallet locked").size(24),
            text(if session.keystore_present {
                "Enter the wallet passphrase to unlock the session."
            } else {
                "Keystore missing. Configure the daemon and restart once the keystore is available."
            })
            .size(16),
            text_input("Passphrase", &self.model.passphrase_input)
                .secure(true)
                .on_input(Message::PassphraseChanged)
                .on_submit(Message::PassphraseSubmitted)
                .padding(12)
                .size(16),
            row![
                unlock_button,
                button(text("Exit")).on_press(Message::Shutdown).padding(10),
            ]
            .spacing(12),
        ]
        .spacing(16)
        .align_items(Alignment::Center);

        modal(content)
    }

    fn view_unlocking_state(&self, session: &LockedSession) -> Element<Message> {
        let message = if session.keystore_present {
            "Unlocking wallet session..."
        } else {
            "Waiting for keystore availability..."
        };

        let progress = progress_bar_view(ProgressBarState {
            progress: if session.keystore_present { 0.5 } else { 0.2 },
            label: Some(message),
        });

        let content = column![
            text("Unlocking").size(24),
            progress,
            button(text("Cancel"))
                .on_press(Message::Shutdown)
                .padding(10),
        ]
        .spacing(16)
        .align_items(Alignment::Center);

        modal(content)
    }

    fn view_unlocked_state(&self) -> Element<Message> {
        let mut column = column![text(self.model.active_route.title()).size(24)]
            .spacing(16)
            .width(Length::Fill);

        if let Some(status) = &self.model.sync_status {
            if self.model.active_route != Route::Overview {
                column = column.push(sync_status_summary(status));
            }
        }

        let content = match self.model.active_route {
            Route::Overview => self.model.dashboard.view().map(Message::Dashboard),
            Route::Receive => self.model.receive.view().map(Message::Receive),
            Route::Send => self.model.send.view().map(Message::Send),
            _ => text("Tab content coming soon...").size(16).into(),
        };

        column = column.push(content);

        container(column)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn route_changed(&mut self, update: &mut Update) {
        if self.model.active_route == Route::Overview {
            let command = self
                .model
                .dashboard
                .activate(self.model.client.clone())
                .map(Message::Dashboard);
            update.push(command);
        }
        if self.model.active_route == Route::Receive {
            let command = self
                .model
                .receive
                .activate(self.model.client.clone())
                .map(Message::Receive);
            update.push(command);
        }
        if self.model.active_route == Route::Send {
            let command = self
                .model
                .send
                .activate(self.model.client.clone())
                .map(Message::Send);
            update.push(command);
        }
    }
}

/// Collects commands produced during a UI update cycle.
#[derive(Default)]
struct Update {
    commands: Vec<Command<Message>>,
}

impl Update {
    fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    fn push(&mut self, command: Command<Message>) {
        self.commands.push(command);
    }

    fn into_command(self) -> Command<Message> {
        Command::batch(self.commands)
    }
}

#[derive(Debug)]
struct Model {
    client: WalletRpcClient,
    config_path: Option<PathBuf>,
    config: Option<WalletConfig>,
    session: SessionState,
    active_route: Route,
    async_queue: VecDeque<AsyncAction>,
    async_inflight: bool,
    sync_poll_interval: Duration,
    sync_status: Option<SyncStatusResponse>,
    sync_inflight: bool,
    global_error: Option<ErrorNotification>,
    passphrase_input: String,
    keystore_path: Option<PathBuf>,
    dashboard: dashboard::State,
    receive: receive::State,
    send: send::State,
}

impl Model {
    fn new(flags: WalletGuiFlags) -> Self {
        Self {
            client: flags.client,
            config_path: flags.config_path,
            config: None,
            session: SessionState::Initializing,
            active_route: Route::Overview,
            async_queue: VecDeque::new(),
            async_inflight: false,
            sync_poll_interval: flags.sync_poll_interval.max(MIN_SYNC_INTERVAL),
            sync_status: None,
            sync_inflight: false,
            global_error: None,
            passphrase_input: String::new(),
            keystore_path: None,
            dashboard: dashboard::State::default(),
            receive: receive::State::default(),
            send: send::State::default(),
        }
    }

    fn queue_async(&mut self, action: AsyncAction) {
        self.async_queue.push_back(action);
    }

    fn dispatch_next_async(&mut self) -> Command<Message> {
        if self.async_inflight {
            return Command::none();
        }
        if let Some(action) = self.async_queue.pop_front() {
            self.async_inflight = true;
            action.into_command(self.client.clone())
        } else {
            Command::none()
        }
    }

    fn mark_async_complete(&mut self) {
        self.async_inflight = false;
    }

    fn push_error(&mut self, error: AppError) {
        self.global_error = Some(ErrorNotification::from(error));
    }

    fn apply_keystore_status(&mut self, status: KeystoreStatus) {
        self.dashboard.reset();
        self.receive.reset();
        self.send.reset();
        if status.locked {
            self.session = SessionState::Locked(LockedSession {
                keystore_present: status.present,
            });
            self.sync_status = None;
            self.sync_inflight = false;
        } else {
            self.session = SessionState::Unlocked(UnlockedSession::new());
            self.sync_status = None;
            self.sync_inflight = false;
        }
    }

    fn set_session_locked(&mut self) {
        self.dashboard.reset();
        self.receive.reset();
        self.send.reset();
        let present = self
            .keystore_path
            .as_ref()
            .map(|path| path.exists())
            .unwrap_or(true);
        self.session = SessionState::Locked(LockedSession {
            keystore_present: present,
        });
        self.sync_inflight = false;
        self.sync_status = None;
    }

    fn set_session_unlocking(&mut self) {
        self.dashboard.reset();
        self.receive.reset();
        self.send.reset();
        let present = self
            .keystore_path
            .as_ref()
            .map(|path| path.exists())
            .unwrap_or(true);
        self.session = SessionState::Unlocking(LockedSession {
            keystore_present: present,
        });
        self.sync_inflight = false;
    }

    fn can_attempt_unlock(&self) -> bool {
        matches!(
            self.session,
            SessionState::Locked(LockedSession {
                keystore_present: true,
            })
        )
    }
}

#[derive(Debug, Clone)]
struct AppError {
    message: String,
    detail: Option<String>,
}

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            detail: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl From<WalletRpcClientError> for AppError {
    fn from(value: WalletRpcClientError) -> Self {
        match value {
            WalletRpcClientError::Rpc {
                code,
                message,
                details,
                ..
            } => {
                let description = describe_rpc_error(&code, details.as_ref());
                let mut extra = Vec::new();
                if let Some(mapped) = description.technical.clone() {
                    extra.push(mapped);
                }
                if let Some(technical) = technical_details(&message, details.as_ref()) {
                    extra.push(technical);
                }
                let detail = if extra.is_empty() {
                    None
                } else {
                    Some(extra.join("\n"))
                };
                let mut error = AppError::new(description.headline);
                error.detail = detail;
                error
            }
            other => AppError::new(other.to_string()),
        }
    }
}

impl From<RpcCallError> for AppError {
    fn from(value: RpcCallError) -> Self {
        match value {
            RpcCallError::Timeout(duration) => AppError::new(format!(
                "Wallet RPC request timed out after {}s",
                duration.as_secs()
            )),
            RpcCallError::Client(error) => AppError::from(error),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        AppError::new(value.to_string())
    }
}

impl From<toml::de::Error> for AppError {
    fn from(value: toml::de::Error) -> Self {
        AppError::new(value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::new(value.to_string())
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(value: tokio::task::JoinError) -> Self {
        AppError::new(value.to_string())
    }
}

#[derive(Debug, Clone)]
struct ErrorNotification {
    message: String,
    detail: Option<String>,
}

impl From<AppError> for ErrorNotification {
    fn from(value: AppError) -> Self {
        Self {
            message: value.message,
            detail: value.detail,
        }
    }
}

impl ErrorNotification {
    fn banner_state(&self) -> ErrorBannerState<'_> {
        ErrorBannerState {
            message: &self.message,
            detail: self.detail.as_deref(),
        }
    }
}

#[derive(Debug, Clone)]
struct KeystoreStatus {
    locked: bool,
    present: bool,
}

#[derive(Debug)]
struct UnlockedSession {
    unlocked_at: Instant,
}

impl UnlockedSession {
    fn new() -> Self {
        Self {
            unlocked_at: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct LockedSession {
    keystore_present: bool,
}

#[derive(Debug)]
enum SessionState {
    Initializing,
    Locked(LockedSession),
    Unlocking(LockedSession),
    Unlocked(UnlockedSession),
}

impl SessionState {
    fn is_unlocked(&self) -> bool {
        matches!(self, SessionState::Unlocked(_))
    }
}

#[derive(Debug)]
enum AsyncAction {
    LoadConfig { path: Option<PathBuf> },
    DetectKeystore { keystore_path: Option<PathBuf> },
    Unlock { passphrase: String },
    FetchSyncStatus,
}

impl AsyncAction {
    fn into_command(self, client: WalletRpcClient) -> Command<Message> {
        match self {
            AsyncAction::LoadConfig { path } => {
                Command::perform(load_wallet_config(path), Message::ConfigLoaded)
            }
            AsyncAction::DetectKeystore { keystore_path } => Command::perform(
                detect_keystore_status(client, keystore_path),
                Message::KeystoreStatusDetected,
            ),
            AsyncAction::Unlock { passphrase } => commands::rpc(
                client,
                move |client| unlock_wallet(client, passphrase),
                |result| Message::UnlockCompleted(result.map_err(AppError::from)),
            ),
            AsyncAction::FetchSyncStatus => commands::rpc(client, poll_sync_status, |result| {
                Message::SyncStatusLoaded(result.map_err(AppError::from))
            }),
        }
    }
}

async fn load_wallet_config(path: Option<PathBuf>) -> Result<WalletConfig, AppError> {
    if let Some(path) = path {
        let contents = task::spawn_blocking(move || std::fs::read_to_string(path))
            .await
            .map_err(AppError::from)??;
        let config: WalletConfig = toml::from_str(&contents).map_err(AppError::from)?;
        Ok(config)
    } else {
        Ok(WalletConfig::default())
    }
}

async fn detect_keystore_status(
    client: WalletRpcClient,
    keystore_path: Option<PathBuf>,
) -> Result<KeystoreStatus, AppError> {
    #[derive(Debug, Deserialize)]
    struct Response {
        locked: bool,
        present: bool,
    }

    match client
        .request("keystore_status", Option::<Value>::None)
        .await
    {
        Ok(value) => {
            let response: Response = serde_json::from_value(value).map_err(AppError::from)?;
            Ok(KeystoreStatus {
                locked: response.locked,
                present: response.present,
            })
        }
        Err(WalletRpcClientError::Rpc { code, .. })
            if code == WalletRpcErrorCode::MethodNotFound =>
        {
            let present = if let Some(path) = keystore_path {
                task::spawn_blocking(move || std::fs::metadata(path).is_ok())
                    .await
                    .map_err(AppError::from)?
            } else {
                false
            };
            Ok(KeystoreStatus {
                locked: present,
                present,
            })
        }
        Err(error) => Err(AppError::from(error)),
    }
}

async fn unlock_wallet(
    client: WalletRpcClient,
    passphrase: String,
) -> Result<(), WalletRpcClientError> {
    #[derive(serde::Serialize)]
    struct UnlockParams {
        passphrase: String,
    }

    let params = UnlockParams { passphrase };

    client
        .request("unlock_wallet", Some(params))
        .await
        .map(|_| ())
}

async fn poll_sync_status(
    client: WalletRpcClient,
) -> Result<SyncStatusResponse, WalletRpcClientError> {
    client.sync_status().await
}

fn sync_status_summary(status: &SyncStatusResponse) -> Element<Message> {
    let mode = status
        .mode
        .as_ref()
        .map(|mode| format!("Mode: {:?}", mode))
        .unwrap_or_else(|| "Mode: unknown".to_string());
    let syncing = if status.syncing { "Syncing" } else { "Idle" };
    let latest = status
        .latest_height
        .map(|height| format!("Latest height: {height}"))
        .unwrap_or_else(|| "Latest height: n/a".to_string());

    container(
        column![
            text(syncing).size(16),
            text(mode).size(16),
            text(latest).size(16)
        ]
        .spacing(4),
    )
    .style(iced::theme::Container::Box)
    .padding(12)
    .width(Length::Shrink)
    .into()
}
