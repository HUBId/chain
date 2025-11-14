use iced::executor::Tokio;
use iced::widget::{button, column, container, text};
use iced::{Alignment, Application, Command, Element, Length, Settings, Theme};
use std::path::PathBuf;

use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};
use crate::rpc::dto::BalanceResponse;

/// Flags supplied by the binary entrypoint when launching the GUI.
#[derive(Debug, Clone)]
pub struct WalletGuiFlags {
    /// Pre-configured RPC client used to communicate with the wallet daemon.
    pub client: WalletRpcClient,
    /// Optional configuration file path surfaced to the operator.
    pub config_path: Option<PathBuf>,
}

/// Launches the wallet GUI using the provided flags.
pub fn launch(flags: WalletGuiFlags) -> iced::Result {
    WalletGui::run(Settings::with_flags(flags))
}

#[derive(Debug, Clone)]
enum GuiState {
    Loading,
    Loaded(BalanceResponse),
    Error(String),
}

#[derive(Debug, Clone)]
enum Message {
    Refresh,
    BalanceLoaded(Result<BalanceResponse, String>),
}

struct WalletGui {
    client: WalletRpcClient,
    config_path: Option<PathBuf>,
    state: GuiState,
}

impl Application for WalletGui {
    type Executor = Tokio;
    type Message = Message;
    type Theme = Theme;
    type Flags = WalletGuiFlags;

    fn new(flags: Self::Flags) -> (Self, Command<Self::Message>) {
        let command = Command::perform(fetch_balance(flags.client.clone()), Message::BalanceLoaded);
        (
            Self {
                client: flags.client,
                config_path: flags.config_path,
                state: GuiState::Loading,
            },
            command,
        )
    }

    fn title(&self) -> String {
        "RPP Wallet".to_string()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Refresh => {
                self.state = GuiState::Loading;
                let client = self.client.clone();
                Command::perform(fetch_balance(client), Message::BalanceLoaded)
            }
            Message::BalanceLoaded(Ok(balance)) => {
                self.state = GuiState::Loaded(balance);
                Command::none()
            }
            Message::BalanceLoaded(Err(error)) => {
                self.state = GuiState::Error(error);
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Self::Message> {
        let mut content = column![
            text("RPP Wallet GUI").size(32),
            text(format!("Endpoint: {}", self.client.endpoint())).size(16),
        ]
        .spacing(16)
        .align_items(Alignment::Start);

        if let Some(config) = &self.config_path {
            content = content.push(text(format!("Config path: {}", config.display())).size(16));
        }

        match &self.state {
            GuiState::Loading => {
                content = content.push(text("Loading wallet state...").size(20));
            }
            GuiState::Loaded(balance) => {
                content = content.push(text("Balance").size(20)).push(
                    column![
                        text(format!("Confirmed: {}", balance.confirmed)).size(18),
                        text(format!("Pending: {}", balance.pending)).size(18),
                        text(format!("Total: {}", balance.total)).size(18),
                    ]
                    .spacing(8),
                );
            }
            GuiState::Error(message) => {
                content = content.push(text(format!("RPC error: {message}")).size(18));
            }
        }

        content = content.push(
            button(text("Refresh").size(16))
                .on_press(Message::Refresh)
                .padding(8),
        );

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}

async fn fetch_balance(client: WalletRpcClient) -> Result<BalanceResponse, String> {
    client
        .get_balance()
        .await
        .map_err(|error| describe_error(&error))
}

fn describe_error(error: &WalletRpcClientError) -> String {
    match error {
        WalletRpcClientError::Rpc { message, .. } => {
            format!("{message} ({error})")
        }
        _ => error.to_string(),
    }
}
