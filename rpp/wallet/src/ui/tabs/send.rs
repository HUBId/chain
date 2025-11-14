use iced::widget::{button, checkbox, column, container, row, text, text_input};
use iced::{Alignment, Command, Element, Length};

use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};
use crate::rpc::dto::{
    BroadcastResponse, CreateTxParams, CreateTxResponse, EstimateFeeResponse,
    PolicyPreviewResponse, SignTxResponse,
};

use crate::ui::commands::{self, RpcCallError};
use crate::ui::error_map::{describe_rpc_error, technical_details};

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestState<T> {
    Idle,
    Loading,
    Success(T),
    Failure(RequestFailure),
}

impl<T> Default for RequestState<T> {
    fn default() -> Self {
        RequestState::Idle
    }
}

impl<T> RequestState<T> {
    fn set_loading(&mut self) {
        *self = RequestState::Loading;
    }

    fn set_success(&mut self, value: T) {
        *self = RequestState::Success(value);
    }

    fn set_failure(&mut self, failure: RequestFailure) {
        *self = RequestState::Failure(failure);
    }

    fn is_loading(&self) -> bool {
        matches!(self, RequestState::Loading)
    }

    fn is_success(&self) -> bool {
        matches!(self, RequestState::Success(_))
    }

    fn as_success(&self) -> Option<&T> {
        match self {
            RequestState::Success(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestFailure {
    summary: String,
    detail: Option<String>,
}

impl RequestFailure {
    fn new(summary: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            summary: summary.into(),
            detail,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ErrorBanner {
    summary: String,
    detail: Option<String>,
    show_detail: bool,
}

impl ErrorBanner {
    fn from_failure(failure: RequestFailure) -> Self {
        Self {
            summary: failure.summary,
            detail: failure.detail,
            show_detail: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationStage {
    PolicyPreview,
    FeeEstimate,
    CreateDraft,
    SignDraft,
    Broadcast,
}

impl OperationStage {
    fn label(self) -> &'static str {
        match self {
            OperationStage::PolicyPreview => "Policy preview",
            OperationStage::FeeEstimate => "Fee estimation",
            OperationStage::CreateDraft => "Draft creation",
            OperationStage::SignDraft => "Draft signing",
            OperationStage::Broadcast => "Broadcast",
        }
    }
}

#[derive(Debug, Default)]
pub struct State {
    recipient_input: String,
    amount_input: String,
    notes_input: String,
    use_estimated_fee: bool,
    fee_rate_input: String,
    confirmation_target_input: String,
    policy_preview: RequestState<PolicyPreviewResponse>,
    fee_estimate: RequestState<EstimateFeeResponse>,
    draft: RequestState<CreateTxResponse>,
    signature: RequestState<SignTxResponse>,
    broadcast: RequestState<BroadcastResponse>,
    error_banner: Option<ErrorBanner>,
}

impl State {
    pub fn reset(&mut self) {
        *self = State::default();
    }

    pub fn activate(&mut self, _client: WalletRpcClient) -> Command<Message> {
        Command::none()
    }

    pub fn update(&mut self, client: WalletRpcClient, message: Message) -> Command<Message> {
        match message {
            Message::RecipientChanged(value) => {
                self.recipient_input = value;
                Command::none()
            }
            Message::AmountChanged(value) => {
                self.amount_input = value;
                Command::none()
            }
            Message::NotesChanged(value) => {
                self.notes_input = value;
                Command::none()
            }
            Message::FeeRateChanged(value) => {
                self.fee_rate_input = value;
                Command::none()
            }
            Message::ConfirmationTargetChanged(value) => {
                self.confirmation_target_input = value;
                Command::none()
            }
            Message::FeeEstimateToggled(value) => {
                self.use_estimated_fee = value;
                if !value {
                    self.fee_estimate = RequestState::Idle;
                }
                Command::none()
            }
            Message::SubmitPreview => self.submit_preview(client),
            Message::PolicyPreviewLoaded(result) => {
                self.apply_policy_preview_result(result);
                Command::none()
            }
            Message::FeeEstimateLoaded(result) => {
                self.apply_fee_estimate_result(result);
                Command::none()
            }
            Message::CreateDraft => self.create_draft(client),
            Message::DraftCreated(result) => {
                self.apply_draft_result(result);
                Command::none()
            }
            Message::SignDraft => self.sign_draft(client),
            Message::DraftSigned(result) => {
                self.apply_signature_result(result);
                Command::none()
            }
            Message::BroadcastDraft => self.broadcast_draft(client),
            Message::DraftBroadcast(result) => {
                self.apply_broadcast_result(result);
                Command::none()
            }
            Message::DismissError => {
                self.error_banner = None;
                Command::none()
            }
            Message::ToggleErrorDetails => {
                if let Some(banner) = &mut self.error_banner {
                    if banner.detail.is_some() {
                        banner.show_detail = !banner.show_detail;
                    }
                }
                Command::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        let mut layout = column![].spacing(16).width(Length::Fill);

        if let Some(banner) = &self.error_banner {
            layout = layout.push(self.error_banner_view(banner));
        }

        layout = layout
            .push(self.form_view())
            .push(self.preview_section())
            .push(self.draft_section())
            .push(self.signature_section())
            .push(self.broadcast_section());

        container(layout).width(Length::Fill).into()
    }

    fn form_view(&self) -> Element<Message> {
        let mut preview_button = button(text("Preview policy")).padding(12);
        if self.can_submit_preview() {
            preview_button = preview_button.on_press(Message::SubmitPreview);
        }

        let fee_controls = if self.use_estimated_fee {
            let mut preview_row = row![
                checkbox("Use estimated fee", true, |_| Message::FeeEstimateToggled(
                    false
                )),
                text_input("Confirmation target", &self.confirmation_target_input)
                    .on_input(Message::ConfirmationTargetChanged)
                    .padding(10)
                    .size(16),
            ]
            .spacing(12)
            .align_items(Alignment::Center);

            if self.fee_estimate.is_loading() {
                preview_row = preview_row.push(text("Estimating fee...").size(14));
            } else if let Some(estimate) = self.fee_estimate.as_success() {
                preview_row = preview_row.push(text(format!(
                    "Estimated rate: {} sats/vB",
                    estimate.fee_rate
                )));
            }

            preview_row
        } else {
            row![
                checkbox("Use estimated fee", false, |_| Message::FeeEstimateToggled(
                    true
                )),
                text_input("Fee rate (sats/vB)", &self.fee_rate_input)
                    .on_input(Message::FeeRateChanged)
                    .padding(10)
                    .size(16),
            ]
            .spacing(12)
            .align_items(Alignment::Center)
        };

        column![
            text_input("Recipient", &self.recipient_input)
                .on_input(Message::RecipientChanged)
                .padding(10)
                .size(16),
            text_input("Amount (sats)", &self.amount_input)
                .on_input(Message::AmountChanged)
                .padding(10)
                .size(16),
            text_input("Notes (optional)", &self.notes_input)
                .on_input(Message::NotesChanged)
                .padding(10)
                .size(16),
            fee_controls,
            preview_button,
        ]
        .spacing(12)
        .into()
    }

    fn preview_section(&self) -> Element<Message> {
        let content = match &self.policy_preview {
            RequestState::Idle => text("No policy preview requested yet.").size(16).into(),
            RequestState::Loading => text("Fetching policy preview...").size(16).into(),
            RequestState::Success(preview) => self.preview_details(preview),
            RequestState::Failure(failure) => text(&failure.summary).size(16).into(),
        };

        container(column![text("Policy preview").size(20), content].spacing(8))
            .width(Length::Fill)
            .into()
    }

    fn draft_section(&self) -> Element<Message> {
        let mut create_button = button(text("Create draft")).padding(12);
        if self.can_create_draft() {
            create_button = create_button.on_press(Message::CreateDraft);
        }

        let status = match &self.draft {
            RequestState::Idle => text("No draft created yet.").size(16).into(),
            RequestState::Loading => text("Creating draft transaction...").size(16).into(),
            RequestState::Success(draft) => self.draft_details(draft),
            RequestState::Failure(failure) => text(&failure.summary).size(16).into(),
        };

        container(
            column![
                row![text("Draft transaction").size(20), create_button.spacing(8)].spacing(16),
                status
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .into()
    }

    fn signature_section(&self) -> Element<Message> {
        let mut sign_button = button(text("Sign draft")).padding(12);
        if self.can_sign_draft() {
            sign_button = sign_button.on_press(Message::SignDraft);
        }

        let status = match &self.signature {
            RequestState::Idle => text("No signature generated yet.").size(16).into(),
            RequestState::Loading => text("Signing draft transaction...").size(16).into(),
            RequestState::Success(signature) => self.signature_details(signature),
            RequestState::Failure(failure) => text(&failure.summary).size(16).into(),
        };

        container(
            column![
                row![text("Signature").size(20), sign_button.spacing(8)].spacing(16),
                status
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .into()
    }

    fn broadcast_section(&self) -> Element<Message> {
        let mut broadcast_button = button(text("Broadcast")).padding(12);
        if self.can_broadcast_draft() {
            broadcast_button = broadcast_button.on_press(Message::BroadcastDraft);
        }

        let status = match &self.broadcast {
            RequestState::Idle => text("Transaction not broadcast.").size(16).into(),
            RequestState::Loading => text("Broadcasting transaction...").size(16).into(),
            RequestState::Success(response) => {
                let accepted = if response.accepted {
                    "Broadcast accepted"
                } else {
                    "Broadcast rejected"
                };
                text(format!("{accepted} — draft ID: {}", response.draft_id))
                    .size(16)
                    .into()
            }
            RequestState::Failure(failure) => text(&failure.summary).size(16).into(),
        };

        container(
            column![
                row![text("Broadcast").size(20), broadcast_button.spacing(8)].spacing(16),
                status
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .into()
    }

    fn preview_details(&self, preview: &PolicyPreviewResponse) -> Element<Message> {
        let hooks = preview
            .tier_hooks
            .hook
            .clone()
            .unwrap_or_else(|| "None".into());
        let spend_limit = preview
            .spend_limit_daily
            .map(|value| format!("{value} sats"))
            .unwrap_or_else(|| "Unlimited".into());

        column![
            text(format!("Min confirmations: {}", preview.min_confirmations)).size(16),
            text(format!("Dust limit: {} sats", preview.dust_limit)).size(16),
            text(format!(
                "Max change outputs: {}",
                preview.max_change_outputs
            ))
            .size(16),
            text(format!("Daily spend limit: {spend_limit}")).size(16),
            text(format!(
                "Pending lock timeout: {}s",
                preview.pending_lock_timeout
            ))
            .size(16),
            text(format!("Policy tier hook: {}", hooks)).size(16),
        ]
        .spacing(4)
        .into()
    }

    fn draft_details(&self, draft: &CreateTxResponse) -> Element<Message> {
        let change_outputs: Vec<_> = draft
            .outputs
            .iter()
            .filter(|output| output.change)
            .collect();

        let mut details = column![
            text(format!("Draft ID: {}", draft.draft_id)).size(16),
            text(format!("Fee rate: {} sats/vB", draft.fee_rate)).size(16),
            text(format!("Fee: {} sats", draft.fee)).size(16),
            text(format!(
                "Inputs: {} • Outputs: {}",
                draft.inputs.len(),
                draft.outputs.len()
            ))
            .size(16),
        ]
        .spacing(4);

        if change_outputs.is_empty() {
            details = details.push(text("No change outputs").size(16));
        } else {
            details = details.push(text("Change outputs:").size(16));
            for output in change_outputs {
                details = details.push(text(format!(
                    "• {} — {} sats",
                    output.address, output.value
                )));
            }
        }

        details.into()
    }

    fn signature_details(&self, signature: &SignTxResponse) -> Element<Message> {
        column![
            text(format!("Draft ID: {}", signature.draft_id)).size(16),
            text(format!("Backend: {}", signature.backend)).size(16),
            text(format!("Witness bytes: {}", signature.witness_bytes)).size(16),
            text(format!(
                "Proof generated: {}",
                if signature.proof_generated {
                    "Yes"
                } else {
                    "No"
                }
            ))
            .size(16),
            text(format!(
                "Proof size: {}",
                signature
                    .proof_size
                    .map(|size| format!("{} bytes", size))
                    .unwrap_or_else(|| "N/A".into())
            ))
            .size(16),
            text(format!("Prover duration: {} ms", signature.duration_ms)).size(16),
        ]
        .spacing(4)
        .into()
    }

    fn error_banner_view(&self, banner: &ErrorBanner) -> Element<Message> {
        let mut description = column![text(&banner.summary).size(16)];
        if banner.show_detail {
            if let Some(detail) = &banner.detail {
                description = description.push(text(detail).size(14));
            }
        }

        let mut actions = row![].spacing(8);
        if banner.detail.is_some() {
            let label = if banner.show_detail {
                "Hide details"
            } else {
                "View details"
            };
            actions =
                actions.push(button(text(label).size(14)).on_press(Message::ToggleErrorDetails));
        }
        actions = actions.push(button(text("Dismiss").size(14)).on_press(Message::DismissError));

        container(
            row![
                description.width(Length::Fill).spacing(8),
                actions.align_items(Alignment::Center)
            ]
            .spacing(16)
            .align_items(Alignment::Center),
        )
        .style(iced::theme::Container::Box)
        .padding(12)
        .width(Length::Fill)
        .into()
    }

    fn submit_preview(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.error_banner = None;
        let mut commands = Vec::new();

        if !self.ensure_preview_inputs_valid() {
            return Command::none();
        }

        self.policy_preview.set_loading();
        self.draft = RequestState::Idle;
        self.signature = RequestState::Idle;
        self.broadcast = RequestState::Idle;

        commands.push(commands::rpc(
            client.clone(),
            |client| async move { client.policy_preview().await },
            map_policy_preview,
        ));

        if self.use_estimated_fee {
            self.fee_estimate.set_loading();
            let target = match self.parse_confirmation_target() {
                Ok(target) => target,
                Err(failure) => {
                    self.policy_preview = RequestState::Idle;
                    self.fee_estimate = RequestState::Idle;
                    self.set_error_banner(failure);
                    return Command::none();
                }
            };

            commands.push(commands::rpc(
                client,
                move |client| async move { client.estimate_fee(target).await },
                map_fee_estimate,
            ));
        } else {
            self.fee_estimate = RequestState::Idle;
        }

        Command::batch(commands)
    }

    fn apply_policy_preview_result(&mut self, result: Result<PolicyPreviewResponse, RpcCallError>) {
        match result {
            Ok(preview) => {
                self.policy_preview.set_success(preview);
                self.error_banner = None;
            }
            Err(error) => {
                let failure = failure_from_rpc(OperationStage::PolicyPreview, &error);
                self.policy_preview.set_failure(failure.clone());
                self.set_error_banner(failure);
            }
        }
    }

    fn apply_fee_estimate_result(&mut self, result: Result<EstimateFeeResponse, RpcCallError>) {
        match result {
            Ok(estimate) => {
                self.fee_rate_input = estimate.fee_rate.to_string();
                self.fee_estimate.set_success(estimate);
                self.error_banner = None;
            }
            Err(error) => {
                let failure = failure_from_rpc(OperationStage::FeeEstimate, &error);
                self.fee_estimate.set_failure(failure.clone());
                self.set_error_banner(failure);
            }
        }
    }

    fn create_draft(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.error_banner = None;

        let params = match self.build_create_params() {
            Ok(params) => params,
            Err(failure) => {
                self.set_error_banner(failure);
                return Command::none();
            }
        };

        self.draft.set_loading();
        self.signature = RequestState::Idle;
        self.broadcast = RequestState::Idle;

        commands::rpc(
            client,
            move |client| {
                let params = params.clone();
                async move { client.create_tx(&params).await }
            },
            map_create_tx,
        )
    }

    fn apply_draft_result(&mut self, result: Result<CreateTxResponse, RpcCallError>) {
        match result {
            Ok(draft) => {
                self.draft.set_success(draft);
                self.error_banner = None;
            }
            Err(error) => {
                let failure = failure_from_rpc(OperationStage::CreateDraft, &error);
                self.draft.set_failure(failure.clone());
                self.set_error_banner(failure);
            }
        }
    }

    fn sign_draft(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.error_banner = None;
        let draft_id = match self.draft.as_success() {
            Some(draft) => draft.draft_id.clone(),
            None => return Command::none(),
        };

        self.signature.set_loading();
        self.broadcast = RequestState::Idle;

        commands::rpc(
            client,
            move |client| {
                let draft_id = draft_id.clone();
                async move { client.sign_tx(&draft_id).await }
            },
            map_sign_tx,
        )
    }

    fn apply_signature_result(&mut self, result: Result<SignTxResponse, RpcCallError>) {
        match result {
            Ok(signature) => {
                self.signature.set_success(signature);
                self.error_banner = None;
            }
            Err(error) => {
                let failure = failure_from_rpc(OperationStage::SignDraft, &error);
                self.signature.set_failure(failure.clone());
                self.set_error_banner(failure);
            }
        }
    }

    fn broadcast_draft(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.error_banner = None;
        let draft_id = match self.signature.as_success() {
            Some(signature) => signature.draft_id.clone(),
            None => return Command::none(),
        };

        self.broadcast.set_loading();

        commands::rpc(
            client,
            move |client| {
                let draft_id = draft_id.clone();
                async move { client.broadcast(&draft_id).await }
            },
            map_broadcast,
        )
    }

    fn apply_broadcast_result(&mut self, result: Result<BroadcastResponse, RpcCallError>) {
        match result {
            Ok(response) => {
                self.broadcast.set_success(response);
                self.error_banner = None;
            }
            Err(error) => {
                let failure = failure_from_rpc(OperationStage::Broadcast, &error);
                self.broadcast.set_failure(failure.clone());
                self.set_error_banner(failure);
            }
        }
    }

    fn ensure_preview_inputs_valid(&mut self) -> bool {
        if self.recipient_input.trim().is_empty() {
            self.set_error_banner(RequestFailure::new("Recipient address is required.", None));
            return false;
        }

        if self.amount_input.trim().is_empty() {
            self.set_error_banner(RequestFailure::new("Amount is required.", None));
            return false;
        }

        if self.use_estimated_fee && self.confirmation_target_input.trim().is_empty() {
            self.set_error_banner(RequestFailure::new(
                "Confirmation target is required when estimating fees.",
                None,
            ));
            return false;
        }

        true
    }

    fn build_create_params(&self) -> Result<CreateTxParams, RequestFailure> {
        let recipient = self.recipient_input.trim();
        if recipient.is_empty() {
            return Err(RequestFailure::new("Recipient address is required.", None));
        }

        let amount = self
            .amount_input
            .trim()
            .parse::<u128>()
            .map_err(|_| RequestFailure::new("Amount must be a positive integer.", None))?;
        if amount == 0 {
            return Err(RequestFailure::new(
                "Amount must be greater than zero.",
                None,
            ));
        }

        if self.fee_rate_input.trim().is_empty() {
            return Err(RequestFailure::new(
                "Fee rate must be provided before creating a draft.",
                None,
            ));
        }

        let fee_rate = self
            .fee_rate_input
            .trim()
            .parse::<u64>()
            .map_err(|_| RequestFailure::new("Fee rate must be a positive integer.", None))?;

        Ok(CreateTxParams {
            to: recipient.to_string(),
            amount,
            fee_rate: Some(fee_rate),
        })
    }

    fn parse_confirmation_target(&self) -> Result<u16, RequestFailure> {
        let target = self
            .confirmation_target_input
            .trim()
            .parse::<u16>()
            .map_err(|_| {
                RequestFailure::new("Confirmation target must be a positive integer.", None)
            })?;
        if target == 0 {
            return Err(RequestFailure::new(
                "Confirmation target must be greater than zero.",
                None,
            ));
        }
        Ok(target)
    }

    fn set_error_banner(&mut self, failure: RequestFailure) {
        self.error_banner = Some(ErrorBanner::from_failure(failure));
    }

    fn can_submit_preview(&self) -> bool {
        !self.policy_preview.is_loading()
            && !self.recipient_input.trim().is_empty()
            && !self.amount_input.trim().is_empty()
            && (!self.use_estimated_fee || !self.confirmation_target_input.trim().is_empty())
    }

    fn can_create_draft(&self) -> bool {
        self.policy_preview.is_success()
            && !self.draft.is_loading()
            && !self.recipient_input.trim().is_empty()
            && !self.amount_input.trim().is_empty()
            && !self.fee_rate_input.trim().is_empty()
    }

    fn can_sign_draft(&self) -> bool {
        self.draft.is_success() && !self.signature.is_loading()
    }

    fn can_broadcast_draft(&self) -> bool {
        self.signature.is_success() && !self.broadcast.is_loading()
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    RecipientChanged(String),
    AmountChanged(String),
    NotesChanged(String),
    FeeRateChanged(String),
    ConfirmationTargetChanged(String),
    FeeEstimateToggled(bool),
    SubmitPreview,
    PolicyPreviewLoaded(Result<PolicyPreviewResponse, RpcCallError>),
    FeeEstimateLoaded(Result<EstimateFeeResponse, RpcCallError>),
    CreateDraft,
    DraftCreated(Result<CreateTxResponse, RpcCallError>),
    SignDraft,
    DraftSigned(Result<SignTxResponse, RpcCallError>),
    BroadcastDraft,
    DraftBroadcast(Result<BroadcastResponse, RpcCallError>),
    DismissError,
    ToggleErrorDetails,
}

fn failure_from_rpc(stage: OperationStage, error: &RpcCallError) -> RequestFailure {
    match error {
        RpcCallError::Timeout(duration) => RequestFailure::new(
            format!("{} request timed out.", stage.label()),
            Some(format!(
                "No response received within {} seconds.",
                duration.as_secs()
            )),
        ),
        RpcCallError::Client(inner) => match inner {
            WalletRpcClientError::Rpc {
                code,
                message,
                details,
                ..
            } => {
                let description = describe_rpc_error(code, details.as_ref());
                let detail =
                    technical_details(message, details.as_ref()).or(description.technical.clone());
                RequestFailure::new(description.headline, detail)
            }
            other => RequestFailure::new(format!("{} failed: {}", stage.label(), other), None),
        },
    }
}

fn map_policy_preview(result: Result<PolicyPreviewResponse, RpcCallError>) -> Message {
    Message::PolicyPreviewLoaded(result)
}

fn map_fee_estimate(result: Result<EstimateFeeResponse, RpcCallError>) -> Message {
    Message::FeeEstimateLoaded(result)
}

fn map_create_tx(result: Result<CreateTxResponse, RpcCallError>) -> Message {
    Message::DraftCreated(result)
}

fn map_sign_tx(result: Result<SignTxResponse, RpcCallError>) -> Message {
    Message::DraftSigned(result)
}

fn map_broadcast(result: Result<BroadcastResponse, RpcCallError>) -> Message {
    Message::DraftBroadcast(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::wallet::PolicyTierHooks;
    use crate::rpc::error::WalletRpcErrorCode;
    use std::time::Duration;

    fn dummy_client() -> WalletRpcClient {
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, Duration::from_secs(1)).unwrap()
    }

    fn sample_preview() -> PolicyPreviewResponse {
        PolicyPreviewResponse {
            min_confirmations: 1,
            dust_limit: 500,
            max_change_outputs: 2,
            spend_limit_daily: Some(1_000_000),
            pending_lock_timeout: 120,
            tier_hooks: PolicyTierHooks {
                enabled: true,
                hook: Some("audit".into()),
            },
        }
    }

    fn sample_draft() -> CreateTxResponse {
        CreateTxResponse {
            draft_id: "draft-1".into(),
            fee_rate: 25,
            fee: 1_500,
            fee_source: None,
            total_input_value: 100_000,
            total_output_value: 98_500,
            spend_model: crate::rpc::dto::DraftSpendModelDto::Exact { amount: 1_500 },
            inputs: Vec::new(),
            outputs: Vec::new(),
            locks: Vec::new(),
        }
    }

    fn sample_signature() -> SignTxResponse {
        SignTxResponse {
            draft_id: "draft-1".into(),
            backend: "mock".into(),
            witness_bytes: 128,
            proof_generated: true,
            proof_size: Some(256),
            duration_ms: 1_500,
            locks: Vec::new(),
        }
    }

    #[test]
    fn preview_submission_sets_loading_and_resets_pipeline() {
        let mut state = State::default();
        state.recipient_input = "addr1".into();
        state.amount_input = "1000".into();
        state.use_estimated_fee = false;

        let _command = state.update(dummy_client(), Message::SubmitPreview);
        assert!(matches!(state.policy_preview, RequestState::Loading));
        assert!(matches!(state.draft, RequestState::Idle));
        assert!(matches!(state.signature, RequestState::Idle));
        assert!(matches!(state.broadcast, RequestState::Idle));
    }

    #[test]
    fn successful_preview_enables_draft_creation() {
        let mut state = State::default();
        state.recipient_input = "addr1".into();
        state.amount_input = "1000".into();
        state.fee_rate_input = "10".into();
        state.policy_preview = RequestState::Success(sample_preview());

        assert!(state.can_create_draft());
    }

    #[test]
    fn draft_error_surfaces_banner() {
        let mut state = State::default();
        state.recipient_input = "addr1".into();
        state.amount_input = "1000".into();
        state.fee_rate_input = "10".into();
        state.policy_preview = RequestState::Success(sample_preview());

        let error = RpcCallError::Client(WalletRpcClientError::Rpc {
            code: WalletRpcErrorCode::FeeTooLow,
            message: "fee too low".into(),
            json_code: WalletRpcErrorCode::FeeTooLow.as_i32(),
            details: None,
        });
        state.apply_draft_result(Err(error));

        let banner = state.error_banner.expect("error banner set");
        assert_eq!(
            banner.summary,
            "Fee rate is too low for network acceptance."
        );
    }

    #[test]
    fn signature_success_enables_broadcast() {
        let mut state = State::default();
        state.signature = RequestState::Success(sample_signature());
        assert!(state.can_broadcast_draft());
    }

    #[test]
    fn fee_estimate_error_disables_create_until_resolved() {
        let mut state = State::default();
        state.recipient_input = "addr1".into();
        state.amount_input = "1000".into();
        state.use_estimated_fee = true;
        state.confirmation_target_input = "6".into();

        let error = RpcCallError::Timeout(Duration::from_secs(5));
        state.apply_fee_estimate_result(Err(error));

        assert!(state.fee_rate_input.is_empty());
        assert!(!state.can_create_draft());
        assert!(state.error_banner.is_some());
    }
}
