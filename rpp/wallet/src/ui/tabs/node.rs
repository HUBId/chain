use iced::widget::{button, column, container, row, text, text_input, Column, Rule};
use iced::{Alignment, Command, Element, Length};

use crate::config::WalletConfig;
use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};
use crate::rpc::dto::{
    BlockFeeSummaryDto, ListPendingLocksResponse, MempoolInfoResponse, PendingLockDto,
    RecentBlocksResponse, ReleasePendingLocksResponse, RescanParams, RescanResponse, SyncModeDto,
    SyncStatusResponse, TelemetryCountersResponse,
};
#[cfg(feature = "wallet_zsi")]
use crate::rpc::dto::{
    ZsiArtifactDto, ZsiBindResponse, ZsiBindingDto, ZsiDeleteParams, ZsiDeleteResponse,
    ZsiListResponse, ZsiProofParams,
};

use crate::telemetry::TelemetryOutcome;
use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::{modal, ConfirmDialog};
use crate::ui::error_map::{describe_rpc_error, technical_details};
use crate::ui::telemetry;
#[cfg(feature = "wallet_zsi")]
use crate::ui::telemetry::ZsiAction;
#[cfg(feature = "wallet_zsi")]
use crate::zsi::bind::ZsiOperation;
#[cfg(feature = "wallet_zsi")]
use crate::zsi::lifecycle::{ConsensusApproval, ZsiRecord};

#[cfg(feature = "wallet_zsi")]
use hex::encode as hex_encode;

#[cfg(feature = "wallet_hw")]
use crate::rpc::dto::{HardwareDeviceDto, HardwareEnumerateResponse};
#[cfg(feature = "wallet_hw")]
use crate::ui::telemetry::HardwareAction;

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

#[cfg(feature = "wallet_zsi")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZsiBindField {
    Identity,
    Genesis,
    Attestation,
    Approvals,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Debug, Default, Clone)]
struct ZsiBindingForm {
    operation: ZsiOperation,
    identity: String,
    genesis_id: String,
    attestation_digest: String,
    approvals_json: String,
    error: Option<String>,
}

#[cfg(feature = "wallet_zsi")]
impl ZsiBindingForm {
    fn reset(&mut self) {
        self.operation = ZsiOperation::Issue;
        self.identity.clear();
        self.genesis_id.clear();
        self.attestation_digest.clear();
        self.approvals_json.clear();
        self.error = None;
    }

    fn update_field(&mut self, field: ZsiBindField, value: String) {
        match field {
            ZsiBindField::Identity => self.identity = value,
            ZsiBindField::Genesis => self.genesis_id = value,
            ZsiBindField::Attestation => self.attestation_digest = value,
            ZsiBindField::Approvals => self.approvals_json = value,
        }
        self.error = None;
    }

    fn cycle_operation(&mut self) {
        self.operation = next_operation(self.operation);
    }

    fn build_params(&self) -> Result<ZsiProofParams, String> {
        let identity = self.identity.trim();
        if identity.is_empty() {
            return Err("Identity is required".into());
        }

        let genesis_id = self.genesis_id.trim();
        if genesis_id.is_empty() {
            return Err("Genesis commitment is required".into());
        }

        let attestation = self.attestation_digest.trim();
        if attestation.is_empty() {
            return Err("Attestation digest is required".into());
        }

        let approvals = if self.approvals_json.trim().is_empty() {
            Vec::<ConsensusApproval>::new()
        } else {
            serde_json::from_str::<Vec<ConsensusApproval>>(&self.approvals_json)
                .map_err(|err| format!("Invalid approvals JSON: {err}"))?
        };

        Ok(ZsiProofParams {
            operation: self.operation,
            record: ZsiRecord {
                identity: identity.to_string(),
                genesis_id: genesis_id.to_string(),
                attestation_digest: attestation.to_string(),
                approvals,
            },
        })
    }
}

#[cfg(feature = "wallet_zsi")]
#[derive(Debug, Clone)]
enum ZsiModal {
    BindConfirm(ZsiProofParams),
    DeleteConfirm {
        identity: String,
        commitment: String,
    },
}

#[derive(Debug, Default)]
pub struct State {
    config: Option<WalletConfig>,
    sync_status: Option<SyncStatusResponse>,
    mempool_info: Snapshot<MempoolInfoResponse>,
    recent_blocks: Snapshot<Vec<BlockFeeSummaryDto>>,
    pending_locks: Snapshot<Vec<PendingLockDto>>,
    telemetry: Snapshot<TelemetryCountersResponse>,
    #[cfg(feature = "wallet_zsi")]
    zsi_artifacts: Snapshot<Vec<ZsiArtifactDto>>,
    #[cfg(feature = "wallet_zsi")]
    zsi_bind_form: ZsiBindingForm,
    #[cfg(feature = "wallet_zsi")]
    zsi_binding: Option<ZsiBindingDto>,
    #[cfg(feature = "wallet_zsi")]
    zsi_op_inflight: bool,
    #[cfg(feature = "wallet_zsi")]
    zsi_feedback: Option<String>,
    #[cfg(feature = "wallet_zsi")]
    zsi_error: Option<String>,
    #[cfg(feature = "wallet_zsi")]
    zsi_modal: Option<ZsiModal>,
    #[cfg(feature = "wallet_hw")]
    hardware_devices: Snapshot<Vec<HardwareDeviceDto>>,
    #[cfg(feature = "wallet_hw")]
    hardware_inflight: bool,
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
    #[cfg(feature = "wallet_zsi")]
    RefreshZsi,
    #[cfg(feature = "wallet_zsi")]
    ZsiArtifactsLoaded(Result<Vec<ZsiArtifactDto>, RpcCallError>),
    #[cfg(feature = "wallet_zsi")]
    ZsiBindFieldChanged(ZsiBindField, String),
    #[cfg(feature = "wallet_zsi")]
    CycleZsiOperation,
    #[cfg(feature = "wallet_zsi")]
    SubmitZsiBind,
    #[cfg(feature = "wallet_zsi")]
    ConfirmZsiBind,
    #[cfg(feature = "wallet_zsi")]
    CancelZsiAction,
    #[cfg(feature = "wallet_zsi")]
    ZsiBindCompleted(Result<ZsiBindResponse, RpcCallError>),
    #[cfg(feature = "wallet_zsi")]
    RequestZsiDelete {
        identity: String,
        commitment: String,
    },
    #[cfg(feature = "wallet_zsi")]
    ConfirmZsiDelete,
    #[cfg(feature = "wallet_zsi")]
    ZsiDeleteCompleted(Result<ZsiDeleteResponse, RpcCallError>),
    #[cfg(feature = "wallet_zsi")]
    DismissZsiFeedback,
    #[cfg(feature = "wallet_hw")]
    HardwareDevicesLoaded(Result<Vec<HardwareDeviceDto>, RpcCallError>),
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
        #[cfg(feature = "wallet_zsi")]
        {
            self.zsi_artifacts = Snapshot::Idle;
            self.zsi_bind_form = ZsiBindingForm::default();
            self.zsi_binding = None;
            self.zsi_op_inflight = false;
            self.zsi_feedback = None;
            self.zsi_error = None;
            self.zsi_modal = None;
        }
        #[cfg(feature = "wallet_hw")]
        {
            self.hardware_devices = Snapshot::Idle;
            self.hardware_inflight = false;
        }
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
        #[cfg(feature = "wallet_hw")]
        if !self.hardware_config_enabled() {
            self.hardware_devices = Snapshot::Idle;
            self.hardware_inflight = false;
        }
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
            #[cfg(feature = "wallet_zsi")]
            Message::RefreshZsi => {
                if !self.zsi_enabled() {
                    return Command::none();
                }
                self.load_zsi_artifacts(client)
            }
            #[cfg(feature = "wallet_zsi")]
            Message::ZsiArtifactsLoaded(result) => {
                match result {
                    Ok(artifacts) => {
                        telemetry::global().record_zsi_outcome(
                            ZsiAction::ListArtifacts,
                            TelemetryOutcome::Success,
                        );
                        self.zsi_artifacts.set_loaded(artifacts)
                    }
                    Err(error) => {
                        telemetry::global()
                            .record_zsi_outcome(ZsiAction::ListArtifacts, TelemetryOutcome::Error);
                        self.zsi_artifacts.set_error(&error)
                    }
                }
                self.finish_refresh();
                Command::none()
            }
            #[cfg(feature = "wallet_zsi")]
            Message::ZsiBindFieldChanged(field, value) => {
                self.zsi_bind_form.update_field(field, value);
                Command::none()
            }
            #[cfg(feature = "wallet_zsi")]
            Message::CycleZsiOperation => {
                self.zsi_bind_form.cycle_operation();
                Command::none()
            }
            #[cfg(feature = "wallet_zsi")]
            Message::SubmitZsiBind => {
                if self.zsi_op_inflight {
                    return Command::none();
                }
                match self.zsi_bind_form.build_params() {
                    Ok(params) => {
                        self.zsi_modal = Some(ZsiModal::BindConfirm(params));
                        self.zsi_bind_form.error = None;
                    }
                    Err(error) => {
                        self.zsi_bind_form.error = Some(error);
                    }
                }
                Command::none()
            }
            #[cfg(feature = "wallet_zsi")]
            Message::ConfirmZsiBind => {
                if self.zsi_op_inflight {
                    return Command::none();
                }
                let Some(ZsiModal::BindConfirm(params)) = self.zsi_modal.take() else {
                    return Command::none();
                };
                self.zsi_op_inflight = true;
                self.zsi_feedback = None;
                self.zsi_error = None;
                commands::rpc(
                    "zsi.bind_account",
                    client,
                    move |client| async move { client.zsi_bind_account(&params).await },
                    Message::ZsiBindCompleted,
                )
            }
            #[cfg(feature = "wallet_zsi")]
            Message::CancelZsiAction => {
                self.zsi_modal = None;
                Command::none()
            }
            #[cfg(feature = "wallet_zsi")]
            Message::ZsiBindCompleted(result) => {
                self.zsi_op_inflight = false;
                match result {
                    Ok(response) => {
                        telemetry::global()
                            .record_zsi_outcome(ZsiAction::BindAccount, TelemetryOutcome::Success);
                        self.zsi_binding = Some(response.binding);
                        self.zsi_bind_form.reset();
                        self.zsi_feedback = Some("Generated account binding witness.".into());
                        Command::none()
                    }
                    Err(error) => {
                        telemetry::global()
                            .record_zsi_outcome(ZsiAction::BindAccount, TelemetryOutcome::Error);
                        self.zsi_error = Some(format_rpc_error(&error));
                        Command::none()
                    }
                }
            }
            #[cfg(feature = "wallet_zsi")]
            Message::RequestZsiDelete {
                identity,
                commitment,
            } => {
                if self.zsi_op_inflight {
                    return Command::none();
                }
                self.zsi_modal = Some(ZsiModal::DeleteConfirm {
                    identity,
                    commitment,
                });
                Command::none()
            }
            #[cfg(feature = "wallet_zsi")]
            Message::ConfirmZsiDelete => {
                if self.zsi_op_inflight {
                    return Command::none();
                }
                let Some(ZsiModal::DeleteConfirm {
                    identity,
                    commitment,
                }) = self.zsi_modal.take()
                else {
                    return Command::none();
                };
                self.zsi_op_inflight = true;
                self.zsi_feedback = None;
                self.zsi_error = None;
                commands::rpc(
                    "zsi.delete",
                    client,
                    move |client| async move {
                        client
                            .zsi_delete(&ZsiDeleteParams {
                                identity,
                                commitment_digest: commitment,
                            })
                            .await
                    },
                    Message::ZsiDeleteCompleted,
                )
            }
            #[cfg(feature = "wallet_zsi")]
            Message::ZsiDeleteCompleted(result) => {
                self.zsi_op_inflight = false;
                match result {
                    Ok(response) => {
                        telemetry::global().record_zsi_outcome(
                            ZsiAction::DeleteArtifact,
                            TelemetryOutcome::Success,
                        );
                        if response.deleted {
                            self.zsi_feedback = Some("Deleted stored Zero Sync artifact.".into());
                        } else {
                            self.zsi_feedback = Some(
                                "No Zero Sync artifact matched the provided commitment.".into(),
                            );
                        }
                        if self.zsi_enabled() {
                            return self.load_zsi_artifacts(client);
                        }
                        Command::none()
                    }
                    Err(error) => {
                        telemetry::global()
                            .record_zsi_outcome(ZsiAction::DeleteArtifact, TelemetryOutcome::Error);
                        self.zsi_error = Some(format_rpc_error(&error));
                        Command::none()
                    }
                }
            }
            #[cfg(feature = "wallet_zsi")]
            Message::DismissZsiFeedback => {
                self.zsi_feedback = None;
                self.zsi_error = None;
                Command::none()
            }
            #[cfg(feature = "wallet_hw")]
            Message::HardwareDevicesLoaded(result) => {
                match result {
                    Ok(devices) => {
                        telemetry::global().record_hardware_outcome(
                            HardwareAction::Enumerate,
                            TelemetryOutcome::Success,
                        );
                        self.hardware_devices.set_loaded(devices)
                    }
                    Err(error) => {
                        telemetry::global().record_hardware_outcome(
                            HardwareAction::Enumerate,
                            TelemetryOutcome::Error,
                        );
                        self.hardware_devices.set_error(&error)
                    }
                }
                self.hardware_inflight = false;
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
        #[cfg(feature = "wallet_zsi")]
        if let Some(modal_state) = &self.zsi_modal {
            let dialog = match modal_state {
                ZsiModal::BindConfirm(params) => {
                    let approvals = params.record.approvals.len();
                    let body = format!(
                        "Generate binding witness for operation {} on identity {}?\nGenesis commitment: {}\nAttestation digest: {}\nApprovals: {}",
                        params.operation.as_str(),
                        params.record.identity,
                        params.record.genesis_id,
                        params.record.attestation_digest,
                        approvals
                    );
                    ConfirmDialog {
                        title: "Generate account binding",
                        body,
                        confirm_label: "Generate",
                        cancel_label: "Cancel",
                        on_confirm: Message::ConfirmZsiBind,
                        on_cancel: Message::CancelZsiAction,
                    }
                }
                ZsiModal::DeleteConfirm {
                    identity,
                    commitment,
                } => {
                    let body = format!(
                        "Delete stored proof for identity {identity}?\nCommitment digest: {commitment}"
                    );
                    ConfirmDialog {
                        title: "Delete Zero Sync proof",
                        body,
                        confirm_label: "Delete",
                        cancel_label: "Cancel",
                        on_confirm: Message::ConfirmZsiDelete,
                        on_cancel: Message::CancelZsiAction,
                    }
                }
            };
            return modal(column![dialog.view()]);
        }

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
            .push(self.zsi_section())
            .push(Rule::horizontal(1))
            .push(self.pending_locks_view())
            .push(Rule::horizontal(1))
            .push(self.hardware_section())
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

        let top = row![sync_card, mempool_card, telemetry_card]
            .spacing(16)
            .width(Length::Fill);

        let mut bottom = row![self.zsi_summary_card(), self.prover_summary_card()]
            .spacing(16)
            .width(Length::Fill);

        bottom = bottom.push(self.hardware_summary_card());

        column![top, bottom].spacing(16).width(Length::Fill).into()
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

    #[cfg(feature = "wallet_zsi")]
    fn zsi_summary_card(&self) -> Element<Message> {
        let lines = if !self.zsi_enabled() {
            vec!["Zero Sync disabled".into()]
        } else {
            match &self.zsi_artifacts {
                Snapshot::Idle => vec!["Awaiting artifact snapshot".into()],
                Snapshot::Loading => vec!["Loading artifacts...".into()],
                Snapshot::Error(error) => vec![format!("Error: {error}")],
                Snapshot::Loaded(artifacts) => {
                    let mut lines = vec![format!("Stored artifacts: {}", artifacts.len())];
                    if let Some(latest) = artifacts.last() {
                        lines.push(format!("Latest identity: {}", latest.identity));
                    }
                    lines
                }
            }
        };

        summary_card("Zero Sync", column_from(lines))
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn zsi_summary_card(&self) -> Element<Message> {
        summary_card(
            "Zero Sync",
            column![text("Zero Sync features are unavailable in this build.")],
        )
    }

    fn prover_summary_card(&self) -> Element<Message> {
        if let Some(config) = &self.config {
            let prover = &config.prover;
            let backend = if prover.enabled {
                prover.backend.as_str().to_string()
            } else {
                "disabled".into()
            };
            let lines = vec![
                format!("Enabled: {}", format_bool(prover.enabled)),
                format!("Backend: {}", backend),
                format!("Require proof: {}", format_bool(prover.require_proof)),
                format!(
                    "Allow broadcast without proof: {}",
                    format_bool(prover.allow_broadcast_without_proof)
                ),
                format!("Timeout: {}s", prover.timeout_secs),
            ];
            summary_card("Prover", column_from(lines))
        } else {
            summary_card("Prover", column![text("Configuration unavailable")])
        }
    }

    fn hardware_summary_card(&self) -> Element<Message> {
        #[cfg(feature = "wallet_hw")]
        {
            if !self.hardware_config_enabled() {
                return summary_card(
                    "Hardware",
                    column![text("Hardware wallet support disabled in configuration.")],
                );
            }
            let body = match &self.hardware_devices {
                Snapshot::Idle => column![text("Enumeration pending")],
                Snapshot::Loading => column![text("Enumerating devices...")],
                Snapshot::Error(error) => column![text(format!("Error: {error}"))],
                Snapshot::Loaded(devices) => {
                    if devices.is_empty() {
                        column![text("No devices detected")]
                    } else {
                        let mut lines = Vec::new();
                        lines.push(format!("Devices: {}", devices.len()));
                        if let Some(first) = devices.first() {
                            let label = first.label.clone().unwrap_or_else(|| "(no label)".into());
                            lines.push(format!("First device: {}", label));
                        }
                        column_from(lines)
                    }
                }
            };
            summary_card("Hardware", body)
        }
        #[cfg(not(feature = "wallet_hw"))]
        {
            summary_card(
                "Hardware",
                column![text("Hardware wallet support not available in this build.")],
            )
        }
    }

    #[cfg(feature = "wallet_zsi")]
    fn zsi_section(&self) -> Element<Message> {
        let mut header = row![text("Zero Sync artifacts").size(18)]
            .spacing(8)
            .align_items(Alignment::Center);
        if self.zsi_enabled() {
            let mut refresh = button(text("Refresh")).padding(8);
            if !matches!(self.zsi_artifacts, Snapshot::Loading) && !self.zsi_op_inflight {
                refresh = refresh.on_press(Message::RefreshZsi);
            }
            header = header.push(refresh);
        } else {
            header = header.push(text("Disabled in configuration").size(14));
        }

        let mut section = column![header, self.zsi_artifacts_view()]
            .spacing(12)
            .width(Length::Fill);

        if let Some(binding) = &self.zsi_binding {
            section = section.push(zsi_binding_view(binding));
        }

        section = section.push(self.zsi_bind_form_view());

        if let Some(feedback) = &self.zsi_feedback {
            section = section.push(text(feedback).size(16));
        }
        if let Some(error) = &self.zsi_error {
            section = section.push(text(error).size(16));
        }
        if self.zsi_feedback.is_some() || self.zsi_error.is_some() {
            let dismiss = button(text("Dismiss message")).padding(8);
            section = section.push(dismiss.on_press(Message::DismissZsiFeedback));
        }

        container(section).width(Length::Fill).into()
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn zsi_section(&self) -> Element<Message> {
        container(
            column![
                text("Zero Sync artifacts").size(18),
                text("This build was compiled without Zero Sync support."),
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .into()
    }

    #[cfg(feature = "wallet_zsi")]
    fn zsi_artifacts_view(&self) -> Element<Message> {
        match &self.zsi_artifacts {
            Snapshot::Idle => container(text("Zero Sync artifacts have not been loaded yet."))
                .width(Length::Fill)
                .into(),
            Snapshot::Loading => container(text("Loading Zero Sync artifacts..."))
                .width(Length::Fill)
                .into(),
            Snapshot::Error(error) => {
                container(text(format!("Unable to load Zero Sync artifacts: {error}")))
                    .width(Length::Fill)
                    .into()
            }
            Snapshot::Loaded(artifacts) => {
                if artifacts.is_empty() {
                    container(text("No stored Zero Sync artifacts were found."))
                        .width(Length::Fill)
                        .into()
                } else {
                    let entries = artifacts.iter().fold(column![], |column, artifact| {
                        column.push(zsi_artifact_entry(artifact, self.zsi_op_inflight))
                    });
                    container(entries.spacing(8)).width(Length::Fill).into()
                }
            }
        }
    }

    #[cfg(feature = "wallet_zsi")]
    fn zsi_bind_form_view(&self) -> Element<Message> {
        let mut operation_button = button(text(format!(
            "Operation: {}",
            self.zsi_bind_form.operation.as_str()
        )))
        .padding(8);
        if !self.zsi_op_inflight {
            operation_button = operation_button.on_press(Message::CycleZsiOperation);
        }

        let identity_input = text_input("Identity", &self.zsi_bind_form.identity)
            .on_input(|value| Message::ZsiBindFieldChanged(ZsiBindField::Identity, value))
            .padding(10)
            .size(16);
        let genesis_input = text_input("Genesis commitment", &self.zsi_bind_form.genesis_id)
            .on_input(|value| Message::ZsiBindFieldChanged(ZsiBindField::Genesis, value))
            .padding(10)
            .size(16);
        let attestation_input =
            text_input("Attestation digest", &self.zsi_bind_form.attestation_digest)
                .on_input(|value| Message::ZsiBindFieldChanged(ZsiBindField::Attestation, value))
                .padding(10)
                .size(16);
        let approvals_input = text_input("Approvals JSON", &self.zsi_bind_form.approvals_json)
            .on_input(|value| Message::ZsiBindFieldChanged(ZsiBindField::Approvals, value))
            .padding(10)
            .size(16);

        let mut submit = button(text("Generate binding witness")).padding(12);
        if self.zsi_enabled() && !self.zsi_op_inflight {
            submit = submit.on_press(Message::SubmitZsiBind);
        }

        let mut form = column![
            text("Generate binding witness").size(18),
            row![operation_button].spacing(8),
            identity_input,
            genesis_input,
            attestation_input,
            approvals_input,
            text("Approvals should be provided as a JSON array (optional)").size(14),
            submit,
        ]
        .spacing(8)
        .width(Length::Fill);

        if !self.zsi_enabled() {
            form = form.push(
                text("Enable Zero Sync support in the wallet configuration to generate bindings.")
                    .size(14),
            );
        }

        if let Some(error) = &self.zsi_bind_form.error {
            form = form.push(text(error).size(14));
        }

        container(form).width(Length::Fill).into()
    }

    #[cfg(feature = "wallet_hw")]
    fn hardware_section(&self) -> Element<Message> {
        let header = row![text("Hardware devices").size(18)]
            .spacing(8)
            .align_items(Alignment::Center);

        let body: Column<Message> = if !self.hardware_config_enabled() {
            column![text("Hardware wallet support disabled in configuration.")]
        } else {
            match &self.hardware_devices {
                Snapshot::Idle => column![text("Hardware enumeration not requested yet.")],
                Snapshot::Loading => column![text("Enumerating connected hardware wallets...")],
                Snapshot::Error(error) => column![text(format!(
                    "Unable to enumerate hardware devices: {error}"
                ))],
                Snapshot::Loaded(devices) => {
                    if devices.is_empty() {
                        column![text("No hardware wallets detected.".to_string())]
                    } else {
                        let entries = devices.iter().fold(column![], |column, device| {
                            column.push(hardware_device_entry(device))
                        });
                        entries.spacing(4)
                    }
                }
            }
        };

        container(column![header, body.spacing(8)].spacing(12))
            .width(Length::Fill)
            .into()
    }

    #[cfg(not(feature = "wallet_hw"))]
    fn hardware_section(&self) -> Element<Message> {
        container(
            column![
                text("Hardware devices").size(18),
                text("This build was compiled without hardware wallet support."),
            ]
            .spacing(8),
        )
        .width(Length::Fill)
        .into()
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
        let backend = if prover.enabled {
            prover.backend.as_str().to_string()
        } else {
            "disabled".into()
        };
        let lines = [
            format!("Enabled: {}", format_bool(prover.enabled)),
            format!("Backend: {}", backend),
            format!("Require proof: {}", format_bool(prover.require_proof)),
            format!(
                "Allow broadcast without proof: {}",
                format_bool(prover.allow_broadcast_without_proof)
            ),
            format!("Timeout: {}s", prover.timeout_secs),
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

        #[cfg(feature = "wallet_zsi")]
        {
            if self.zsi_enabled() {
                self.zsi_artifacts.set_loading();
                self.refresh_pending += 1;
                commands.push(commands::rpc(
                    "zsi.list",
                    client.clone(),
                    |client| async move { client.zsi_list().await },
                    map_zsi_artifacts,
                ));
            } else {
                self.zsi_artifacts = Snapshot::Loaded(Vec::new());
            }
        }

        self.telemetry.set_loading();
        self.refresh_pending += 1;
        commands.push(commands::rpc(
            "telemetry_counters",
            client.clone(),
            |client| async move { client.telemetry_counters().await },
            Message::TelemetryLoaded,
        ));

        #[cfg(feature = "wallet_hw")]
        {
            if self.hardware_config_enabled() {
                self.hardware_devices.set_loading();
                self.hardware_inflight = true;
                self.refresh_pending += 1;
                commands.push(commands::rpc(
                    "hw.enumerate",
                    client,
                    |client| async move { client.hw_enumerate().await },
                    map_hardware_devices,
                ));
            } else {
                self.hardware_devices = Snapshot::Idle;
                self.hardware_inflight = false;
            }
        }

        Command::batch(commands)
    }

    #[cfg(feature = "wallet_zsi")]
    fn load_zsi_artifacts(&mut self, client: WalletRpcClient) -> Command<Message> {
        if matches!(self.zsi_artifacts, Snapshot::Loading) {
            return Command::none();
        }
        self.zsi_artifacts.set_loading();
        self.zsi_error = None;
        commands::rpc(
            "zsi.list",
            client,
            |client| async move { client.zsi_list().await },
            map_zsi_artifacts,
        )
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

    #[cfg(feature = "wallet_zsi")]
    fn zsi_enabled(&self) -> bool {
        cfg!(feature = "wallet_zsi")
            && self
                .config
                .as_ref()
                .map(|config| config.zsi.enabled)
                .unwrap_or(false)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn zsi_enabled(&self) -> bool {
        false
    }

    #[cfg(feature = "wallet_hw")]
    fn hardware_config_enabled(&self) -> bool {
        self.config
            .as_ref()
            .map(|config| config.hw.enabled)
            .unwrap_or(false)
    }
}

fn map_pending_locks(result: Result<ListPendingLocksResponse, RpcCallError>) -> Message {
    Message::PendingLocksLoaded(result.map(|response| response.locks))
}

fn map_recent_blocks(result: Result<RecentBlocksResponse, RpcCallError>) -> Message {
    Message::RecentBlocksLoaded(result.map(|response| response.blocks))
}

#[cfg(feature = "wallet_zsi")]
fn map_zsi_artifacts(result: Result<ZsiListResponse, RpcCallError>) -> Message {
    Message::ZsiArtifactsLoaded(result.map(|response| response.artifacts))
}

#[cfg(feature = "wallet_hw")]
fn map_hardware_devices(result: Result<HardwareEnumerateResponse, RpcCallError>) -> Message {
    Message::HardwareDevicesLoaded(result.map(|response| response.devices))
}

fn column_from(lines: Vec<String>) -> Column<'static, Message> {
    lines
        .into_iter()
        .fold(column![], |column, line| column.push(text(line)))
}

#[cfg(feature = "wallet_zsi")]
fn zsi_artifact_entry(artifact: &ZsiArtifactDto, op_inflight: bool) -> Element<Message> {
    let mut delete = button(text("Delete")).padding(8);
    if !op_inflight {
        delete = delete.on_press(Message::RequestZsiDelete {
            identity: artifact.identity.clone(),
            commitment: artifact.commitment_digest.clone(),
        });
    }

    column![
        row![
            text(format!("Identity: {}", artifact.identity)).width(Length::FillPortion(3)),
            text(format!("Backend: {}", artifact.backend)).width(Length::FillPortion(2)),
            text(format!("Recorded at: {}", artifact.recorded_at_ms)).width(Length::FillPortion(2)),
        ]
        .spacing(8),
        row![
            text(format!("Commitment: {}", artifact.commitment_digest))
                .width(Length::FillPortion(5)),
            text(format!("Proof bytes: {}", artifact.proof.len())).width(Length::FillPortion(2)),
            delete,
        ]
        .spacing(8)
        .align_items(Alignment::Center),
    ]
    .spacing(4)
    .into()
}

#[cfg(feature = "wallet_zsi")]
fn zsi_binding_view(binding: &ZsiBindingDto) -> Element<Message> {
    let mut lines = vec![
        format!("Operation: {}", binding.operation.as_str()),
        format!("Identity: {}", binding.record.identity),
        format!("Genesis commitment: {}", binding.record.genesis_id),
        format!("Attestation digest: {}", binding.record.attestation_digest),
        format!("Approvals recorded: {}", binding.record.approvals.len()),
        format!("Witness bytes: {}", binding.witness.len()),
        format!(
            "Wallet address digest: {}",
            hex_encode(binding.inputs.wallet_address)
        ),
        format!(
            "Identity root digest: {}",
            hex_encode(binding.inputs.identity_root)
        ),
        format!(
            "State root digest: {}",
            hex_encode(binding.inputs.state_root)
        ),
    ];
    if !binding.inputs.vrf_tag.is_empty() {
        lines.push(format!("VRF tag: {}", hex_encode(&binding.inputs.vrf_tag)));
    }

    container(
        column![
            text("Generated binding summary").size(16),
            column_from(lines).spacing(4)
        ]
        .spacing(8),
    )
    .width(Length::Fill)
    .style(iced::theme::Container::Box)
    .padding(12)
    .into()
}

#[cfg(feature = "wallet_hw")]
fn hardware_device_entry(device: &HardwareDeviceDto) -> Element<Message> {
    let label = device
        .label
        .clone()
        .unwrap_or_else(|| "Unnamed device".to_string());
    container(
        column![
            text(format!("Fingerprint: {}", device.fingerprint)),
            text(format!("Model: {}", device.model)),
            text(format!("Label: {label}")),
        ]
        .spacing(4),
    )
    .width(Length::Fill)
    .style(iced::theme::Container::Box)
    .padding(8)
    .into()
}

#[cfg(feature = "wallet_zsi")]
fn next_operation(current: ZsiOperation) -> ZsiOperation {
    match current {
        ZsiOperation::Issue => ZsiOperation::Rotate,
        ZsiOperation::Rotate => ZsiOperation::Revoke,
        ZsiOperation::Revoke => ZsiOperation::Audit,
        ZsiOperation::Audit => ZsiOperation::Issue,
    }
}

fn lock_row(lock: &PendingLockDto) -> Element<Message> {
    let status = lock
        .spending_txid
        .as_ref()
        .map(|txid| format!("spending {txid}"))
        .unwrap_or_else(|| "available".into());
    let proof_summary = format!(
        "req {} / has {}",
        bool_label(lock.proof_required),
        bool_label(lock.proof_present)
    );
    let proof_hash = lock.proof_hash.as_deref().unwrap_or("-").to_string();
    row![
        text(format!("{}:{}", lock.utxo_txid, lock.utxo_index)).width(Length::FillPortion(3)),
        text(lock.locked_at_ms.to_string()).width(Length::FillPortion(2)),
        text(&lock.backend).width(Length::FillPortion(2)),
        text(status).width(Length::FillPortion(3)),
        text(proof_summary).width(Length::FillPortion(2)),
        text(proof_hash).width(Length::FillPortion(3)),
    ]
    .spacing(12)
    .align_items(Alignment::Center)
    .into()
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
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
        RpcCallError::Client(WalletRpcClientError::Rpc {
            code,
            message,
            details,
            ..
        }) => {
            let description = describe_rpc_error(code, details.as_ref());
            let mut headline = description.headline;
            if let Some(detail) = description.technical {
                headline = format!("{headline} — {detail}");
            }
            if let Some(extra) = technical_details(message, details.as_ref()) {
                format!("{headline} ({extra})")
            } else {
                headline
            }
        }
        RpcCallError::Client(inner) => inner.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::rpc::client::WalletRpcClientError;
    use crate::rpc::error::WalletRpcErrorCode;
    #[cfg(feature = "wallet_zsi")]
    use crate::zsi::bind::ZsiOperation;
    #[cfg(feature = "wallet_zsi")]
    use crate::zsi::lifecycle::ZsiRecord;

    fn dummy_client() -> WalletRpcClient {
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, None, Duration::from_secs(1))
            .unwrap()
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

    #[cfg(feature = "wallet_zsi")]
    #[test]
    fn zsi_bind_requires_confirmation() {
        let mut state = State::default();
        state.zsi_bind_form.identity = "alice".into();
        state.zsi_bind_form.genesis_id = "genesis".into();
        state.zsi_bind_form.attestation_digest = "attest".into();
        let command = state.update(dummy_client(), Message::SubmitZsiBind);
        assert!(matches!(state.zsi_modal, Some(ZsiModal::BindConfirm(_))));
        assert!(command.actions().is_empty());
    }

    #[cfg(feature = "wallet_zsi")]
    #[test]
    fn zsi_bind_blocks_duplicates() {
        let mut state = State::default();
        let record = ZsiRecord {
            identity: "alice".into(),
            genesis_id: "genesis".into(),
            attestation_digest: "attest".into(),
            approvals: Vec::new(),
        };
        let params = ZsiProofParams {
            operation: ZsiOperation::Issue,
            record,
        };
        state.zsi_modal = Some(ZsiModal::BindConfirm(params.clone()));
        let client = dummy_client();
        let _ = state.update(client.clone(), Message::ConfirmZsiBind);
        assert!(state.zsi_op_inflight);
        assert!(state.zsi_modal.is_none());
        let _ = state.update(client, Message::ConfirmZsiBind);
        assert!(state.zsi_op_inflight);
    }

    #[cfg(feature = "wallet_zsi")]
    #[test]
    fn zsi_delete_requires_confirmation() {
        let mut state = State::default();
        let _ = state.update(
            dummy_client(),
            Message::RequestZsiDelete {
                identity: "alice".into(),
                commitment: "commit".into(),
            },
        );
        assert!(matches!(
            state.zsi_modal,
            Some(ZsiModal::DeleteConfirm { .. })
        ));
    }

    #[cfg(feature = "wallet_zsi")]
    #[test]
    fn zsi_delete_blocks_duplicates() {
        let mut state = State::default();
        state.zsi_modal = Some(ZsiModal::DeleteConfirm {
            identity: "alice".into(),
            commitment: "commit".into(),
        });
        let client = dummy_client();
        let _ = state.update(client.clone(), Message::ConfirmZsiDelete);
        assert!(state.zsi_op_inflight);
        assert!(state.zsi_modal.is_none());
        let _ = state.update(client, Message::ConfirmZsiDelete);
        assert!(state.zsi_op_inflight);
    }

    #[cfg(feature = "wallet_zsi")]
    #[test]
    fn zsi_errors_map_to_friendly_message() {
        let mut state = State::default();
        let error = RpcCallError::Client(WalletRpcClientError::Rpc {
            code: WalletRpcErrorCode::ProverTimeout,
            message: "timeout".into(),
            json_code: -32014,
            details: None,
        });
        let _ = state.update(dummy_client(), Message::ZsiBindCompleted(Err(error)));
        assert_eq!(
            state.zsi_error.as_deref(),
            Some("The prover timed out while building the proof.")
        );
    }
}
