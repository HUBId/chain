use iced::widget::{button, checkbox, column, container, horizontal_rule, row, text, text_input};
use iced::{Alignment, Command, Element, Length};
use zeroize::Zeroize;

use crate::config::WalletConfig;
use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};
use crate::rpc::dto::{
    BackupExportParams, BackupExportResponse, BackupImportParams, BackupImportResponse,
    BackupMetadataDto, BackupValidateParams, BackupValidateResponse, BackupValidationModeDto,
    GetPolicyResponse, PolicySnapshotDto, SetPolicyParams, SetPolicyResponse,
};
use crate::rpc::error::WalletRpcErrorCode;

use crate::ui::commands::{self, RpcCallError};
use crate::ui::components::modal;
use crate::ui::preferences::{Preferences, ThemePreference};
use crate::ui::telemetry;

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PolicySnapshot {
    revision: u64,
    updated_at: u64,
    statements: Vec<String>,
}

impl From<PolicySnapshotDto> for PolicySnapshot {
    fn from(value: PolicySnapshotDto) -> Self {
        Self {
            revision: value.revision,
            updated_at: value.updated_at,
            statements: value.statements,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseField {
    New,
    Confirm,
}

#[derive(Debug, Default, Clone)]
struct PassphraseForm {
    new_passphrase: String,
    confirm_passphrase: String,
    error: Option<String>,
}

impl PassphraseForm {
    fn reset(&mut self) {
        self.new_passphrase.zeroize();
        self.new_passphrase.clear();
        self.confirm_passphrase.zeroize();
        self.confirm_passphrase.clear();
        self.error = None;
    }
}

#[derive(Debug, Clone)]
struct BackupExportForm {
    passphrase: PassphraseForm,
    metadata_only: bool,
    include_checksums: bool,
}

impl Default for BackupExportForm {
    fn default() -> Self {
        Self {
            passphrase: PassphraseForm::default(),
            metadata_only: false,
            include_checksums: true,
        }
    }
}

impl BackupExportForm {
    fn reset(&mut self) {
        self.passphrase.reset();
        self.metadata_only = false;
        self.include_checksums = true;
    }
}

#[derive(Debug, Default, Clone)]
struct BackupValidateForm {
    name: String,
    passphrase: String,
    dry_run: bool,
    error: Option<String>,
}

impl BackupValidateForm {
    fn reset(&mut self) {
        self.name.clear();
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.dry_run = false;
        self.error = None;
    }

    fn clear_passphrase(&mut self) {
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.error = None;
    }
}

#[derive(Debug, Default, Clone)]
struct BackupImportForm {
    name: String,
    passphrase: String,
    error: Option<String>,
}

impl BackupImportForm {
    fn reset(&mut self) {
        self.name.clear();
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.error = None;
    }

    fn clear_passphrase(&mut self) {
        self.passphrase.zeroize();
        self.passphrase.clear();
        self.error = None;
    }
}

#[derive(Debug, Clone)]
struct BackupOutcome {
    title: String,
    metadata: BackupMetadataDto,
    details: Vec<String>,
}

#[derive(Debug, Clone)]
enum Modal {
    ChangePassphrase(PassphraseForm),
    BackupExport(BackupExportForm),
    BackupValidate(BackupValidateForm),
    BackupImport(BackupImportForm),
}

#[derive(Debug, Default, Clone)]
pub struct State {
    config: Option<WalletConfig>,
    policy: Snapshot<Option<PolicySnapshot>>,
    policy_statements: Vec<String>,
    policy_inflight: bool,
    policy_feedback: Option<String>,
    policy_error: Option<String>,
    policy_validation_errors: Vec<String>,
    preferences: Preferences,
    preferences_dirty: bool,
    telemetry_inflight: bool,
    telemetry_pending: Option<(bool, bool)>,
    telemetry_error: Option<String>,
    clipboard_feedback: Option<String>,
    theme_feedback: Option<String>,
    keystore_present: bool,
    keystore_locked: bool,
    keystore_inflight: bool,
    backup_inflight: bool,
    keystore_feedback: Option<String>,
    keystore_error: Option<String>,
    backup_error: Option<String>,
    backup_outcome: Option<BackupOutcome>,
    backup_pending_name: Option<String>,
    backup_pending_mode: Option<BackupValidationModeDto>,
    modal: Option<Modal>,
}

#[derive(Debug, Clone)]
pub enum Message {
    LoadPolicy,
    PolicyLoaded(Result<GetPolicyResponse, RpcCallError>),
    PolicyStatementChanged(usize, String),
    AddPolicyStatement,
    RemovePolicyStatement(usize),
    SubmitPolicy,
    PolicySubmitted(Result<SetPolicyResponse, RpcCallError>),
    DismissPolicyFeedback,
    DismissPolicyError,
    ThemeSelected(ThemePreference),
    ClipboardConsentChanged(bool),
    ToggleTelemetry(bool),
    TelemetryUpdated(Result<bool, RpcCallError>),
    ShowPassphraseModal,
    ShowBackupExportModal,
    ShowBackupValidateModal,
    ShowBackupImportModal,
    DismissModal,
    PassphraseChanged(PassphraseField, String),
    BackupExportMetadataOnlyChanged(bool),
    BackupExportChecksumsChanged(bool),
    BackupValidateNameChanged(String),
    BackupValidatePassphraseChanged(String),
    BackupValidateModeChanged(bool),
    BackupImportNameChanged(String),
    BackupImportPassphraseChanged(String),
    SubmitPassphraseChange,
    PassphraseChangeCompleted(Result<(), RpcCallError>),
    SubmitBackupExport,
    BackupExported(Result<BackupExportResponse, RpcCallError>),
    SubmitBackupValidation,
    BackupValidated(Result<BackupValidateResponse, RpcCallError>),
    SubmitBackupImport,
    BackupImported(Result<BackupImportResponse, RpcCallError>),
}

impl State {
    pub fn reset(&mut self) {
        self.policy = Snapshot::Idle;
        self.policy_statements.clear();
        self.policy_inflight = false;
        self.policy_feedback = None;
        self.policy_error = None;
        self.policy_validation_errors.clear();
        self.preferences_dirty = false;
        self.telemetry_inflight = false;
        self.telemetry_pending = None;
        self.telemetry_error = None;
        self.clipboard_feedback = None;
        self.theme_feedback = None;
        self.keystore_inflight = false;
        self.backup_inflight = false;
        self.keystore_feedback = None;
        self.keystore_error = None;
        self.backup_error = None;
        self.backup_outcome = None;
        self.backup_pending_name = None;
        self.backup_pending_mode = None;
        self.dismiss_modal();
        if self.policy_statements.is_empty() {
            self.policy_statements.push(String::new());
        }
    }

    pub fn set_config(&mut self, config: Option<WalletConfig>) {
        self.config = config;
    }

    pub fn set_preferences(&mut self, preferences: Preferences) {
        self.preferences = preferences;
        self.preferences_dirty = false;
        self.telemetry_pending = None;
        self.telemetry_inflight = false;
        self.telemetry_error = None;
    }

    pub fn set_clipboard_opt_in(&mut self, enabled: bool) {
        self.preferences.set_clipboard_allowed(enabled);
    }

    pub fn set_keystore_status(&mut self, present: bool, locked: bool) {
        self.keystore_present = present;
        self.keystore_locked = locked;
    }

    pub fn set_session_locked(&mut self) {
        self.keystore_locked = true;
    }

    pub fn set_session_unlocked(&mut self) {
        self.keystore_locked = false;
    }

    pub fn activate(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.policy.should_refresh() {
            return self.load_policy(client);
        }
        Command::none()
    }

    pub fn update(&mut self, client: WalletRpcClient, message: Message) -> Command<Message> {
        match message {
            Message::LoadPolicy => self.load_policy(client),
            Message::PolicyLoaded(result) => {
                self.apply_policy_loaded(result);
                Command::none()
            }
            Message::PolicyStatementChanged(index, value) => {
                if let Some(entry) = self.policy_statements.get_mut(index) {
                    *entry = value;
                }
                Command::none()
            }
            Message::AddPolicyStatement => {
                self.policy_statements.push(String::new());
                Command::none()
            }
            Message::RemovePolicyStatement(index) => {
                if index < self.policy_statements.len() {
                    self.policy_statements.remove(index);
                    if self.policy_statements.is_empty() {
                        self.policy_statements.push(String::new());
                    }
                }
                Command::none()
            }
            Message::SubmitPolicy => self.submit_policy(client),
            Message::PolicySubmitted(result) => {
                self.apply_policy_updated(result);
                Command::none()
            }
            Message::DismissPolicyFeedback => {
                self.policy_feedback = None;
                Command::none()
            }
            Message::DismissPolicyError => {
                self.policy_error = None;
                self.policy_validation_errors.clear();
                Command::none()
            }
            Message::ThemeSelected(theme) => {
                if self.preferences.theme != theme {
                    self.preferences.theme = theme;
                    self.preferences_dirty = true;
                    self.theme_feedback = Some("Theme preference updated.".into());
                }
                Command::none()
            }
            Message::ClipboardConsentChanged(enabled) => {
                if self.preferences.clipboard_allowed() != enabled {
                    self.preferences.set_clipboard_allowed(enabled);
                    self.preferences_dirty = true;
                    self.clipboard_feedback = Some(if enabled {
                        "Clipboard access enabled.".into()
                    } else {
                        "Clipboard access disabled.".into()
                    });
                }
                Command::none()
            }
            Message::ToggleTelemetry(enabled) => {
                if self.telemetry_inflight || self.preferences.telemetry_opt_in == enabled {
                    return Command::none();
                }
                self.telemetry_inflight = true;
                self.telemetry_error = None;
                let previous = self.preferences.telemetry_opt_in;
                self.preferences.telemetry_opt_in = enabled;
                self.telemetry_pending = Some((previous, enabled));
                commands::rpc(
                    "telemetry_toggle",
                    client,
                    move |client| async move { client.toggle_telemetry(enabled).await },
                    Message::TelemetryUpdated,
                )
            }
            Message::TelemetryUpdated(result) => {
                self.apply_telemetry_result(result);
                Command::none()
            }
            Message::ShowPassphraseModal => {
                if self.keystore_present && !self.keystore_locked {
                    self.modal = Some(Modal::ChangePassphrase(PassphraseForm::default()));
                }
                Command::none()
            }
            Message::ShowBackupExportModal => {
                if self.keystore_present && !self.keystore_locked {
                    self.modal = Some(Modal::BackupExport(BackupExportForm::default()));
                }
                Command::none()
            }
            Message::ShowBackupValidateModal => {
                if !self.keystore_locked {
                    self.modal = Some(Modal::BackupValidate(BackupValidateForm::default()));
                }
                Command::none()
            }
            Message::ShowBackupImportModal => {
                if !self.keystore_locked {
                    self.modal = Some(Modal::BackupImport(BackupImportForm::default()));
                }
                Command::none()
            }
            Message::DismissModal => {
                self.dismiss_modal();
                Command::none()
            }
            Message::PassphraseChanged(field, value) => {
                if let Some(modal) = self.modal.as_mut() {
                    match modal {
                        Modal::ChangePassphrase(form) => {
                            match field {
                                PassphraseField::New => form.new_passphrase = value,
                                PassphraseField::Confirm => form.confirm_passphrase = value,
                            }
                            form.error = None;
                        }
                        Modal::BackupExport(form) => {
                            let passphrase = &mut form.passphrase;
                            match field {
                                PassphraseField::New => passphrase.new_passphrase = value,
                                PassphraseField::Confirm => passphrase.confirm_passphrase = value,
                            }
                            passphrase.error = None;
                        }
                        _ => {}
                    }
                }
                Command::none()
            }
            Message::BackupExportMetadataOnlyChanged(value) => {
                if let Some(Modal::BackupExport(form)) = self.modal.as_mut() {
                    form.metadata_only = value;
                }
                Command::none()
            }
            Message::BackupExportChecksumsChanged(value) => {
                if let Some(Modal::BackupExport(form)) = self.modal.as_mut() {
                    form.include_checksums = value;
                }
                Command::none()
            }
            Message::BackupValidateNameChanged(value) => {
                if let Some(Modal::BackupValidate(form)) = self.modal.as_mut() {
                    form.name = value;
                    form.error = None;
                }
                Command::none()
            }
            Message::BackupValidatePassphraseChanged(value) => {
                if let Some(Modal::BackupValidate(form)) = self.modal.as_mut() {
                    form.passphrase = value;
                    form.error = None;
                }
                Command::none()
            }
            Message::BackupValidateModeChanged(value) => {
                if let Some(Modal::BackupValidate(form)) = self.modal.as_mut() {
                    form.dry_run = value;
                }
                Command::none()
            }
            Message::BackupImportNameChanged(value) => {
                if let Some(Modal::BackupImport(form)) = self.modal.as_mut() {
                    form.name = value;
                    form.error = None;
                }
                Command::none()
            }
            Message::BackupImportPassphraseChanged(value) => {
                if let Some(Modal::BackupImport(form)) = self.modal.as_mut() {
                    form.passphrase = value;
                    form.error = None;
                }
                Command::none()
            }
            Message::SubmitPassphraseChange => self.submit_passphrase_change(client),
            Message::PassphraseChangeCompleted(result) => {
                self.apply_passphrase_result(result);
                Command::none()
            }
            Message::SubmitBackupExport => self.submit_backup_export(client),
            Message::BackupExported(result) => {
                self.apply_backup_export(result);
                Command::none()
            }
            Message::SubmitBackupValidation => self.submit_backup_validation(client),
            Message::BackupValidated(result) => {
                self.apply_backup_validation(result);
                Command::none()
            }
            Message::SubmitBackupImport => self.submit_backup_import(client),
            Message::BackupImported(result) => {
                self.apply_backup_import(result);
                Command::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        if let Some(modal_state) = &self.modal {
            let content = match modal_state {
                Modal::ChangePassphrase(form) => passphrase_modal(form),
                Modal::BackupExport(form) => export_modal(form),
                Modal::BackupValidate(form) => validate_modal(form),
                Modal::BackupImport(form) => import_modal(form),
            };
            return modal(content);
        }

        let mut content = column![self.policy_section()]
            .spacing(24)
            .width(Length::Fill);

        content = content.push(horizontal_rule(1));
        content = content.push(self.fee_section());
        content = content.push(horizontal_rule(1));
        content = content.push(self.preferences_section());
        content = content.push(horizontal_rule(1));
        content = content.push(self.keystore_section());
        content = content.push(horizontal_rule(1));
        content = content.push(self.backup_section());

        container(content).width(Length::Fill).into()
    }

    pub fn take_dirty_preferences(&mut self) -> Option<Preferences> {
        if self.preferences_dirty {
            self.preferences_dirty = false;
            Some(self.preferences.clone())
        } else {
            None
        }
    }

    fn dismiss_modal(&mut self) {
        if let Some(modal) = self.modal.as_mut() {
            match modal {
                Modal::ChangePassphrase(form) => form.reset(),
                Modal::BackupExport(form) => form.reset(),
                Modal::BackupValidate(form) => form.reset(),
                Modal::BackupImport(form) => form.reset(),
            }
        }
        self.backup_pending_name = None;
        self.backup_pending_mode = None;
        self.modal = None;
    }

    fn load_policy(&mut self, client: WalletRpcClient) -> Command<Message> {
        self.policy.set_loading();
        commands::rpc(
            "get_policy",
            client,
            |client| async move { client.get_policy().await },
            Message::PolicyLoaded,
        )
    }

    fn submit_policy(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.policy_inflight {
            return Command::none();
        }
        let statements: Vec<String> = self
            .policy_statements
            .iter()
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();
        self.policy_inflight = true;
        self.policy_feedback = None;
        self.policy_error = None;
        self.policy_validation_errors.clear();
        let params = SetPolicyParams { statements };
        commands::rpc(
            "set_policy",
            client,
            move |client| async move { client.set_policy(&params).await },
            Message::PolicySubmitted,
        )
    }

    fn apply_policy_loaded(&mut self, result: Result<GetPolicyResponse, RpcCallError>) {
        match result {
            Ok(response) => {
                if let Some(snapshot) = response.snapshot.map(PolicySnapshot::from) {
                    self.policy.set_loaded(Some(snapshot.clone()));
                    self.policy_statements = snapshot.statements;
                } else {
                    self.policy.set_loaded(None);
                    self.policy_statements.clear();
                }
                if self.policy_statements.is_empty() {
                    self.policy_statements.push(String::new());
                }
                self.policy_error = None;
            }
            Err(error) => {
                self.policy.set_error(&error);
                self.policy_statements.clear();
                self.policy_inflight = false;
                self.policy_statements.push(String::new());
            }
        }
    }

    fn apply_policy_updated(&mut self, result: Result<SetPolicyResponse, RpcCallError>) {
        self.policy_inflight = false;
        match result {
            Ok(response) => {
                let snapshot = PolicySnapshot::from(response.snapshot);
                self.policy.set_loaded(Some(snapshot.clone()));
                self.policy_statements = snapshot.statements;
                if self.policy_statements.is_empty() {
                    self.policy_statements.push(String::new());
                }
                self.policy_feedback = Some("Policy updated successfully.".into());
            }
            Err(error) => {
                self.policy_error = Some(format_rpc_error(&error));
                self.policy_validation_errors = extract_policy_violations(&error);
            }
        }
    }

    fn apply_telemetry_result(&mut self, result: Result<bool, RpcCallError>) {
        self.telemetry_inflight = false;
        match result {
            Ok(enabled) => {
                if let Some((previous, _desired)) = self.telemetry_pending.take() {
                    if enabled != previous {
                        self.preferences.telemetry_opt_in = enabled;
                        self.preferences_dirty = true;
                    } else {
                        self.preferences.telemetry_opt_in = enabled;
                    }
                } else {
                    self.preferences.telemetry_opt_in = enabled;
                }
            }
            Err(error) => {
                if let Some((previous, _)) = self.telemetry_pending.take() {
                    self.preferences.telemetry_opt_in = previous;
                }
                self.telemetry_error = Some(format_rpc_error(&error));
            }
        }
        telemetry::global().set_opt_in(self.preferences.telemetry_opt_in);
    }

    fn submit_passphrase_change(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.keystore_inflight {
            return Command::none();
        }
        let Some(Modal::ChangePassphrase(form)) = self.modal.as_mut() else {
            return Command::none();
        };
        if form.new_passphrase.is_empty() {
            form.error = Some("Passphrase must not be empty.".into());
            return Command::none();
        }
        if form.new_passphrase != form.confirm_passphrase {
            form.error = Some("Passphrases do not match.".into());
            return Command::none();
        }
        self.keystore_inflight = true;
        self.keystore_error = None;
        self.keystore_feedback = None;
        let passphrase = std::mem::take(&mut form.new_passphrase);
        form.confirm_passphrase.zeroize();
        form.confirm_passphrase.clear();
        commands::rpc(
            "keystore.passphrase_update",
            client,
            move |client| async move { change_keystore_passphrase(client, passphrase).await },
            Message::PassphraseChangeCompleted,
        )
    }

    fn apply_passphrase_result(&mut self, result: Result<(), RpcCallError>) {
        self.keystore_inflight = false;
        match result {
            Ok(()) => {
                self.keystore_feedback = Some("Passphrase updated.".into());
                self.dismiss_modal();
            }
            Err(error) => {
                self.keystore_error = Some(format_rpc_error(&error));
                if let Some(Modal::ChangePassphrase(form)) = self.modal.as_mut() {
                    form.reset();
                }
            }
        }
    }

    fn submit_backup_export(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.backup_inflight {
            return Command::none();
        }
        let Some(Modal::BackupExport(form)) = self.modal.as_mut() else {
            return Command::none();
        };
        let passphrase = &mut form.passphrase;
        if passphrase.new_passphrase.is_empty() {
            passphrase.error = Some("Passphrase must not be empty.".into());
            return Command::none();
        }
        if passphrase.new_passphrase != passphrase.confirm_passphrase {
            passphrase.error = Some("Passphrases do not match.".into());
            return Command::none();
        }
        self.backup_inflight = true;
        self.backup_error = None;
        self.backup_outcome = None;
        self.backup_pending_name = None;
        self.backup_pending_mode = None;
        let params = BackupExportParams {
            passphrase: std::mem::take(&mut passphrase.new_passphrase),
            confirmation: std::mem::take(&mut passphrase.confirm_passphrase),
            metadata_only: form.metadata_only,
            include_checksums: form.include_checksums,
        };
        passphrase.error = None;
        commands::rpc(
            "backup.export",
            client,
            move |client| {
                let mut params = params;
                async move {
                    let result = client.backup_export(&params).await;
                    params.passphrase.zeroize();
                    params.confirmation.zeroize();
                    result
                }
            },
            Message::BackupExported,
        )
    }

    fn apply_backup_export(&mut self, result: Result<BackupExportResponse, RpcCallError>) {
        self.backup_inflight = false;
        self.backup_pending_name = None;
        self.backup_pending_mode = None;
        match result {
            Ok(response) => {
                self.backup_error = None;
                self.backup_outcome = Some(BackupOutcome {
                    title: format!("Backup exported to {}", response.path),
                    metadata: response.metadata,
                    details: Vec::new(),
                });
                self.dismiss_modal();
            }
            Err(error) => {
                self.backup_error = Some(format_rpc_error(&error));
                if let Some(Modal::BackupExport(form)) = self.modal.as_mut() {
                    form.passphrase.reset();
                }
            }
        }
    }

    fn submit_backup_validation(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.backup_inflight {
            return Command::none();
        }
        let Some(Modal::BackupValidate(form)) = self.modal.as_mut() else {
            return Command::none();
        };
        let name = form.name.trim();
        if name.is_empty() {
            form.error = Some("Backup name must not be empty.".into());
            return Command::none();
        }
        if form.passphrase.is_empty() {
            form.error = Some("Passphrase must not be empty.".into());
            return Command::none();
        }
        self.backup_inflight = true;
        self.backup_error = None;
        self.backup_outcome = None;
        let mode = if form.dry_run {
            BackupValidationModeDto::DryRun
        } else {
            BackupValidationModeDto::Full
        };
        let params = BackupValidateParams {
            name: name.to_string(),
            passphrase: std::mem::take(&mut form.passphrase),
            mode: mode.clone(),
        };
        self.backup_pending_name = Some(params.name.clone());
        self.backup_pending_mode = Some(mode);
        form.error = None;
        commands::rpc(
            "backup.validate",
            client,
            move |client| {
                let mut params = params;
                async move {
                    let result = client.backup_validate(&params).await;
                    params.passphrase.zeroize();
                    result
                }
            },
            Message::BackupValidated,
        )
    }

    fn apply_backup_validation(&mut self, result: Result<BackupValidateResponse, RpcCallError>) {
        self.backup_inflight = false;
        let name = self.backup_pending_name.take();
        let mode = self.backup_pending_mode.take();
        match result {
            Ok(response) => {
                self.backup_error = None;
                let mut details = Vec::new();
                if let Some(mode) = mode {
                    let label = match mode {
                        BackupValidationModeDto::DryRun => {
                            "Validation mode: Dry run (checksums skipped)".to_string()
                        }
                        BackupValidationModeDto::Full => "Validation mode: Full".to_string(),
                    };
                    details.push(label);
                }
                let title = name
                    .map(|name| format!("Backup {name} validated."))
                    .unwrap_or_else(|| "Backup validated.".into());
                self.backup_outcome = Some(BackupOutcome {
                    title,
                    metadata: response.metadata,
                    details,
                });
                self.dismiss_modal();
            }
            Err(error) => {
                self.backup_error = Some(format_rpc_error(&error));
                if let Some(Modal::BackupValidate(form)) = self.modal.as_mut() {
                    form.clear_passphrase();
                }
            }
        }
    }

    fn submit_backup_import(&mut self, client: WalletRpcClient) -> Command<Message> {
        if self.backup_inflight {
            return Command::none();
        }
        let Some(Modal::BackupImport(form)) = self.modal.as_mut() else {
            return Command::none();
        };
        let name = form.name.trim();
        if name.is_empty() {
            form.error = Some("Backup name must not be empty.".into());
            return Command::none();
        }
        if form.passphrase.is_empty() {
            form.error = Some("Passphrase must not be empty.".into());
            return Command::none();
        }
        self.backup_inflight = true;
        self.backup_error = None;
        self.backup_outcome = None;
        self.backup_pending_mode = None;
        let params = BackupImportParams {
            name: name.to_string(),
            passphrase: std::mem::take(&mut form.passphrase),
        };
        self.backup_pending_name = Some(params.name.clone());
        form.error = None;
        commands::rpc(
            "backup.import",
            client,
            move |client| {
                let mut params = params;
                async move {
                    let result = client.backup_import(&params).await;
                    params.passphrase.zeroize();
                    result
                }
            },
            Message::BackupImported,
        )
    }

    fn apply_backup_import(&mut self, result: Result<BackupImportResponse, RpcCallError>) {
        self.backup_inflight = false;
        let name = self.backup_pending_name.take();
        self.backup_pending_mode = None;
        match result {
            Ok(response) => {
                self.backup_error = None;
                let details = vec![
                    format!(
                        "Restored keystore: {}",
                        format_bool(response.restored_keystore)
                    ),
                    format!("Restored policy: {}", format_bool(response.restored_policy)),
                    format!("Rescan from height: {}", response.rescan_from_height),
                ];
                let title = name
                    .map(|name| format!("Backup {name} imported."))
                    .unwrap_or_else(|| "Backup imported.".into());
                self.backup_outcome = Some(BackupOutcome {
                    title,
                    metadata: response.metadata,
                    details,
                });
                self.dismiss_modal();
            }
            Err(error) => {
                self.backup_error = Some(format_rpc_error(&error));
                if let Some(Modal::BackupImport(form)) = self.modal.as_mut() {
                    form.clear_passphrase();
                }
            }
        }
    }

    fn policy_section(&self) -> Element<Message> {
        let mut column = column![text("Wallet policy").size(20)].spacing(12);

        match &self.policy {
            Snapshot::Idle | Snapshot::Loading => {
                column = column.push(text("Loading policy...").size(16));
            }
            Snapshot::Error(error) => {
                column = column.push(text(format!("Unable to load policy: {error}")));
            }
            Snapshot::Loaded(snapshot) => {
                if let Some(snapshot) = snapshot {
                    column = column.push(text(format!(
                        "Revision {} · Updated {}",
                        snapshot.revision, snapshot.updated_at
                    )));
                } else {
                    column = column.push(text("No policy statements configured."));
                }
            }
        }

        for (index, statement) in self.policy_statements.iter().enumerate() {
            let input = text_input("Policy statement", statement)
                .on_input(move |value| Message::PolicyStatementChanged(index, value));
            let row = row![
                input.width(Length::Fill),
                button(text("Remove"))
                    .on_press(Message::RemovePolicyStatement(index))
                    .padding(6),
            ]
            .spacing(8);
            column = column.push(row);
        }

        column = column.push(button(text("Add statement")).on_press(Message::AddPolicyStatement));

        let mut actions = row![
            button(text("Reload"))
                .on_press(Message::LoadPolicy)
                .padding(8),
            button(text("Save policy"))
                .on_press(Message::SubmitPolicy)
                .padding(8),
        ]
        .spacing(8);

        if self.policy_inflight {
            actions = actions.push(text("Updating...").size(16));
        }

        column = column.push(actions);

        if let Some(feedback) = &self.policy_feedback {
            column = column.push(
                row![
                    text(feedback.clone()),
                    button(text("Dismiss"))
                        .on_press(Message::DismissPolicyFeedback)
                        .padding(6)
                ]
                .spacing(8),
            );
        }

        if let Some(error) = &self.policy_error {
            column = column.push(
                row![
                    text(error.clone()),
                    button(text("Dismiss"))
                        .on_press(Message::DismissPolicyError)
                        .padding(6)
                ]
                .spacing(8),
            );
            if !self.policy_validation_errors.is_empty() {
                for violation in &self.policy_validation_errors {
                    column = column.push(text(format!("- {violation}")));
                }
            }
        }

        container(column).width(Length::Fill).into()
    }

    fn fee_section(&self) -> Element<Message> {
        let mut column = column![text("Fee defaults").size(20)].spacing(12);
        if let Some(config) = &self.config {
            let fees = &config.fees;
            column = column.push(text(format!(
                "Default fee rate: {} sat/vB",
                fees.default_sats_per_vbyte
            )));
            column = column.push(text(format!(
                "Min fee rate: {} sat/vB",
                fees.min_sats_per_vbyte
            )));
            column = column.push(text(format!(
                "Max fee rate: {} sat/vB",
                fees.max_sats_per_vbyte
            )));
            column = column.push(text(format!(
                "Target confirmations: {}",
                fees.target_confirmations
            )));
        } else {
            column = column.push(text("Wallet configuration unavailable."));
        }
        container(column).width(Length::Fill).into()
    }

    fn preferences_section(&self) -> Element<Message> {
        let mut column = column![text("Appearance & Privacy").size(20)].spacing(12);

        let themes = row![
            theme_radio("System", ThemePreference::System, self.preferences.theme),
            theme_radio("Light", ThemePreference::Light, self.preferences.theme),
            theme_radio("Dark", ThemePreference::Dark, self.preferences.theme),
        ]
        .spacing(12);
        column = column.push(text("Theme"));
        column = column.push(themes);

        column = column.push(
            checkbox(
                "Allow copying addresses to the clipboard",
                self.preferences.clipboard_allowed(),
            )
            .on_toggle(Message::ClipboardConsentChanged),
        );

        let inflight = self.telemetry_inflight;
        let current = self.preferences.telemetry_opt_in;
        let telemetry_toggle =
            checkbox("Enable telemetry opt-in", current).on_toggle(move |enabled| {
                if inflight {
                    Message::ToggleTelemetry(current)
                } else {
                    Message::ToggleTelemetry(enabled)
                }
            });
        column = column.push(telemetry_toggle);

        if let Some(error) = &self.telemetry_error {
            column = column.push(text(format!("Telemetry update failed: {error}")));
        }
        if let Some(feedback) = &self.clipboard_feedback {
            column = column.push(text(feedback.clone()));
        }
        if let Some(feedback) = &self.theme_feedback {
            column = column.push(text(feedback.clone()));
        }

        container(column).width(Length::Fill).into()
    }

    fn keystore_section(&self) -> Element<Message> {
        let mut column = column![text("Keystore").size(20)].spacing(12);

        if !self.keystore_present {
            column = column.push(text("Keystore unavailable."));
        } else if self.keystore_locked {
            column = column.push(text("Unlock the wallet to manage the keystore."));
        } else {
            let change_button = if self.keystore_inflight {
                button(text("Change passphrase")).padding(8)
            } else {
                button(text("Change passphrase"))
                    .on_press(Message::ShowPassphraseModal)
                    .padding(8)
            };
            let mut actions = row![change_button].spacing(8);
            if self.keystore_inflight {
                actions = actions.push(text("Processing...").size(16));
            }
            column = column.push(actions);
        }

        if let Some(feedback) = &self.keystore_feedback {
            column = column.push(text(feedback.clone()));
        }
        if let Some(error) = &self.keystore_error {
            column = column.push(text(format!("Keystore operation failed: {error}")));
        }

        container(column).width(Length::Fill).into()
    }

    fn backup_section(&self) -> Element<Message> {
        let mut column = column![text("Backups").size(20)].spacing(12);

        if let Some(config) = &self.config {
            column = column.push(text(format!(
                "Backup directory: {}",
                config.engine.backup_path.display()
            )));
        }

        let export_disabled =
            self.backup_inflight || self.keystore_locked || !self.keystore_present;
        let validate_disabled = self.backup_inflight || self.keystore_locked;
        let import_disabled = self.backup_inflight || self.keystore_locked;

        let export_button = if export_disabled {
            button(text("Export backup")).padding(8)
        } else {
            button(text("Export backup"))
                .on_press(Message::ShowBackupExportModal)
                .padding(8)
        };
        let validate_button = if validate_disabled {
            button(text("Validate backup")).padding(8)
        } else {
            button(text("Validate backup"))
                .on_press(Message::ShowBackupValidateModal)
                .padding(8)
        };
        let import_button = if import_disabled {
            button(text("Import backup")).padding(8)
        } else {
            button(text("Import backup"))
                .on_press(Message::ShowBackupImportModal)
                .padding(8)
        };

        let mut actions = row![export_button, validate_button, import_button].spacing(8);
        if self.backup_inflight {
            actions = actions.push(text("Processing...").size(16));
        }
        column = column.push(actions);

        if let Some(outcome) = &self.backup_outcome {
            let mut summary = column![text(outcome.title.clone())].spacing(4);
            for line in metadata_lines(&outcome.metadata) {
                summary = summary.push(text(line));
            }
            for detail in &outcome.details {
                summary = summary.push(text(detail.clone()));
            }
            column = column.push(summary.into());
        }

        if let Some(error) = &self.backup_error {
            column = column.push(text(format!("Backup operation failed: {error}")));
        }

        container(column).width(Length::Fill).into()
    }
}

fn theme_radio<'a>(
    label: &str,
    value: ThemePreference,
    selected: ThemePreference,
) -> Element<'a, Message> {
    iced::widget::radio(label, value, Some(selected), Message::ThemeSelected)
        .size(16)
        .into()
}

fn passphrase_modal<'a>(form: &'a PassphraseForm) -> iced::widget::Column<'a, Message> {
    let mut content = column![text("Update keystore passphrase").size(20)]
        .spacing(12)
        .align_items(Alignment::Center);

    content = content.push(
        text_input("New passphrase", &form.new_passphrase)
            .on_input(|value| Message::PassphraseChanged(PassphraseField::New, value))
            .password(),
    );
    content = content.push(
        text_input("Confirm passphrase", &form.confirm_passphrase)
            .on_input(|value| Message::PassphraseChanged(PassphraseField::Confirm, value))
            .password(),
    );

    if let Some(error) = &form.error {
        content = content.push(text(error.clone()));
    }

    let actions = row![
        button(text("Cancel")).on_press(Message::DismissModal),
        button(text("Update")).on_press(Message::SubmitPassphraseChange),
    ]
    .spacing(8);

    content.push(actions)
}

fn export_modal<'a>(form: &'a BackupExportForm) -> iced::widget::Column<'a, Message> {
    let mut content = column![text("Export encrypted backup").size(20)]
        .spacing(12)
        .align_items(Alignment::Center);

    let passphrase = &form.passphrase;
    content = content.push(
        text_input("Backup passphrase", &passphrase.new_passphrase)
            .on_input(|value| Message::PassphraseChanged(PassphraseField::New, value))
            .password(),
    );
    content = content.push(
        text_input("Confirm passphrase", &passphrase.confirm_passphrase)
            .on_input(|value| Message::PassphraseChanged(PassphraseField::Confirm, value))
            .password(),
    );

    content = content.push(
        checkbox("Export metadata only (skip keystore)", form.metadata_only)
            .on_toggle(Message::BackupExportMetadataOnlyChanged),
    );
    content = content.push(
        checkbox("Include component checksums", form.include_checksums)
            .on_toggle(Message::BackupExportChecksumsChanged),
    );

    if let Some(error) = &passphrase.error {
        content = content.push(text(error.clone()));
    }

    let actions = row![
        button(text("Cancel")).on_press(Message::DismissModal),
        button(text("Export")).on_press(Message::SubmitBackupExport),
    ]
    .spacing(8);

    content.push(actions)
}

fn validate_modal<'a>(form: &'a BackupValidateForm) -> iced::widget::Column<'a, Message> {
    let mut content = column![text("Validate encrypted backup").size(20)]
        .spacing(12)
        .align_items(Alignment::Center);

    content = content
        .push(text_input("Backup name", &form.name).on_input(Message::BackupValidateNameChanged));
    content = content.push(
        text_input("Backup passphrase", &form.passphrase)
            .on_input(Message::BackupValidatePassphraseChanged)
            .password(),
    );
    content = content.push(
        checkbox(
            "Dry-run validation (skip checksum verification)",
            form.dry_run,
        )
        .on_toggle(Message::BackupValidateModeChanged),
    );

    if let Some(error) = &form.error {
        content = content.push(text(error.clone()));
    }

    let actions = row![
        button(text("Cancel")).on_press(Message::DismissModal),
        button(text("Validate")).on_press(Message::SubmitBackupValidation),
    ]
    .spacing(8);

    content.push(actions)
}

fn import_modal<'a>(form: &'a BackupImportForm) -> iced::widget::Column<'a, Message> {
    let mut content = column![text("Import encrypted backup").size(20)]
        .spacing(12)
        .align_items(Alignment::Center);

    content = content
        .push(text_input("Backup name", &form.name).on_input(Message::BackupImportNameChanged));
    content = content.push(
        text_input("Backup passphrase", &form.passphrase)
            .on_input(Message::BackupImportPassphraseChanged)
            .password(),
    );

    if let Some(error) = &form.error {
        content = content.push(text(error.clone()));
    }

    let actions = row![
        button(text("Cancel")).on_press(Message::DismissModal),
        button(text("Import")).on_press(Message::SubmitBackupImport),
    ]
    .spacing(8);

    content.push(actions)
}

async fn change_keystore_passphrase(
    client: WalletRpcClient,
    passphrase: String,
) -> Result<(), WalletRpcClientError> {
    #[derive(serde::Serialize)]
    struct Params {
        passphrase: String,
    }

    let mut params = Params { passphrase };

    let result = client
        .request("keystore.passphrase_update", Some(&params))
        .await
        .map(|_| ());
    params.passphrase.zeroize();
    result
}

fn extract_policy_violations(error: &RpcCallError) -> Vec<String> {
    if let RpcCallError::Client(WalletRpcClientError::Rpc { code, details, .. }) = error {
        if *code != WalletRpcErrorCode::WalletPolicyViolation {
            return Vec::new();
        }
        if let Some(value) = details {
            if let Some(violations) = value.get("violations") {
                if let Some(array) = violations.as_array() {
                    return array
                        .iter()
                        .filter_map(|entry| entry.as_str().map(ToString::to_string))
                        .collect();
                }
            }
        }
    }
    Vec::new()
}

fn format_rpc_error(error: &RpcCallError) -> String {
    match error {
        RpcCallError::Timeout(duration) => {
            format!("Request timed out after {} seconds.", duration.as_secs())
        }
        RpcCallError::Client(inner) => inner.to_string(),
    }
}

fn format_bool(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn metadata_lines(metadata: &BackupMetadataDto) -> Vec<String> {
    vec![
        format!("Version: {}", metadata.version),
        format!("Created at (ms): {}", metadata.created_at_ms),
        format!("Schema checksum: {}", metadata.schema_checksum),
        format!("Includes keystore: {}", format_bool(metadata.has_keystore)),
        format!("Policy entries: {}", metadata.policy_entries),
        format!("Metadata entries: {}", metadata.meta_entries),
        format!(
            "Includes checksums: {}",
            format_bool(metadata.include_checksums)
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::client::WalletRpcClientError;
    use crate::rpc::error::WalletRpcErrorCode;
    use serde_json::json;
    use std::time::Duration;

    fn dummy_client() -> WalletRpcClient {
        WalletRpcClient::from_endpoint("http://127.0.0.1:1", None, None, Duration::from_secs(1))
            .unwrap()
    }

    #[test]
    fn policy_validation_errors_are_captured() {
        let mut state = State::default();
        state.policy_statements = vec!["min_confirmations 10".into()];
        let error = RpcCallError::Client(WalletRpcClientError::Rpc {
            code: WalletRpcErrorCode::WalletPolicyViolation,
            message: "invalid policy".into(),
            json_code: WalletRpcErrorCode::WalletPolicyViolation.as_i32(),
            details: Some(json!({ "violations": ["gap limit too low"] })),
        });
        state.apply_policy_updated(Err(error));
        assert_eq!(
            state.policy_validation_errors,
            vec!["gap limit too low".to_string()]
        );
    }

    #[test]
    fn preference_changes_mark_dirty() {
        let mut state = State::default();
        state.set_preferences(Preferences::default());
        let _ = state.update(dummy_client(), Message::ClipboardConsentChanged(true));
        let prefs = state.take_dirty_preferences().expect("preferences updated");
        assert!(prefs.clipboard_allowed());
        assert!(state.take_dirty_preferences().is_none());
    }

    #[test]
    fn telemetry_toggle_reverts_on_failure() {
        let mut state = State::default();
        state.set_preferences(Preferences::default());
        state.preferences.telemetry_opt_in = false;

        let _command = state.update(dummy_client(), Message::ToggleTelemetry(true));
        assert!(state.telemetry_inflight);
        assert_eq!(state.telemetry_pending, Some((false, true)));

        let error = RpcCallError::Timeout(Duration::from_secs(2));
        let _ = state.update(dummy_client(), Message::TelemetryUpdated(Err(error)));
        assert!(!state.telemetry_inflight);
        assert_eq!(state.preferences.telemetry_opt_in, false);
        assert!(state
            .telemetry_error
            .as_ref()
            .expect("telemetry error recorded")
            .contains("2"));
    }

    #[test]
    fn passphrase_change_requires_matching_inputs() {
        let mut state = State::default();
        state.keystore_present = true;
        state.keystore_locked = false;
        state.modal = Some(Modal::ChangePassphrase(PassphraseForm::default()));

        let _ = state.update(
            dummy_client(),
            Message::PassphraseChanged(PassphraseField::New, "secret".into()),
        );
        let _ = state.update(
            dummy_client(),
            Message::PassphraseChanged(PassphraseField::Confirm, "mismatch".into()),
        );
        let _ = state.update(dummy_client(), Message::SubmitPassphraseChange);

        if let Some(Modal::ChangePassphrase(form)) = &state.modal {
            assert_eq!(form.error.as_deref(), Some("Passphrases do not match."));
        } else {
            panic!("passphrase modal should remain open");
        }
        assert!(!state.keystore_inflight);
    }

    #[test]
    fn backup_export_requires_matching_passphrase() {
        let mut state = State::default();
        state.keystore_present = true;
        state.keystore_locked = false;
        state.modal = Some(Modal::BackupExport(BackupExportForm::default()));

        let _ = state.update(
            dummy_client(),
            Message::PassphraseChanged(PassphraseField::New, "secret".into()),
        );
        let _ = state.update(
            dummy_client(),
            Message::PassphraseChanged(PassphraseField::Confirm, "mismatch".into()),
        );
        let _ = state.update(dummy_client(), Message::SubmitBackupExport);

        if let Some(Modal::BackupExport(form)) = &state.modal {
            assert_eq!(
                form.passphrase.error.as_deref(),
                Some("Passphrases do not match.")
            );
        } else {
            panic!("export modal should remain open");
        }
        assert!(!state.backup_inflight);
    }
}
