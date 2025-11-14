use iced::widget::{container, text};
use iced::{Element, Length};

/// Visual styling for a toast notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Warning,
    Error,
}

impl ToastKind {
    fn container_style(self) -> iced::theme::Container {
        match self {
            ToastKind::Info => iced::theme::Container::Box,
            ToastKind::Success => iced::theme::Container::Box,
            ToastKind::Warning => iced::theme::Container::Box,
            ToastKind::Error => iced::theme::Container::Box,
        }
    }
}

/// Immutable view state for a toast notification.
pub struct ToastState<'a> {
    pub message: &'a str,
    pub kind: ToastKind,
}

/// Renders a toast notification container.
pub fn toast<'a, Message>(state: ToastState<'a>) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    container(text(state.message).size(16))
        .style(state.kind.container_style())
        .padding(12)
        .width(Length::Fill)
        .into()
}
