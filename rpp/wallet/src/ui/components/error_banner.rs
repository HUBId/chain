use iced::widget::{button, column, container, row, text};
use iced::{Alignment, Element, Length};

/// Read-only view state used to render global error banners.
pub struct ErrorBannerState<'a> {
    pub message: &'a str,
    pub detail: Option<&'a str>,
}

/// Renders an error banner with an optional technical detail section.
pub fn error_banner<'a, Message>(
    state: ErrorBannerState<'a>,
    dismiss: Message,
) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    let mut description = column![text(state.message).size(16)];
    if let Some(detail) = state.detail {
        description = description.push(text(detail).size(14));
    }

    let dismiss_button = button(text("Dismiss").size(14))
        .on_press(dismiss)
        .padding(8);

    container(
        row![description.spacing(8).width(Length::Fill), dismiss_button,]
            .spacing(12)
            .align_items(Alignment::Center),
    )
    .style(iced::theme::Container::Box)
    .padding(12)
    .width(Length::Fill)
    .into()
}
