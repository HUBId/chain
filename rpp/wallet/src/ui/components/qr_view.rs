use iced::widget::{column, container, text};
use iced::{Alignment, Element, Length};

/// View state used when rendering QR data.
pub struct QrViewState<'a> {
    pub payload: &'a str,
    pub caption: Option<&'a str>,
}

/// Renders a placeholder QR view until a renderer is integrated.
pub fn qr_view<'a, Message>(state: QrViewState<'a>) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    let mut column = column![
        container(text("[ QR PREVIEW ]").size(20))
            .width(Length::Fill)
            .padding(24)
            .style(iced::theme::Container::Box)
            .center_x(),
        text(state.payload).size(16),
    ]
    .spacing(12)
    .align_items(Alignment::Center);

    if let Some(caption) = state.caption {
        column = column.push(text(caption).size(14));
    }

    container(column)
        .width(Length::Fill)
        .align_x(Alignment::Center)
        .into()
}
