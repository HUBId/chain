use iced::widget::{button, container, row, text};
use iced::{Alignment, Element, Length};

/// Renders a labelled value with a copy button.
pub fn copyable_text<'a, Message>(
    label: &'a str,
    value: &'a str,
    on_copy: Message,
) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    let value_container = container(text(value).size(16))
        .width(Length::Fill)
        .padding(8)
        .style(iced::theme::Container::Box);

    row![
        container(text(label).size(14))
            .width(Length::Fixed(140.0))
            .align_x(Alignment::Start),
        value_container,
        button(text("Copy").size(14)).on_press(on_copy).padding(8),
    ]
    .spacing(12)
    .align_items(Alignment::Center)
    .into()
}
