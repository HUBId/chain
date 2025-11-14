use iced::widget::{container, row, text};
use iced::{Alignment, Element, Length};

/// Helper rendering a labelled form row, aligning inputs on a grid.
pub fn form_row<'a, Message>(label: &'a str, field: Element<'a, Message>) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    let mut layout = row![container(text(label).size(14))
        .width(Length::Fixed(160.0))
        .align_x(Alignment::Start),]
    .spacing(12)
    .align_items(Alignment::Center);

    layout = layout.push(field);

    layout.width(Length::Fill).into()
}
