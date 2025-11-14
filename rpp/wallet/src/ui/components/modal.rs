use iced::widget::{column, container, row, Space};
use iced::{Alignment, Element, Length};

/// Fixed width modal wrapper used by the wallet UI.
pub fn modal<'a, Message>(content: iced::widget::Column<'a, Message>) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    const DEFAULT_MODAL_WIDTH: f32 = 420.0;

    let modal = container(content)
        .padding(24)
        .width(Length::Fixed(DEFAULT_MODAL_WIDTH))
        .style(iced::theme::Container::Box);

    let layout = column![
        Space::with_height(Length::Fill),
        row![
            Space::with_width(Length::Fill),
            modal,
            Space::with_width(Length::Fill)
        ],
        Space::with_height(Length::Fill),
    ]
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(0)
    .align_items(Alignment::Center);

    container(layout)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}
