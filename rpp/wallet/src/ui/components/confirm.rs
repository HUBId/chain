use iced::widget::{button, column, container, row, text};
use iced::{Alignment, Element, Length};

/// State describing a confirmation dialog rendered inside a modal.
pub struct ConfirmDialog<Message>
where
    Message: Clone,
{
    pub title: String,
    pub body: String,
    pub confirm_label: String,
    pub cancel_label: String,
    pub on_confirm: Message,
    pub on_cancel: Message,
}

impl<Message> ConfirmDialog<Message>
where
    Message: Clone,
{
    /// Builds the dialog contents as an [`Element`].
    pub fn view<'a>(self) -> Element<'a, Message>
    where
        Message: 'a,
    {
        let content = column![
            text(self.title).size(24),
            text(self.body).size(16),
            row![
                button(text(self.confirm_label))
                    .on_press(self.on_confirm.clone())
                    .style(iced::theme::Button::Primary)
                    .padding(12),
                button(text(self.cancel_label))
                    .on_press(self.on_cancel.clone())
                    .padding(12),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
        ]
        .spacing(16)
        .align_items(Alignment::Start);

        container(content).width(Length::Shrink).padding(12).into()
    }
}
