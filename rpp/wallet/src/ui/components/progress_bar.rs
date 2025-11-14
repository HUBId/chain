use iced::widget::{column, progress_bar as iced_progress_bar, text};
use iced::{Alignment, Element, Length};

/// Read-only view state for progress indicators.
pub struct ProgressBarState<'a> {
    pub progress: f32,
    pub label: Option<&'a str>,
}

/// Renders a determinate progress bar.
pub fn progress_bar<'a, Message>(state: ProgressBarState<'a>) -> Element<'a, Message>
where
    Message: Clone + 'a,
{
    let mut column = column![iced_progress_bar(0.0..=1.0, state.progress)]
        .width(Length::Fill)
        .align_items(Alignment::Start)
        .spacing(8);

    if let Some(label) = state.label {
        column = column.push(text(label).size(14));
    }

    column.into()
}
