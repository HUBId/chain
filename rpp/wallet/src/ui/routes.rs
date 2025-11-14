use iced::keyboard::{self, key::Named, Key, Modifiers};

/// All navigable wallet tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    Overview,
    Activity,
    Receive,
    Send,
    Node,
    Settings,
}

impl Route {
    /// Ordered list of tabs surfaced in the navigation bar.
    pub const ALL: [Route; 6] = [
        Route::Overview,
        Route::Activity,
        Route::Receive,
        Route::Send,
        Route::Node,
        Route::Settings,
    ];

    /// Human readable title rendered in the UI.
    pub const fn title(self) -> &'static str {
        match self {
            Route::Overview => "Overview",
            Route::Activity => "Activity",
            Route::Receive => "Receive",
            Route::Send => "Send",
            Route::Node => "Node",
            Route::Settings => "Settings",
        }
    }

    /// Index of the tab in [`Route::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Route::Overview => 0,
            Route::Activity => 1,
            Route::Receive => 2,
            Route::Send => 3,
            Route::Node => 4,
            Route::Settings => 5,
        }
    }

    /// Route matching the provided index.
    pub fn from_index(index: usize) -> Route {
        Self::ALL[index % Self::ALL.len()]
    }

    /// Select the next tab, wrapping around to the first entry.
    pub fn next(self) -> Route {
        let index = (self.index() + 1) % Self::ALL.len();
        Self::from_index(index)
    }

    /// Select the previous tab, wrapping around to the last entry.
    pub fn previous(self) -> Route {
        let index = if self.index() == 0 {
            Self::ALL.len() - 1
        } else {
            self.index() - 1
        };
        Self::from_index(index)
    }

    /// Maps a keyboard digit shortcut (1-based) to a tab.
    pub fn from_digit(digit: u8) -> Option<Route> {
        if digit == 0 {
            return None;
        }
        let index = (digit - 1) as usize;
        if index < Self::ALL.len() {
            Some(Self::ALL[index])
        } else {
            None
        }
    }
}

/// Navigation intent derived from keyboard shortcuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationIntent {
    Activate(Route),
    Next,
    Previous,
}

/// Returns the navigation intent (if any) produced by the pressed key.
pub fn navigation_intent(key: Key, modifiers: Modifiers) -> Option<NavigationIntent> {
    let key_ref = key.as_ref();

    if modifiers.control() {
        if modifiers.shift() && matches!(key_ref, Key::Named(Named::Tab)) {
            return Some(NavigationIntent::Previous);
        }
        if matches!(key_ref, Key::Named(Named::Tab)) {
            return Some(NavigationIntent::Next);
        }
        if let Some(route) = digit_shortcut(key_ref) {
            return Some(NavigationIntent::Activate(route));
        }
    } else if !modifiers.alt() && !modifiers.logo() {
        match key_ref {
            Key::Named(Named::ArrowLeft) => return Some(NavigationIntent::Previous),
            Key::Named(Named::ArrowRight) => return Some(NavigationIntent::Next),
            _ => {
                if let Some(route) = digit_shortcut(key_ref) {
                    return Some(NavigationIntent::Activate(route));
                }
            }
        }
    }

    None
}

fn digit_shortcut(key: Key<&str>) -> Option<Route> {
    match key {
        Key::Character("1") => Some(Route::Overview),
        Key::Character("2") => Some(Route::Activity),
        Key::Character("3") => Some(Route::Receive),
        Key::Character("4") => Some(Route::Send),
        Key::Character("5") => Some(Route::Node),
        Key::Character("6") => Some(Route::Settings),
        Key::Named(named) => match named {
            Named::Numpad1 => Some(Route::Overview),
            Named::Numpad2 => Some(Route::Activity),
            Named::Numpad3 => Some(Route::Receive),
            Named::Numpad4 => Some(Route::Send),
            Named::Numpad5 => Some(Route::Node),
            Named::Numpad6 => Some(Route::Settings),
            _ => None,
        },
        _ => None,
    }
}
