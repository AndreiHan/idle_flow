use std::time::{Duration, Instant};

use tracing::{error, info, trace, warn};
use tray_icon::TrayIcon;
use winit::application::ApplicationHandler;

use crate::tray;

#[derive(Debug)]
pub enum UserEvent {
    TrayIconEvent(tray_icon::TrayIconEvent),
    MenuEvent(tray_icon::menu::MenuEvent),
}

pub(crate) struct Application {
    tray_icon: Option<TrayIcon>,
    last_tray_update: Option<std::time::Instant>,
}

impl Default for Application {
    fn default() -> Self {
        Self::new()
    }
}

impl Application {
    fn new() -> Application {
        Application {
            tray_icon: None,
            last_tray_update: None,
        }
    }

    fn new_tray_icon() -> TrayIcon {
        let Ok(tray) = tray::get_tray() else {
            error!("Failed to create tray icon");
            std::process::exit(1);
        };
        tray
    }
}

impl ApplicationHandler<UserEvent> for Application {
    fn resumed(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {}

    fn window_event(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        _window_id: winit::window::WindowId,
        _event: winit::event::WindowEvent,
    ) {
    }

    fn new_events(
        &mut self,
        _event_loop: &winit::event_loop::ActiveEventLoop,
        cause: winit::event::StartCause,
    ) {
        if winit::event::StartCause::Init == cause {
            self.tray_icon = Some(Self::new_tray_icon());
        }
    }

    fn user_event(&mut self, event_loop: &winit::event_loop::ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::TrayIconEvent(tray_event) => {
                handle_tray_icon_event(self, event_loop, &tray_event);
            }
            UserEvent::MenuEvent(menu_event) => {
                handle_menu_event(event_loop, &menu_event);
            }
        }
    }
}

fn handle_tray_icon_event(
    app: &mut Application,
    _event_loop: &winit::event_loop::ActiveEventLoop,
    event: &tray_icon::TrayIconEvent,
) {
    if let tray_icon::TrayIconEvent::Move { .. } = event {
        let now = Instant::now();
        let debounce: Duration = Duration::from_millis(5000);
        if let Some(last) = app.last_tray_update {
            let elapsed = now.duration_since(last);
            if elapsed < debounce {
                trace!(
                    "Tray menu refresh debounced ({}ms < {}ms)",
                    elapsed.as_millis(),
                    debounce.as_millis()
                );
                return;
            }
        }
        app.last_tray_update = Some(now);

        let Some(tray_icon) = &app.tray_icon else {
            warn!("Tray icon is not initialized; cannot refresh menu.");
            return;
        };

        trace!("Refreshing tray menu after Move event");
        match tray::get_menu() {
            Ok(menu) => {
                tray_icon.set_menu(None);
                tray_icon.set_menu(Some(Box::new(menu)));
                info!("Tray menu refreshed successfully.");
            }
            Err(e) => {
                error!("Failed to get tray menu: {e}");
            }
        }
    }
}

fn handle_menu_event(
    event_loop: &winit::event_loop::ActiveEventLoop,
    event: &tray_icon::menu::MenuEvent,
) {
    match event.id.0.as_str() {
        "quit" => {
            info!("Quit menu item clicked, exiting event loop.");
            idler_utils::ExecState::stop();
            event_loop.exit();
        }
        _ => {
            warn!("Unhandled menu event: {:?}", event.id);
        }
    }
}
