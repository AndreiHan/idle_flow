use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use tracing::{error, info, trace, warn};
use tray_icon::TrayIcon;
use winit::application::ApplicationHandler;

use crate::tray;

#[derive(Debug, Clone)]
pub enum UserEvent {
    TrayIconEvent(tray_icon::TrayIconEvent),
    MenuEvent(tray_icon::menu::MenuEvent),
}

pub(crate) struct Application {
    tray_icon: Option<TrayIcon>,
    last_tray_update: Option<std::time::Instant>,
    shutdown: Arc<RwLock<Option<app_controller::AppController>>>,
    idle_controller: Option<idler_utils::IdleController>,
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
            shutdown: Arc::new(RwLock::new(None)),
            idle_controller: None,
        }
    }

    fn new_tray_icon() -> TrayIcon {
        let Ok(tray) = tray::get_tray() else {
            error!("Failed to create tray icon");
            std::process::exit(1);
        };
        tray
    }

    fn set_text(&self, text: String) {
        if let Some(tray_icon) = &self.tray_icon {
            if let Err(e) = tray_icon.set_tooltip(Some(text)) {
                error!("Failed to set tooltip: {e}");
            } else {
                trace!("Tooltip set successfully");
            }
        } else {
            warn!("Tray icon is not initialized; cannot set tooltip.");
        }
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
            self.idle_controller = Some(idler_utils::spawn_idle_thread(None));
        }
    }

    fn user_event(&mut self, event_loop: &winit::event_loop::ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::TrayIconEvent(tray_event) => {
                handle_tray_icon_event(self, event_loop, &tray_event);
            }
            UserEvent::MenuEvent(menu_event) => {
                handle_menu_event(self, event_loop, &menu_event);
            }
        }
    }
}

#[inline]
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

#[inline]
fn handle_menu_event(
    app: &mut Application,
    event_loop: &winit::event_loop::ActiveEventLoop,
    event: &tray_icon::menu::MenuEvent,
) {
    match event.id.0.as_str() {
        "quit" => {
            info!("Quit menu item clicked, exiting event loop.");
            idler_utils::ExecState::stop();
            event_loop.exit();

            if let Some(idle_controller) = app.idle_controller.take() {
                if let Err(e) = idle_controller.stop() {
                    error!("Failed to stop idle controller: {e}");
                } else {
                    info!("Idle controller stopped successfully.");
                }
            }

            if let Some(shutdown) = app.shutdown.write().unwrap().take() {
                info!("Shutdown data taken");
                let status = shutdown.close();
                info!("Shutdown handler disabled, status: {status:?}");
            }
        }
        data => {
            if data == tray::DISABLE_SHUTDOWN {
                info!("Disable shutdown menu item clicked, disabling shutdown.");
                if let Some(shutdown) = app.shutdown.write().unwrap().take() {
                    let status = shutdown.close();
                    info!("Shutdown handler disabled, status: {status:?}");
                } else {
                    warn!("No shutdown handler to disable.");
                }
                app.set_text(tray::DEFAULT.to_string());
                return;
            }

            info!("Menu event received: {data}");
            let shutdown = app.shutdown.read().unwrap();

            if shutdown.is_none() {
                drop(shutdown);
                info!("Initializing shutdown handler.");
                let mut shutdown = app.shutdown.write().unwrap();

                let controller = app_controller::AppController::new();

                let Ok(()) = controller.send_event(data.to_string()) else {
                    error!("Failed to send shutdown time");
                    return;
                };
                *shutdown = Some(controller);

                info!("Shutdown handler initialized.");
                app.set_text(format!("Shutdown scheduled for: {data}"));
                return;
            }

            let Some(shutdown) = &*shutdown else {
                error!("Shutdown handler is not initialized.");
                return;
            };

            info!("Sending shutdown time: {data}");
            if let Err(e) = shutdown.send_event(data.to_string()) {
                error!("Failed to send shutdown time: {e}");
            }
            app.set_text(format!("Shutdown scheduled for: {data}"));
            trace!("Shutdown time sent: {data}");
        }
    }
}
