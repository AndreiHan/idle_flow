#![cfg(windows)]
use anyhow::Result;
use mitigations::Closeable;
use tracing::{error, info, trace, warn};
use winit::application::ApplicationHandler;

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub struct Application {
    sender_proxy: winit::event_loop::EventLoopProxy<tray::UserEvent>,
    tray_icon: Option<tray_icon::TrayIcon>,
    last_tray_update: Option<std::time::Instant>,
    shutdown: Option<app_controller::AppController>,
    idle_controller: Option<idler_utils::IdleController>,
    registry_watcher: Option<idler_utils::registry::RegistryWatcher>,
}

impl Application {
    #[must_use]
    pub const fn new(sender_proxy: winit::event_loop::EventLoopProxy<tray::UserEvent>) -> Self {
        Self {
            sender_proxy,
            tray_icon: None,
            last_tray_update: None,
            shutdown: None,
            idle_controller: None,
            registry_watcher: None,
        }
    }

    fn new_tray_icon() -> Result<tray_icon::TrayIcon> {
        let Ok(tray) = tray::get_tray() else {
            error!("Failed to create tray icon");
            return Err(anyhow::anyhow!("Failed to create tray icon"));
        };
        Ok(tray)
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

impl ApplicationHandler<tray::UserEvent> for Application {
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
        event_loop: &winit::event_loop::ActiveEventLoop,
        cause: winit::event::StartCause,
    ) {
        if winit::event::StartCause::Init != cause {
            return;
        }
        let Ok(tray_icon) = Self::new_tray_icon() else {
            error!("Failed to create tray icon, exiting event loop.");
            event_loop.exit();
            return;
        };
        self.tray_icon = Some(tray_icon);
        self.registry_watcher = idler_utils::registry::RegistryWatcher::build().ok();
        self.idle_controller = Some(idler_utils::spawn_idle_thread(None));
        mitigations::set_process_priority();
        mitigations::set_priority(mitigations::Priority::Lowest);
        info!("Tray icon created successfully.");
    }

    fn user_event(
        &mut self,
        event_loop: &winit::event_loop::ActiveEventLoop,
        event: tray::UserEvent,
    ) {
        match event {
            tray::UserEvent::TrayIconEvent(tray_event) => {
                handle_tray_icon_event(self, event_loop, &tray_event);
            }
            tray::UserEvent::MenuEvent(menu_event) => {
                handle_menu_event(self, event_loop, &menu_event);
            }
        }
    }
}

fn refresh_menu(app: &Application) {
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

fn handle_tray_icon_event(
    app: &mut Application,
    _event_loop: &winit::event_loop::ActiveEventLoop,
    event: &tray_icon::TrayIconEvent,
) {
    if !matches!(event, tray_icon::TrayIconEvent::Enter { .. }) {
        return;
    }

    let now = std::time::Instant::now();
    let debounce = std::time::Duration::from_secs(120);
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

    trace!("Refreshing tray menu after Move event");
    refresh_menu(app);
}

fn handle_menu_event(
    app: &mut Application,
    event_loop: &winit::event_loop::ActiveEventLoop,
    event: &tray_icon::menu::MenuEvent,
) {
    let data = event.id.0.as_str();
    info!("Menu event received: {data}");
    if data == tray::QUIT_ID {
        handle_quit(app, event_loop);
        return;
    }
    if data == tray::DISABLE_SHUTDOWN {
        handle_disable_shutdown(app);
        return;
    }
    if data == tray::START_WITH_DESKTOP_ID {
        if let Err(e) = idler_utils::registry::set_key() {
            error!("Failed to set start with desktop: {e}");
        } else {
            info!("Start with desktop enabled.");
        }
        refresh_menu(app);
        return;
    }
    if data == tray::DISABLE_START_WITH_DESKTOP_ID {
        if let Err(e) = idler_utils::registry::unset_key() {
            error!("Failed to clear start with desktop: {e}");
        } else {
            info!("Start with desktop disabled.");
        }
        refresh_menu(app);
        return;
    }
    handle_shutdown_time(app, data);
}

fn handle_shutdown_time(app: &mut Application, data: &str) {
    info!("Received shutdown time: {data}");
    if app.shutdown.is_none() {
        info!("Initializing shutdown handler.");
        let controller = app_controller::AppController::new(app.sender_proxy.clone());

        let Ok(()) = controller.send_event(data.to_string()) else {
            error!("Failed to send shutdown time");
            return;
        };
        app.shutdown = Some(controller);
        info!("Shutdown handler initialized.");
        app.set_text(format!("Shutdown scheduled for: {data}"));
        return;
    }

    let Some(shutdown) = app.shutdown.as_ref() else {
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

fn handle_quit(app: &mut Application, event_loop: &winit::event_loop::ActiveEventLoop) {
    info!("Quit menu item clicked, exiting event loop.");
    idler_utils::ExecState::stop();
    event_loop.exit();
    info!("Exiting event loop.");

    if let Some(tray_icon) = app.tray_icon.take() {
        info!("Destroying tray icon.");
        let res = tray_icon.set_icon(None);
        info!("Tray icon set to None, result: {res:?}");
    } else {
        warn!("No tray icon to destroy.");
    }

    let current_idle = app.idle_controller.take().map_or_else(
        || None,
        |idle_controller| {
            info!("Initiating close of idle controller.");
            idle_controller.init_close();
            Some(idle_controller)
        },
    );

    let current_shutdown = app.shutdown.take().map_or_else(
        || None,
        |shutdown| {
            info!("Initiating close of shutdown handler.");
            shutdown.init_close();
            Some(shutdown)
        },
    );

    let inner_registry = app.registry_watcher.take().map_or_else(
        || None,
        |registry_watcher| {
            info!("Initiating close of registry watcher.");
            registry_watcher.init_close();
            Some(registry_watcher)
        },
    );

    info!("Initiated close of all closable items.");

    if let Some(current_idle) = current_idle {
        info!("Waiting for idle controller to finish.");
        current_idle.wait_close();
        info!("Idle controller closed.");
    }

    if let Some(current_shutdown) = current_shutdown {
        info!("Waiting for shutdown handler to finish.");
        current_shutdown.wait_close();
        info!("Shutdown handler closed.");
    }

    if let Some(inner_registry) = inner_registry {
        info!("Waiting for registry watcher to finish.");
        inner_registry.wait_close();
        info!("Registry watcher closed.");
    }

    info!("Exiting after cleanup.");
}

fn handle_disable_shutdown(app: &mut Application) {
    info!("Disable shutdown menu item clicked, disabling shutdown.");
    if let Some(shutdown) = app.shutdown.take() {
        let status = shutdown.close(TIMEOUT);
        info!("Shutdown handler disabled, status: {status:?}");
    } else {
        warn!("No shutdown handler to disable.");
    }
    app.set_text(tray::DEFAULT.to_string());
}
