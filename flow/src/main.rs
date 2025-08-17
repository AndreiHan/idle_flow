#![cfg(windows)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use tracing::{error, trace};

fn main() {
    #[cfg(debug_assertions)]
    let _ = tracing_subscriber::fmt()
        .compact()
        .with_max_level(tracing::Level::TRACE)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_ansi(true)
        .try_init();

    trace!("Initializing Flow application, pid: {}", std::process::id());
    mitigations::enable_mitigations();

    trace!("Starting Flow application");
    if !std::env::args().any(|arg| arg == "--restart") {
        trace!("Restarting Flow application");
        if mitigations::restart_self().is_err() {
            error!("Failed to restart Flow application");
        }
        std::process::exit(0);
    }
    idler_utils::ExecState::start();

    let Ok(event_loop) = winit::event_loop::EventLoop::<tray::UserEvent>::with_user_event().build()
    else {
        error!("Failed to create event loop");
        return;
    };

    let tray_icon_proxy = event_loop.create_proxy();
    tray_icon::TrayIconEvent::set_event_handler(Some(move |event| {
        let status = tray_icon_proxy.send_event(tray::UserEvent::TrayIconEvent(event));
        if let Err(err) = status {
            error!("Failed to send tray icon event: {err:?}");
        }
    }));

    let menu_proxy = event_loop.create_proxy();
    tray_icon::menu::MenuEvent::set_event_handler(Some(move |event| {
        let status = menu_proxy.send_event(tray::UserEvent::MenuEvent(event));
        if let Err(err) = status {
            error!("Failed to send menu event: {err:?}");
        }
    }));
    mitigations::set_priority(mitigations::Priority::Lowest);

    let mut app = app::Application::new(event_loop.create_proxy());
    if let Err(err) = event_loop.run_app(&mut app) {
        error!("Run Error: {err:?}");
        return;
    }
    trace!("Flow application exited successfully");
    #[cfg(debug_assertions)]
    {
        std::process::exit(0);
    }
}
