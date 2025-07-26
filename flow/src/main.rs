#![cfg(windows)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use tracing::{error, trace};
mod app;
mod tray;

fn main() {
    mitigations::enable_mitigations();
    #[cfg(debug_assertions)]
    {
        let _ = tracing_subscriber::fmt()
            .compact()
            .with_max_level(tracing::Level::TRACE)
            .with_line_number(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_ansi(true)
            .try_init();
    }
    trace!("Starting Flow application");
    let Ok(event_loop) = winit::event_loop::EventLoop::<app::UserEvent>::with_user_event().build()
    else {
        error!("Failed to create event loop");
        std::process::exit(1);
    };

    let proxy = event_loop.create_proxy();
    tray_icon::TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(app::UserEvent::TrayIconEvent(event));
    }));

    let proxy = event_loop.create_proxy();
    tray_icon::menu::MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(app::UserEvent::MenuEvent(event));
    }));

    idler_utils::ExecState::start();

    let mut app = app::Application::default();
    if let Err(err) = event_loop.run_app(&mut app) {
        error!("Error: {err:?}");
        std::process::exit(1);
    }
}
