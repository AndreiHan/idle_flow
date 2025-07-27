#![cfg(windows)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use tracing::{error, trace};
use tray::UserEvent;

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
    let Ok(event_loop) = winit::event_loop::EventLoop::<UserEvent>::with_user_event().build()
    else {
        error!("Failed to create event loop");
        std::process::exit(1);
    };

    let proxy = event_loop.create_proxy();
    tray_icon::TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::TrayIconEvent(event));
    }));

    let proxy = event_loop.create_proxy();
    tray_icon::menu::MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::MenuEvent(event));
    }));

    idler_utils::ExecState::start();

    let sender_proxy = event_loop.create_proxy();

    let mut app = app::Application::new(sender_proxy.clone());
    if let Err(err) = event_loop.run_app(&mut app) {
        error!("Run Error: {err:?}");
        std::process::exit(2);
    }
}
