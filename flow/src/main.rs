#![cfg(windows)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::process::ExitCode;
use tracing::{error, trace};

#[cfg(debug_assertions)]
const GIT_COMMIT_SHA: &str = env!("GIT_COMMIT_SHA");
#[cfg(debug_assertions)]
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    init_app();
    if !std::env::args().any(|arg| arg == "--clean") {
        trace!("Restarting Flow application");
        let res = mitigations::restart_self();
        if let Err(err) = res {
            error!("Failed to restart Flow application: {err}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let exit_code = run_app();
    trace!("Flow application exited with code: {exit_code:?}");

    mitigations::free_console();
    exit_code
}

fn init_app() {
    #[cfg(debug_assertions)]
    let _ = tracing_subscriber::fmt()
        .compact()
        .log_internal_errors(true)
        .with_max_level(tracing::Level::TRACE)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_ansi(true)
        .try_init();

    #[cfg(debug_assertions)]
    trace!("Starting Flow application, \nVersion: {VERSION}\nGit Commit SHA: {GIT_COMMIT_SHA}");

    mitigations::enable_mitigations();
    idler_utils::ExecState::start();
}

fn run_app() -> ExitCode {
    let Ok(_guard) = idler_utils::single_instance::get_single_instance_guard() else {
        error!("Another instance of Flow is already running");
        return ExitCode::FAILURE;
    };

    let Ok(event_loop) = winit::event_loop::EventLoop::<tray::UserEvent>::with_user_event().build()
    else {
        error!("Failed to create event loop");
        return ExitCode::FAILURE;
    };
    setup_event_loop(&event_loop);

    let mut app = app::Application::new(event_loop.create_proxy());
    if let Err(err) = event_loop.run_app(&mut app) {
        error!("Run Error: {err:?}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn setup_event_loop(event_loop: &winit::event_loop::EventLoop<tray::UserEvent>) {
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
}
