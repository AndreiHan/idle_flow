use chrono::{Local, NaiveTime, TimeDelta};
use std::{
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};
use tracing::{debug, error, info, trace};

#[must_use]
pub fn close_app_remote(rx: crossbeam::channel::Receiver<String>) -> JoinHandle<()> {
    thread::spawn(move || {
        info!("Starting shutdown handler thread");
        mitigations::hide_current_thread_from_debuggers();
        let mut _sender: Option<mpsc::Sender<()>> = None;
        loop {
            let hour = match rx.recv() {
                Ok(val) => val,
                Err(err) => {
                    info!("Received err: {err}");
                    return;
                }
            };
            if hour == "shutdown" {
                info!("Received shutdown signal, exiting");
                return;
            }
            debug!("Received time: {hour:?}");
            let Ok(received_time) = NaiveTime::parse_from_str(&hour, "%H:%M") else {
                info!("Received non time value, {hour}. Ignorring");
                _sender = None;
                continue;
            };
            let (sen, receiver) = mpsc::channel::<()>();
            _sender = Some(sen);

            trace!("Received time: {received_time:?}, spawning thread");
            thread::spawn(move || {
                mitigations::hide_current_thread_from_debuggers();
                loop {
                    let now = Local::now().time();
                    let diff = if let Ok(dur) = received_time.signed_duration_since(now).to_std() {
                        dur
                    } else {
                        let Some(current_diff) = now
                            .signed_duration_since(received_time)
                            .checked_add(&TimeDelta::days(1))
                        else {
                            error!("Failed to add 1 day to time");
                            break;
                        };
                        match current_diff.to_std() {
                            Ok(d) => d,
                            Err(err) => {
                                error!("Err converting {current_diff} to std, err: {err}");
                                break;
                            }
                        }
                    };

                    if diff.as_secs() == 0 {
                        info!("Shutdown");
                        idler_utils::ExecState::stop();
                        std::process::exit(0);
                    }
                    match receiver.recv_timeout(Duration::from_millis(500)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                            info!("Cancelling task for: {received_time}");
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                }
            });
        }
    })
}
