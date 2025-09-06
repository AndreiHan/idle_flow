#![cfg(windows)]
use anyhow::Result;
use chrono::{Local, NaiveTime, TimeDelta};
use tracing::{error, info, trace};

#[inline]
fn get_time(time: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(time, "%H:%M").ok()
}

enum Status {
    NewTime(NaiveTime),
    Shutdown,
}

#[inline]
fn get_status(status: &str) -> Option<Status> {
    match status {
        "shutdown" => Some(Status::Shutdown),
        time if time.len() == 5 => get_time(time).map(Status::NewTime),
        _ => None,
    }
}

#[inline]
fn get_diff(received_time: NaiveTime) -> Option<std::time::Duration> {
    let now = Local::now().time();
    let diff = if let Ok(dur) = received_time.signed_duration_since(now).to_std() {
        dur
    } else {
        let Some(current_diff) = now
            .signed_duration_since(received_time)
            .checked_add(&TimeDelta::days(1))
        else {
            error!("Failed to add 1 day to time");
            return None;
        };
        match current_diff.to_std() {
            Ok(d) => d,
            Err(err) => {
                error!("Err converting {current_diff} to std, err: {err}");
                return None;
            }
        }
    };
    Some(diff)
}

#[inline]
fn check_close_condition(
    sender_proxy: &winit::event_loop::EventLoopProxy<tray::UserEvent>,
    data: &str,
) -> Option<std::time::Duration> {
    trace!("Received time: {data:?}");
    let Some(status) = get_status(data) else {
        info!("Received non time value, {data}. Returning");
        return None;
    };

    let Status::NewTime(received_time) = status else {
        return None;
    };

    trace!("Received time: {received_time:?}");
    let Some(diff) = get_diff(received_time) else {
        info!("Failed to get diff for time: {received_time:?}");
        return None;
    };

    let secs = diff.as_secs();
    trace!("Time difference in seconds: {secs}");
    if secs < 5 {
        info!("Shutdown");

        let event = tray::UserEvent::MenuEvent(tray_icon::menu::MenuEvent {
            id: tray_icon::menu::MenuId("quit".to_string()),
        });

        let status = sender_proxy.send_event(event);
        trace!("Sent shutdown event: {status:?}");
        return None;
    }
    info!("Scheduling shutdown in {diff:?}");
    Some(std::time::Duration::from_secs(diff.as_secs()))
}

pub struct AppController {
    close_handle: std::thread::JoinHandle<()>,
    sender: crossbeam::channel::Sender<String>,
}

impl AppController {
    #[must_use]
    pub fn new(sender_proxy: winit::event_loop::EventLoopProxy<tray::UserEvent>) -> Self {
        let (tx, rx) = crossbeam::channel::bounded(1);
        let handle = schedule_close(sender_proxy, rx);
        Self {
            close_handle: handle,
            sender: tx,
        }
    }

    /// Sends an event to the controller.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the event fails.
    pub fn send_event(&self, event: String) -> Result<()> {
        self.sender
            .send(event)
            .inspect_err(|e| error!("Failed to send event: {e}"))?;
        Ok(())
    }

    /// Closes the controller, sending a shutdown signal and waiting for the close handle to finish.
    ///
    /// # Errors
    ///
    /// Returns an error if sending the shutdown signal fails or if joining the close handle fails.
    pub fn close(self, timeout: std::time::Duration) -> Result<()> {
        let status = self.sender.send("shutdown".to_string());
        info!("Sent shutdown signal: {status:?}");
        mitigations::join_timeout(self.close_handle, timeout)
    }
}

#[inline]
fn schedule_close(
    proxy: winit::event_loop::EventLoopProxy<tray::UserEvent>,
    rx: crossbeam::channel::Receiver<String>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        info!("Starting shutdown handler thread");
        mitigations::set_priority(mitigations::Priority::BelowNormal);
        mitigations::hide_current_thread_from_debuggers();
        let Ok(data) = rx.recv() else {
            error!("Failed to receive data");
            return;
        };
        let mut current_data = data;
        let Some(mut diff) = check_close_condition(&proxy, &current_data) else {
            error!("Failed to get initial diff, exiting thread");
            return;
        };
        loop {
            trace!("Waiting for data with timeout: {diff:?}");
            let data: String = match rx.recv_timeout(diff) {
                Ok(val) => val,
                Err(err) => match err {
                    crossbeam::channel::RecvTimeoutError::Timeout => {
                        trace!("No data received, continuing");
                        let Some(new_diff) = check_close_condition(&proxy, &current_data) else {
                            return;
                        };
                        diff = new_diff;
                        continue;
                    }
                    crossbeam::channel::RecvTimeoutError::Disconnected => {
                        info!("Channel disconnected, exiting thread");
                        return;
                    }
                },
            };
            current_data = data;
            let Some(new_diff) = check_close_condition(&proxy, &current_data) else {
                return;
            };
            diff = new_diff;
        }
    })
}
