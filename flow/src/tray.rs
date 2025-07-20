use chrono::{NaiveTime, Timelike};
use tracing::trace;
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuItem, Submenu},
};

const RAW_ICON: &[u8] = include_bytes!("../../resources/icon.png");

pub fn next_half_hours() -> Vec<NaiveTime> {
    let now = chrono::Local::now().time();
    let mut times = Vec::new();
    let mut minute = if now.minute() < 30 { 30 } else { 0 };
    let mut hour = now.hour();
    if minute == 0 {
        hour += 1;
    }
    for _ in 0..8 {
        let t = NaiveTime::from_hms_opt(hour % 24, minute, 0).unwrap();
        times.push(t);
        minute += 30;
        if minute == 60 {
            minute = 0;
            hour += 1;
        }
    }
    trace!("Next half hours: {:?}", times);
    times
}

pub(crate) fn get_default_icon() -> Result<tray_icon::Icon, Box<dyn std::error::Error>> {
    get_icon(RAW_ICON)
}

pub fn get_icon(bytes: &[u8]) -> Result<tray_icon::Icon, Box<dyn std::error::Error>> {
    use image::GenericImageView;

    let img = image::load_from_memory(bytes)?;
    let pixels = img
        .pixels()
        .flat_map(|(_, _, pixel)| pixel.0)
        .collect::<Vec<_>>();

    Ok(tray_icon::Icon::from_rgba(
        pixels,
        img.width(),
        img.height(),
    )?)
}

pub fn get_menu() -> Result<Menu, Box<dyn std::error::Error>> {
    let submenu_items = next_half_hours()
        .iter()
        .map(|t| {
            let label = format!("{:02}:{:02}", t.hour(), t.minute());
            MenuItem::with_id(label.clone(), label, true, None)
        })
        .collect::<Vec<_>>();

    let submenu = Submenu::new("Shutdown at", true);

    for item in submenu_items {
        submenu.append(&item)?;
    }
    let quit_item = MenuItem::with_id("quit", "Quit", true, None);
    Ok(Menu::with_items(&[&submenu, &quit_item])?)
}

pub fn get_tray() -> Result<TrayIcon, Box<dyn std::error::Error>> {
    let icon = get_default_icon()?;
    Ok(TrayIconBuilder::new()
        .with_menu(Box::new(get_menu()?))
        .with_icon(icon)
        .with_tooltip("Flow is running.")
        .build()?)
}
