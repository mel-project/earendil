#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::thread;

use subscriber::VecLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::subscriber::LOGS;

mod app;
mod subscriber;

fn main() -> eframe::Result<()> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive("earendil=debug".parse().unwrap())
                .from_env_lossy(),
        )
        //
        .with(VecLayer)
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([300.0, 220.0]),
        ..Default::default()
    };
    eframe::run_native(
        "earendil",
        native_options,
        Box::new(|cc| Box::new(app::App::new(cc))),
    )?;
    Ok(())
}
