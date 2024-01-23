mod config;
mod daemon_wrap;
mod modal_state;
mod refresh_cell;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyctx::AnyCtx;
use anyhow::Context;
use earendil::daemon::Daemon;
use egui::{
    mutex::Mutex, Color32, FontData, FontDefinitions, FontFamily, FontId, RichText, Shape,
    TextStyle, Visuals,
};
use egui_modal::Modal;
use poll_promise::Promise;
use smol::future::block_on;
use tap::Tap;

use crate::{app::refresh_cell::RefreshCell, subscriber::LOGS};

use self::{
    config::{ConfigState, DaemonMode},
    daemon_wrap::DaemonWrap,
    modal_state::{ModalState, Severity},
};

pub struct App {
    daemon: Option<Promise<anyhow::Result<DaemonWrap>>>,
    daemon_cfg: Arc<Mutex<ConfigState>>,
    selected_tab: TabName,
    modal: Arc<Mutex<Option<ModalState>>>,

    state: AnyCtx<()>,

    last_sync_time: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TabName {
    Dashboard,
    Chat,
    Settings,
    Logs,
}

impl App {
    /// Constructs the app.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // light mode
        cc.egui_ctx.set_visuals(
            Visuals::light()
                .tap_mut(|vis| vis.widgets.noninteractive.fg_stroke.color = Color32::BLACK),
        );

        // set up fonts. currently this uses SC for CJK, but this can be autodetected instead.
        let mut fonts = FontDefinitions::default();
        fonts.font_data.insert(
            "sarasa_sc".into(),
            FontData::from_static(include_bytes!("assets/SarasaUiSC-Regular.ttf")),
        );
        fonts
            .families
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .insert(0, "sarasa_sc".into());
        cc.egui_ctx.set_fonts(fonts);
        Self {
            daemon: None,
            daemon_cfg: Arc::new(Mutex::new(ConfigState::load().unwrap_or_default())),
            modal: Default::default(),
            selected_tab: TabName::Dashboard,
            last_sync_time: Instant::now(),
            state: AnyCtx::new(()),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, TabName::Dashboard, "Dashboard");
                ui.selectable_value(&mut self.selected_tab, TabName::Chat, "Chat");
                ui.selectable_value(&mut self.selected_tab, TabName::Settings, "Settings");
                ui.selectable_value(&mut self.selected_tab, TabName::Logs, "Logs");
            })
        });
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| self.render_bottom_panel(ctx, ui));
        egui::CentralPanel::default().show(ctx, |ui| match self.selected_tab {
            TabName::Dashboard => self.render_dashboard(ctx, ui),
            TabName::Chat => self.render_chat(ctx, ui),
            TabName::Settings => self.render_settings(ctx, ui),
            TabName::Logs => self.render_logs(ctx, ui),
        });

        // sync if it's been a while since our last sync
        if self.last_sync_time.elapsed() > Duration::from_secs(1) {
            self.last_sync_time = Instant::now();
            let daemon_cfg = self.daemon_cfg.clone();
            std::thread::spawn(move || {
                daemon_cfg.lock().save().unwrap();
            });
        }

        // modal
        let mut modal_state = self.modal.lock();
        let modal = Modal::new(ctx, "warning");
        modal.show(|ui| {
            if let Some(ModalState(severity, message)) = modal_state.as_ref() {
                match severity {
                    Severity::Info => modal.title(ui, "Info"),
                    Severity::Error => modal.title(ui, "Error"),
                }
                modal.body(ui, message);
            }
            modal.buttons(ui, |ui| {
                if modal.button(ui, "Okay").clicked() {
                    *modal_state = None;
                }
            });
        });
        if modal_state.is_some() {
            modal.open();
        }
    }
}

impl App {
    fn render_dashboard(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.columns(2, |cols| {
                cols[0].vertical(|ui| ui.heading("Peers"));
                cols[1].vertical(|ui| ui.heading("Stats"));
            });
            ui.separator();
            ui.heading("Graph dump");
            if let Some(Ok(daemon)) = self.daemon.as_ref().and_then(|d| d.ready()) {
                static GRAPH_DUMP: fn(&AnyCtx<()>) -> Mutex<RefreshCell<anyhow::Result<String>>> =
                    |_| Mutex::new(RefreshCell::new());

                let control = daemon.control();
                let mut dump = self.state.get(GRAPH_DUMP).lock();
                let dump = dump.get_or_refresh(Duration::from_millis(100), || {
                    block_on(async move {
                        let dump = control.graph_dump(true).await?;
                        Ok(dump)
                    })
                });
                match dump {
                    None => {
                        ui.label("Loading...");
                    }
                    Some(Err(err)) => {
                        ui.colored_label(Color32::DARK_RED, "Loading graph failed:");
                        ui.label(format!("{:?}", err));
                    }
                    Some(Ok(dump)) => {
                        ui.centered_and_justified(|ui| ui.code_editor(&mut dump.as_str()));
                    }
                }
            }
        });
    }

    fn render_chat(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.columns(3, |cols| {
            cols[0].vertical(|ui| ui.heading("Select peer"));
            cols[1].vertical(|ui| ui.heading("Chat"));
        });
    }

    fn render_settings(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let mut daemon_cfg = self.daemon_cfg.lock();
        ui.heading("Settings");
        egui::ComboBox::from_label("Daemon mode")
            .selected_text(format!("{:?}", daemon_cfg.gui_prefs.daemon_mode))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut daemon_cfg.gui_prefs.daemon_mode,
                    DaemonMode::Embedded,
                    "Embedded",
                );
                ui.selectable_value(
                    &mut daemon_cfg.gui_prefs.daemon_mode,
                    DaemonMode::Remote,
                    "Remote",
                );
            });
        ui.separator();
        ui.heading("Earendil config");
        if let Err(err) = daemon_cfg.realize() {
            ui.label(
                RichText::new(format!("invalid config: {:?}", err))
                    .background_color(Color32::LIGHT_RED),
            );
        } else {
            ui.label(
                RichText::new("config successfully validated!")
                    .background_color(Color32::LIGHT_GREEN),
            );
        }
        ui.centered_and_justified(|ui| {
            egui::ScrollArea::vertical().show(ui, |ui| ui.code_editor(&mut daemon_cfg.raw_yaml))
        });
    }

    fn render_bottom_panel(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        // render the bottom panel here
        ui.horizontal_centered(|ui| {
            // render the little circle
            let circle_color: Color32;
            let label_text: String;
            match self.daemon.as_ref() {
                Some(prom) => match prom.ready() {
                    None => {
                        circle_color = Color32::from_rgb(0xff, 0xd7, 0x00);
                        label_text = "Connecting...".into();
                    }
                    Some(Ok(daemon)) => {
                        circle_color = Color32::GREEN;
                        label_text = "Running".into();
                    }
                    Some(Err(err)) => {
                        circle_color = Color32::RED;
                        label_text = "Dead".into();
                        self.modal
                            .lock()
                            .replace(ModalState(Severity::Error, format!("{:?}", err)));
                        self.daemon = None;
                    }
                },
                None => {
                    circle_color = Color32::RED;
                    label_text = "Disconnected".into()
                }
            }
            let (_, rect) = ui.allocate_space(egui::vec2(7.0, 7.0));
            ui.painter()
                .add(Shape::circle_filled(rect.center(), 7.0, circle_color));
            ui.label(&label_text);
            // here we handle the daemon-starting and daemon-stopping logic.
            if label_text == "Disconnected" && ui.button("Start").clicked() {
                let daemon_cfg = self.daemon_cfg.lock().raw_yaml.clone();
                self.daemon = Some(Promise::spawn_thread("daemon-starter", move || {
                    std::env::set_current_dir(config::earendil_config_dir())?;
                    let config_file =
                        serde_yaml::from_str(&daemon_cfg).context("could not parse config file")?;
                    let daemon = Daemon::init(config_file).context("cannot start daemon")?;
                    smol::future::block_on(daemon.control_client().graph_dump(false))
                        .context("could not get graph dump")?;
                    Ok(DaemonWrap::Embedded(daemon))
                }))
            }

            if label_text == "Running" && ui.button("Stop").clicked() {
                self.daemon = None;
            }
        });
    }

    fn render_logs(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.heading("Logs");
        let logs = LOGS.read().unwrap();
        let mut logs_str = logs.iter().fold(String::new(), |init, x| init + "\n" + x);

        ui.centered_and_justified(|ui| {
            egui::ScrollArea::vertical().show(ui, |ui| ui.code_editor(&mut logs_str.as_str()))
        });
    }
}
