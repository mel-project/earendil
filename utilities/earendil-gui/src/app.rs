mod config;
mod daemon_wrap;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use earendil::config::ConfigFile;
use egui::{
    mutex::Mutex, Color32, FontData, FontDefinitions, FontFamily, RichText, Shape, Visuals,
};
use poll_promise::Promise;
use tap::Tap;

use self::{config::ConfigState, daemon_wrap::DaemonWrap};

pub struct App {
    daemon: Option<Promise<DaemonWrap>>,
    daemon_cfg: Arc<Mutex<ConfigState>>,
    selected_tab: TabName,

    last_sync_time: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TabName {
    Dashboard,
    Chat,
    Settings,
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
            selected_tab: TabName::Dashboard,
            last_sync_time: Instant::now(),
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
            })
        });
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            // render the bottom panel here
            ui.horizontal_centered(|ui| {
                // render the little circle
                let circle_color: Color32;
                let label_text: String;
                match self.daemon.as_ref() {
                    Some(prom) => {
                        if prom.ready().is_some() {
                            circle_color = Color32::GREEN;
                            label_text = "Running".into();
                        } else {
                            circle_color = Color32::YELLOW;
                            label_text = "Connecting...".into();
                        }
                    }
                    None => {
                        circle_color = Color32::RED;
                        label_text = "Disconnected".into()
                    }
                }
                let (_, rect) = ui.allocate_space(egui::vec2(5.0, 5.0));
                ui.painter()
                    .add(Shape::circle_filled(rect.center(), 5.0, circle_color));
                ui.label(label_text);

                if ui.button("Restart").clicked() {}
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| match self.selected_tab {
            TabName::Dashboard => self.render_dashboard(ctx, ui),
            TabName::Chat => self.render_chat(ctx, ui),
            TabName::Settings => self.render_settings(ctx, ui),
        });

        // sync if it's been a while since our last sync
        if self.last_sync_time.elapsed() > Duration::from_secs(1) {
            self.last_sync_time = Instant::now();
            let daemon_cfg = self.daemon_cfg.clone();
            std::thread::spawn(move || {
                let _ = daemon_cfg.lock().save();
            });
        }
    }
}

impl App {
    fn render_dashboard(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.columns(2, |cols| {
            cols[0].vertical(|ui| ui.heading("Peers"));
            cols[1].vertical(|ui| ui.heading("Stats"));
        });
    }

    fn render_chat(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.columns(3, |cols| {
            cols[0].vertical(|ui| ui.heading("Select peer"));
            cols[1].vertical(|ui| ui.heading("Chat"));
        });
    }

    fn render_settings(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();
        ui.heading("Earendil config");
        if let Err(err) = self.daemon_cfg.lock().realize() {
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
        ui.centered_and_justified(|ui| ui.code_editor(&mut self.daemon_cfg.lock().raw_yaml));
    }
}
