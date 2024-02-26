use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyctx::AnyCtx;
use chrono::{DateTime, Local};
use earendil_crypt::Fingerprint;
use egui::{mutex::Mutex, Color32};
use smol::block_on;

use crate::app::refresh_cell::RefreshCell;

use super::{config::Prefs, App};

pub fn render_chat(app: &App, ctx: &egui::Context, ui: &mut egui::Ui) {
    let mut daemon_cfg = app.daemon_cfg.lock();

    let chat_heading = if let Some(neigh) = daemon_cfg.gui_prefs.chatting_with {
        format!("Chatting with {neigh}")
    } else {
        "Chat".to_string()
    };

    ui.columns(2, |cols| {
        cols[0].vertical(|ui| ui.heading("Select a Peer"));
        cols[1].vertical(|ui| ui.heading(chat_heading));
    });
    ui.separator();

    if let Some(Ok(daemon)) = app.daemon.as_ref().and_then(|d| d.ready()) {
        let control = Arc::new(async_std::sync::Mutex::new(daemon.control()));
        let control_clone = control.clone();

        static NEIGHBORS: fn(&AnyCtx<()>) -> Mutex<RefreshCell<anyhow::Result<Vec<Fingerprint>>>> =
            |_| Mutex::new(RefreshCell::new());
        let mut neighbors = app.state.get(NEIGHBORS).lock();
        let neighbors = neighbors.get_or_refresh(Duration::from_millis(100), || {
            block_on(async move {
                let neighbors = control.lock().await.list_neighbors().await?;
                Ok(neighbors)
            })
        });

        ui.columns(2, |cols| {
            match neighbors {
                None => {
                    cols[0].label("Loading...");
                }
                Some(Err(err)) => {
                    cols[0].colored_label(Color32::DARK_RED, "Loading peers failed:");
                    cols[0].label(format!("{:?}", err));
                }
                Some(Ok(neighs)) => {
                    cols[0].vertical(|ui| {
                        for neigh in neighs {
                            if ui.button(neigh.to_string()).clicked() {
                                daemon_cfg.gui_prefs.chatting_with = Some(*neigh);
                            }
                        }
                    });
                }
            }

            static CHAT: fn(
                &AnyCtx<()>,
            )
                -> Mutex<RefreshCell<anyhow::Result<Vec<(bool, String, SystemTime)>>>> =
                |_| Mutex::new(RefreshCell::new());
            let mut chat = app.state.get(CHAT).lock();
            let chatting_with = daemon_cfg.gui_prefs.chatting_with;
            let chat = chat.get_or_refresh(Duration::from_millis(100), move || {
                if let Some(neigh) = chatting_with {
                    block_on(async move {
                        let chat = control_clone
                            .lock()
                            .await
                            .get_chat(neigh)
                            .await
                            .map_err(|e| anyhow::anyhow!("error pulling chat with {neigh}: {e}"))?;
                        Ok(chat)
                    })
                } else {
                    Ok(vec![])
                }
            });

            if let Some(neigh) = chatting_with {
                match chat {
                    None => {
                        cols[1].label("Loading...");
                    }

                    Some(Ok(chat)) => {
                        render_convo(
                            &mut cols[1],
                            chat.to_vec(),
                            daemon
                                .global_sk()
                                .expect("unable to get remote daemon pk")
                                .public()
                                .fingerprint(),
                            neigh,
                        );
                        let daemon = app.daemon.as_ref().and_then(|d| d.ready());
                        if let Some(Ok(_daemon)) = daemon {
                            if let Some(neigh) = chatting_with {
                                match neighbors {
                                    Some(Ok(neighs)) => {
                                        if neighs.contains(&neigh) {
                                            render_input(
                                                app,
                                                ctx,
                                                &mut cols[1],
                                                &mut daemon_cfg.gui_prefs,
                                                neigh,
                                            );
                                        }
                                    }
                                    _ => (),
                                }
                            }
                        }
                    }
                    Some(Err(err)) => {
                        cols[1].colored_label(Color32::DARK_RED, "Loading peers failed:");
                        cols[1].label(format!("{:?}", err));
                    }
                }
            }
        });
    }
}

fn render_convo(
    ui: &mut egui::Ui,
    tuple_chat: Vec<(bool, String, SystemTime)>,
    my_fp: Fingerprint,
    their_fp: Fingerprint,
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.set_height(ui.available_height() - 25.0);

        for (is_mine, msg, time) in tuple_chat {
            let time: DateTime<Local> = time.into();
            let time_str = format!("{}", time.format("%H:%M:%S"));

            if is_mine {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("[{time_str}]"));
                    render_fp(ui, my_fp);
                    ui.add(egui::Label::new(msg));
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("[{time_str}]"));
                    render_fp(ui, their_fp);
                    ui.add(egui::Label::new(msg));
                });
            }
        }
    });
}

fn render_fp(ui: &mut egui::Ui, fp: Fingerprint) {
    let bytes = fp.as_bytes();
    let r_bytes = &bytes[0..6];
    let g_bytes = &bytes[6..12];
    let b_bytes = &bytes[12..18];

    let mut r_acc: u8 = 0;
    let mut g_acc: u8 = 0;
    let mut b_acc: u8 = 0;

    for i in 0..6 {
        r_acc = r_acc.wrapping_add(r_bytes[i]);
        g_acc = g_acc.wrapping_add(g_bytes[i]);
        b_acc = b_acc.wrapping_add(b_bytes[i]);
    }

    ui.colored_label(
        egui::Color32::from_rgb(r_acc / 2, g_acc / 2, b_acc / 2),
        fp.to_string(),
    );
}

fn render_input(
    app: &App,
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    prefs: &mut Prefs,
    dest: Fingerprint,
) {
    ui.horizontal(|ui| {
        let response = ui.add(
            egui::TextEdit::singleline(&mut prefs.chat_msg)
                .desired_width(ui.available_width() - 50.0),
        );
        let enter_pressed = ctx.input(|input| input.key_pressed(egui::Key::Enter));

        if ui.button("Send").clicked() || enter_pressed {
            if let Some(Ok(daemon)) = app.daemon.as_ref().and_then(|d| d.ready()) {
                let msg = prefs.chat_msg.clone();
                let daemon = daemon.clone();
                std::thread::spawn(move || {
                    block_on(async move { daemon.control().send_chat_msg(dest, msg).await })
                });
                prefs.chat_msg.clear();
                response.request_focus();
            }
        }
    });
}
