use std::{sync::Arc, time::Duration};

use anyctx::AnyCtx;
use chrono::DateTime;
use earendil::{ChatEntry, NeighborId};

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

        static NEIGHBORS: fn(&AnyCtx<()>) -> Mutex<RefreshCell<anyhow::Result<Vec<NeighborId>>>> =
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

            static CHAT: fn(&AnyCtx<()>) -> Mutex<RefreshCell<anyhow::Result<Vec<ChatEntry>>>> =
                |_| Mutex::new(RefreshCell::new());
            let mut chat = app.state.get(CHAT).lock();
            let chatting_with = daemon_cfg.gui_prefs.chatting_with;
            let chat = chat.get_or_refresh(Duration::from_millis(100), move || {
                if let Some(neigh) = chatting_with {
                    Ok(block_on(async move {
                        control_clone
                            .lock()
                            .await
                            .get_chat(neigh.to_string())
                            .await
                            .map_err(|e| {
                                earendil::control_protocol::ChatError::Get(format!(
                                    "error pulling chat with {neigh}: {e}"
                                ))
                            })?
                    })?)
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
                        render_convo(&mut cols[1], chat.to_vec(), daemon.identity(), neigh);
                        let daemon = app.daemon.as_ref().and_then(|d| d.ready());
                        if let Some(Ok(_daemon)) = daemon {
                            if let Some(neigh) = chatting_with {
                                if let Some(Ok(neighs)) = neighbors {
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
    tuple_chat: Vec<ChatEntry>,
    my_fp: NeighborId,
    their_fp: NeighborId,
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.set_height(ui.available_height() - 25.0);

        for ChatEntry {
            text,
            timestamp,
            is_outgoing,
        } in tuple_chat
        {
            let local_date_time = DateTime::from_timestamp(timestamp, 0)
                .unwrap()
                .naive_local();
            let time_str = format!("{}", local_date_time.format("%H:%M:%S"));

            if is_outgoing {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("[{time_str}]"));
                    color_id(ui, my_fp);
                    ui.add(egui::Label::new(text));
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("[{time_str}]"));
                    color_id(ui, their_fp);
                    ui.add(egui::Label::new(text));
                });
            }
        }
    });
}

fn color_id(ui: &mut egui::Ui, id: NeighborId) {
    let (hash, id) = match id {
        NeighborId::Relay(fp) => (blake3::hash(fp.as_bytes()), fp.to_string()),
        NeighborId::Client(id) => (blake3::hash(&id.to_be_bytes()), id.to_string()),
    };

    let r: u8 = hash.as_bytes()[0] / 2;
    let g: u8 = hash.as_bytes()[1] / 2;
    let b: u8 = hash.as_bytes()[2] / 2;

    ui.colored_label(egui::Color32::from_rgb(r, g, b), id);
}

fn render_input(
    app: &App,
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    prefs: &mut Prefs,
    dest: NeighborId,
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
                    block_on(async move { daemon.control().send_chat(dest.to_string(), msg).await })
                });
                prefs.chat_msg.clear();
                response.request_focus();
            }
        }
    });
}
