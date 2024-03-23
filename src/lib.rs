mod commands;
mod config;
mod context;
mod control_protocol;
mod daemon;
mod db;
mod debts;
mod dht;
mod global_rpc;
mod haven;
mod n2r;
mod n2r_socket;
mod network;
mod settlement;

mod pascal;
mod stream;

// Create the public API here.

pub use commands::ControlCommand;
pub use config::*;
pub use control_protocol::main_control;
pub use daemon::Daemon;
pub use haven::{HavenConnection, HavenEndpoint, HavenListener};
pub use n2r_socket::*;

fn log_error<E>(label: &str) -> impl FnOnce(E) + '_
where
    E: std::fmt::Debug,
{
    move |s| tracing::warn!("{label} restart, error: {:?}", s)
}
