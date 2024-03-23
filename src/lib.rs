pub mod commands;
pub mod config;
mod context;
pub mod control_protocol;
pub mod daemon;
mod db;
mod debts;
mod dht;
mod global_rpc;
mod haven;
mod haven_util;
mod n2r;
mod network;
mod settlement;
pub mod socket;

mod pascal;
pub mod stream;

fn log_error<E>(label: &str) -> impl FnOnce(E) + '_
where
    E: std::fmt::Debug,
{
    move |s| tracing::warn!("{label} restart, error: {:?}", s)
}
