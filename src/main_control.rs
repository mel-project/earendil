use anyhow::Context;
use chrono::{DateTime, NaiveDateTime};
use colored::{ColoredString, Colorize};

use nanorpc::RpcTransport;
use nanorpc_http::client::HttpRpcTransport;
use serde_yaml;
use std::net::SocketAddr;

use crate::ChatEntry;

pub async fn main_control(
    method: String,
    args: Vec<String>,
    json: bool,
    connect: SocketAddr,
) -> anyhow::Result<()> {
    let control =
        HttpRpcTransport::new_with_proxy(connect.to_string(), nanorpc_http::client::Proxy::Direct);
    let args: Result<Vec<serde_json::Value>, _> =
        args.into_iter().map(|a| serde_yaml::from_str(&a)).collect();
    let args = args.context("arguments not YAML")?;
    let res = control.call(&method, &args).await?;
    let res = res.ok_or_else(|| anyhow::anyhow!("method not found"))?;
    let output = match res {
        Ok(val) => val,
        Err(err) => serde_json::to_value(err)?,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", serde_yaml::to_string(&output)?);
    }
    Ok(())
}

fn earendil_blue(string: &str) -> ColoredString {
    string
        .custom_color(colored::CustomColor {
            r: 0,
            g: 129,
            b: 162,
        })
        .bold()
}

fn left_arrow() -> ColoredString {
    earendil_blue("<-")
}

fn right_arrow() -> ColoredString {
    earendil_blue("->")
}

fn pretty_entry(entry: &ChatEntry) -> String {
    let date_time = DateTime::from_timestamp(entry.timestamp, 0)
        .unwrap()
        .naive_local();
    let arrow = if entry.is_outgoing {
        right_arrow()
    } else {
        left_arrow()
    };

    format!("{} {} {}", arrow, entry.text, pretty_time(date_time))
}

fn pretty_time(date_time: NaiveDateTime) -> ColoredString {
    format!("[{}]", date_time.format("%Y-%m-%d %H:%M:%S")).bright_yellow()
}

fn format_timestamp(timestamp: i64) -> String {
    let date_time = DateTime::from_timestamp(timestamp, 0)
        .unwrap()
        .naive_local();
    format!("[{}]", date_time.format("%Y-%m-%d %H:%M:%S"))
}
