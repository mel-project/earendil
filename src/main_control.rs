use anyhow::Context;
use colored::{ColoredString, Colorize};

use nanorpc::RpcTransport;
use nanorpc_http::client::HttpRpcTransport;
use serde_yaml;
use std::net::SocketAddr;

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
