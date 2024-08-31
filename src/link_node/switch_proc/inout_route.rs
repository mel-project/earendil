use std::sync::Arc;

use bytes::Bytes;
use earendil_crypt::{ClientId, RelayIdentityPublic, RelayIdentitySecret};

use futures_util::AsyncReadExt;
use haiyuu::{Process, WeakHandle};
use nanorpc::RpcService;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sillad::{
    dialer::{Dialer, DialerExt},
    listener::Listener,
};
use sillad_sosistab3::Cookie;
use smol::io::AsyncWriteExt;

use crate::{
    config::{InRouteConfig, OutRouteConfig},
    link_node::switch_proc::{read_pascal, write_pascal},
};

use super::{link_proc::LinkProcess, SwitchMessage, SwitchProcess};

pub async fn process_in_route(
    in_route: InRouteConfig,
    switch: WeakHandle<SwitchProcess>,
    rpc_serve: Option<impl RpcService>,
) -> anyhow::Result<()> {
    let listener = sillad::tcp::TcpListener::bind(in_route.listen).await?;
    let mut listener = match in_route.obfs {
        crate::config::ObfsConfig::None => sillad::listener::EitherListener::Left(listener),
        crate::config::ObfsConfig::Sosistab3(cookie) => sillad::listener::EitherListener::Right(
            sillad_sosistab3::listener::SosistabListener::new(listener, Cookie::new(&cookie)),
        ),
    };
    let rpc_serve = rpc_serve.map(Arc::new);
    loop {
        let mut pipe = listener.accept().await?;
        let switch = switch.clone();
        let rpc_serve = rpc_serve.clone();
        smolscale::spawn(async move {
            // challenge the other side
            let mut challenge = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut challenge);
            pipe.write_all(&challenge).await?;
            // Read the challenge response
            let charesp = read_pascal(&mut pipe).await?;
            let charesp: ChallengeResponse = ciborium::from_reader(&charesp[..])?;
            let remote = match charesp {
                ChallengeResponse::Client(id) => either::Either::Right(id),
                ChallengeResponse::Relay {
                    identity,
                    challenge_sig,
                } => {
                    let to_sign = blake3::derive_key("earendil-link-auth-1", &challenge);
                    identity.verify(&to_sign, &challenge_sig)?;
                    either::Either::Left(identity.fingerprint())
                }
            };
            // Construct the link process and attach to switch
            let link = LinkProcess::new(switch.clone(), remote, rpc_serve, pipe).spawn_smolscale();
            match remote {
                either::Either::Right(id) => {
                    switch.send(SwitchMessage::NewClientLink(link, id)).await?;
                }
                either::Either::Left(fp) => {
                    switch.send(SwitchMessage::NewRelayLink(link, fp)).await?;
                }
            }
            anyhow::Ok(())
        })
        .detach();
    }
}

pub async fn process_out_route(
    out_route: OutRouteConfig,
    switch: WeakHandle<SwitchProcess>,

    my_identity: either::Either<RelayIdentitySecret, ClientId>,
    rpc_serve: Option<impl RpcService>,
) -> anyhow::Result<()> {
    let rpc_serve = rpc_serve.map(Arc::new);
    loop {
        let addrs = smol::net::resolve(out_route.connect.clone()).await?;
        let dialer = sillad::tcp::HappyEyeballsTcpDialer(addrs);

        let dialer = match &out_route.obfs {
            crate::config::ObfsConfig::None => dialer.dynamic(),
            crate::config::ObfsConfig::Sosistab3(cookie) => {
                sillad_sosistab3::dialer::SosistabDialer {
                    inner: dialer,
                    cookie: Cookie::new(cookie),
                }
                .dynamic()
            }
        };
        let mut pipe = dialer.dial().await?;
        // read the challenge here
        let mut challenge = [0u8; 32];
        pipe.read_exact(&mut challenge).await?;
        // respond to the challenge
        let resp = match my_identity {
            either::Either::Left(relay) => {
                let to_sign = blake3::derive_key("earendil-link-auth-1", &challenge);
                let sig = relay.sign(&to_sign);
                ChallengeResponse::Relay {
                    identity: relay.public(),
                    challenge_sig: sig,
                }
            }
            either::Either::Right(id) => ChallengeResponse::Client(id),
        };
        let mut buf = vec![];
        ciborium::into_writer(&resp, &mut buf)?;
        write_pascal(&buf, &mut pipe).await?;
        // spawn the link process
        let link = LinkProcess::new(
            switch.clone(),
            either::Either::Left(out_route.fingerprint),
            rpc_serve.clone(),
            pipe,
        )
        .spawn_smolscale();
        switch
            .send(SwitchMessage::NewRelayLink(
                link.clone(),
                out_route.fingerprint,
            ))
            .await?;
        // wait for the link process
        tracing::debug!(
            remote = debug(out_route.fingerprint),
            "link initialized, waiting for death..."
        );
        link.wait().await;
    }
}

#[derive(Serialize, Deserialize)]
enum ChallengeResponse {
    Client(ClientId),
    Relay {
        identity: RelayIdentityPublic,
        challenge_sig: Bytes,
    },
}
