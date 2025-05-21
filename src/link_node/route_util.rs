use anyhow::Context;
use earendil_crypt::RelayFingerprint;
use earendil_packet::ForwardInstruction;
use earendil_topology::{NodeAddr, RelayGraph};
use rand::prelude::*;

pub fn forward_route_to(
    graph: &RelayGraph,
    dest_fp: RelayFingerprint,
    num_peelers: usize,
) -> anyhow::Result<Vec<NodeAddr>> {
    let mut route: Vec<NodeAddr> = graph
        .rand_relays(num_peelers)
        .into_iter()
        .map(|fp| NodeAddr::new(fp, 0))
        .collect();
    route.push(NodeAddr::new(dest_fp, 0));
    tracing::trace!("forward route formed: {:?}", route);
    Ok(route)
}

pub fn route_to_instructs(
    graph: &RelayGraph,
    route: &[NodeAddr],
) -> anyhow::Result<Vec<ForwardInstruction>> {
    route
        .windows(2)
        .map(|wind| {
            let this = wind[0].relay;
            let next = wind[1];

            let this_pubkey = graph
                .identity(this)
                .context("failed to get an identity somewhere in our route")?
                .onion_pk;
            Ok(ForwardInstruction {
                this_pubkey,
                next_hop: next,
            })
        })
        .collect()
}
