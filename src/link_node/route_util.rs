use anyhow::Context;
use earendil_crypt::RelayFingerprint;
use earendil_packet::ForwardInstruction;
use earendil_topology::RelayGraph;

pub fn forward_route_to(
    graph: &RelayGraph,
    dest_fp: RelayFingerprint,
    num_peelers: usize,
) -> anyhow::Result<Vec<RelayFingerprint>> {
    let mut route = graph.rand_relays(num_peelers);
    route.push(dest_fp);
    tracing::trace!("forward route formed: {:?}", route);
    Ok(route)
}

pub fn route_to_instructs(
    graph: &RelayGraph,
    route: &[RelayFingerprint],
) -> anyhow::Result<Vec<ForwardInstruction>> {
    route
        .windows(2)
        .map(|wind| {
            let this = wind[0];
            let next = wind[1];

            let this_pubkey = graph
                .identity(&this)
                .context("failed to get an identity somewhere in our route")?
                .onion_pk;
            Ok(ForwardInstruction {
                this_pubkey,
                next_hop: next,
            })
        })
        .collect()
}
