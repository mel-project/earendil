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

pub fn one_hop_closer(
    my_neighs: &[RelayFingerprint],
    graph: &RelayGraph,
    dest: RelayFingerprint,
) -> anyhow::Result<RelayFingerprint> {
    if my_neighs.is_empty() {
        anyhow::bail!("cannot route one hop closer since we don't have ANY neighbors!")
    }

    let mut shortest_route_len = usize::MAX;
    let mut next_hop = None;

    for neigh in my_neighs.iter() {
        if let Some(route) = graph.find_shortest_path(neigh, &dest) {
            if route.len() < shortest_route_len {
                shortest_route_len = route.len();
                next_hop = Some(*neigh);
            }
        }
    }

    next_hop
        .context(format!("cannot route one hop closer to {:?} since none of our neighbors ({:?}) could find a route there", dest, my_neighs))
}
