![](https://www.gitbook.com/cdn-cgi/image/width=40,dpr=2,height=40,fit=contain,format=auto/https%3A%2F%2F2883814063-files.gitbook.io%2F~%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FJ1kEaMoiT7xVUWAPVbNQ%252Ficon%252FSVWPlrZB5aoRflZ3Mvqp%252Fpath856.png%3Falt%3Dmedia%26token%3D58e9a929-7718-43ef-8d62-12d9475b0e5d)

# About

Earendil is a decentralized, censorship-resistant packet-routing overlay network designed for performance and censorship resistance. It enables secure and private communication between nodes, even against powerful state-level adversaries.

Currently, the project is extremely early-stage and not ready to use. Stay tuned for updates!

## Key Features

- Robust censorship resistance
- Confederal, non-egalitarian topology
- Decentralized, sybil-resistant incentives based on micropayments
- User-tunable anonymity/performance tradeoff

## User documentation

Detailed info can be found in the **[Earendil documentation](https://docs.earendil.network)**.

# Developers

## Layout of the crate

This repository is laid out as a [Cargo workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html).

The primary, "root" crate is `earendil`, the primary daemon intended to be run on any machine that wishes to access Earendil (similar to the `tor` daemon for Tor).

Other crates live in `libraries/`:

- `earendil_packet` implements structs for the Earendil packet format at different layers of the protocol, such as the onion-encrypted mixnet format and the format that carries the end-to-end application messages.
- `earendil_topology` implements functionality for Earendil's relay graph, including helper functions for gossip

Overall, we follow an architecture where the crates in `libraries/` avoid doing any I/O, and instead implement data types. Actual communication is done by the `earendil` daemon.

## Quick example

See [the docs](https://docs.earendil.network/getting-started/quick-start)
