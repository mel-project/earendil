# earendil_lownet: low-level network of Earendil

This crate implements the low-level network of Earendil, which is a vaguely IP-like network with no mixnet features.

## Code architecture

The `LowNet` structure exposes the public API, which is essentially a raw "socket" for sending and receiving datagrams.

Datagrams are then routed into specific `Link`s.

`Link`s are organized into a `LinkTable`, indexed by `NodeAddr`. The `LinkTable` can include multiple entries corresponding to the same `NodeAddr`, which allows for load-balancing and such, while avoiding issues with overwriting.