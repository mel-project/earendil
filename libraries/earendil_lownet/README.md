# earendil_lownet: low-level network of Earendil

This crate implements the low-level network of Earendil, which is a vaguely IP-like network with no mixnet features.

## Code architecture

The `LowNet` structure exposes the public API, which is essentially a raw "socket" for sending and receiving datagrams.

Datagrams are then routed into specific `Link`s.

`Link`s are organized into a `LinkTable`, indexed by `NodeAddr`. The `LinkTable` can include multiple entries corresponding to the same `NodeAddr`, which allows for load-balancing and such, while avoiding issues with overwriting.

## Link authentication

One must prevent a random guy from stealing somebody else's globally routable `NodeAddr` by claiming to be a particular client at a particular node.

This is prevented by a basic "accounting" procedure:
- When the client connects to a neighboring relay, it provides a random persistent bearer secret identifying itself. This is also the string used to key e.g. payment accounts.
- The relay assigns an ID based on this random bearer secret. This assignment can be done either through a persistent mapping, or through some deterministic pseudorandom process.

This way, somebody else with a different bearer secret will not get assigned the same ID.