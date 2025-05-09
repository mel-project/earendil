# Refactoring the lowest level

## Addresses

Having addresses be uniformly globally routable would be nice. This can be accomplished by

```rust
pub struct NodeAddr {
    pub relay: RelayFingerprint,
    pub client_id: u64
}
```

serialized as `na-[hex]-[client_id]`

where a `client_id` of 0 indicates the relay itself.

This allows us to have a low-level IP-like layer where every node can reach every other node with an arbitrary datagram. That will also be the layer that all bandwidth / cost accounting happens, since we assume that bandwidth is the cost bottleneck in the entire stack.

This also means that if a node has $n$ neighbors, then it has either $n$ or $n+1$ addresses (depending on whether it's a client or relay). A helper function can sort these in order of importance.

## Network layer code

There's a *relay-specific* part and an *invariant* part.

The invariant part is that to send a datagram to an address, we pick the link that goes closest to the destination address and go for it. And all incoming datagrams addressed to us get put into a big queue that a `recv()` method pops.

The relay-specific part is that incoming datagrams addressed *not to* us get forwarded.

## Onion peeling

We don't special-case clients anymore. Everybody is a potential peeler.

Forward packets take in destination `NodeAddr` and destination `OnionPublic`. Backward packets consume a SURB.

At each level of peeling, the next hop is a `NodeAddr`.


## Non-mixnet usage?

Completely non-mixnet traffic can easily travel over the low-level network transport. This may or may not be a good thing?