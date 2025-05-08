# Refactoring ideas

## Relays and clients

The whole refactor to make clients a special kind of node was a disaster, as it introduced relay vs client special casing throughout the stack.

Instead, we take a page from IP, and simply have nodes that either have globally reachable addresses or don't. There is no need to special case around this if we are careful about non-leaky abstractions.

## Pricing and peeling

Should we enforce the original design of peeling, which is entirely based on source routing that couples the mixnet layer with the network layer, rather than the new design?

The new design is easier to tune for the performance/privacy tradeoff and has more provable privacy, but it makes pricing somewhat problematic, since per-packet costs will vary drastically based on whether the relay needs to peel or simply pass along. (Or maybe not, if we can make peeling cheap enough)


## Layers

This will be assuming we keep the separation between the mixing layer and the network layer.

Earendil's internal abstractions are inspired by traditional IP stack abstractions.

The lowest level exposes an interface like IP: you can send or receive datagrams, and they are addressed to a `Fingerprint`, which represents a public key hash. Receive receives fingerprints that are addressed to oneself.

At one higher level, we implement the onion encryption stuff.


## Implementation

The current API is actually quite nice. The only thing that needs to be changed is probably a refactor of `LinkNode`, to separate out the network layer better.