# Refactoring plan

Currently, the link layer is refactored to primarily use actors. This might or might not be a great idea, but it's a good start.

The objective is to have a really robust design for the entire link layer, including:

- avoiding passing around weird tuples and other unstructured data
- avoiding direct use of `bytemuck` by better encapsulation in `earendil_packet`
- a _much better_ debt and payment system

## New debt and storage

We simply record the current debt with each neighbor, rather than recording a ledger. This simplifies the database and improves performance.

We also now initialize a `SqlitePool` and pass it around. Structs like `DebtStore` take this single global database as an input.

We simply use _other_ structs, like `OttStore` and `KeyStore`, for other uses of the database.

This way, any `Store` object would be a _view_ into the global database, which we would assume does not have "writeback" caching, can be discarded at any time, etc.

This also enables debugging code to have much more direct access to the database without hacks, and it also allows for global configuration of database options more easily.

## Payment methods

Instead of an "ott" or invoice-id based system, we use a _nonce_ based system for eliminating double-spending. This removes the need for an initial RTT and simplifies the data flow. It also avoids keeping track of an unbounded number of invoice ids.

The basic idea is that payment systems have:

- A method `new_payment(PaymentInfo{destination, source, amount, nonce}) -> Proof` where `nonce` is an always-increasing u64. This can be implemented as a microsecond timestamp plus counter, which is almost certainly safe against wraparounds.
- A method `verify(proof) -> Result<PaymentInfo>` that returns the `PaymentInfo` if the proof is valid.

The caller is responsible for keeping track of nonces. In particular, we keep track of the highest nonce from each source, and we reject any payment with a nonce lower than the highest nonce from that source. This is by a `NonceStore` struct.

## Chat?

Chat will be removed. It's not a core feature of a network protocol. There's no reason for "chatting with your ISP" to be built into IP.

Instead, once we have "xirtam" working, we can have a semi-official community of node runners etc there. Before that, Discord should suffice.

## Action plan

- [x] Completely remove chat
- [ ] Implement storage system for debts
- [ ] Test
- [ ] Implement payment system
