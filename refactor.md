# Refactoring ideas

Besides some code duplication issues, the biggest problem is weak encapsulation and abstraction.

Partly to the difficulty presented by Rust's type system (most notably, mutually referencing objects are highly difficult and unidiomatic), we aren't using an "object-oriented"/noun-based abstraction system, but a procedural style.

But we don't have a great organization for the procedures, so we have a bunch of functions calling each other, touching all sorts of context-scoped variables and spawning tasks running about, making the code hard to follow.

It seems like fundamentally, humans need to think in terms of big, abstract "nouns" in addition to procedural "verbs", not just verbs operating on primitive pieces of data.

I think the best approach to this is to **treat modules as "nouns"**. Each **module** should present a coherent mental model of some part of the system, and only expose what's needed.

## Refactoring the network layer

The most complex and spaghetti area of the current code is the network layer --- the code that takes outgoing raw packets and sends them off, while feeding the rest of the code incoming raw packets. It's currently a mess of a bunch of tables with channels, connected to tasks on the other end, with lots of subtle race conditions related to tasks restarting, etc.

Here we outline a better design:

- `network`
  - `send_raw()`
  - `incoming_raw()`
  - `subscribe_outgoing_relay()`, returning a receiver that represents all the packets outgoing to a particular neighboring relay. If this is called multiple times, packets are sent to arbitrary channels, and none of them should be closed. The receiver should only close when there are no more subscribers at all.
  - `subscribe_outgoing_client()`
