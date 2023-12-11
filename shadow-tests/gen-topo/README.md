This tool produces a realistic-esque graph of `number` nodes for using in `gen-earendil-shadow`, in which each node is connected to `neigh` many other nodes. How to use:
```
gen-topo number neigh
```
Note that `neigh < number` must hold; otherwise the program will panic.