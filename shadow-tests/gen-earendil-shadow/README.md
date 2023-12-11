This tool generates earendil config files for both local testing and for using in shadow (with `--shadow`). How to use:

1. Manually write an adjacencies graph YAML (see `example-graph.yaml`) *or* generate one using `gen-topo`
2. `cargo run adjacencies-graph.yaml output-directory-name [--shadow]` to generate a directory containing a `shadow.yaml` and a `configs` directory tree containing relevant earendil configs. Skip the `--shadow` flag to produce config files for local testing (these have different `control_listen` sections, localhost IP addrs, etc)
3. For shadow: modify the `shadow.yaml` to have nodes run desired programs. Then `shadow shadow.yaml` to run the shadow simulation