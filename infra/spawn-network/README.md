# spawn-network
This is a tool to spawn a network of connected Earendil nodes on real servers.

## Setup

First, you'll need to fill in some secrets for your cloud provider. Currently, this only supports Linode. Make a `terraform.tfvars` file in the `infra/terraform/` directory and fill these values in:

```
linode_api_token     = ""
authorized_keys      = ["..."]
linode_root_password = "..."
```

Then you'll need provide the topology of the network graph to create. Modify the `topology.yaml` file to do so:
```
adjacencies:
  - [alice, rob]
  - [rob, bob]
```
In this example, alice is connected to rob, and rob is connected to bob.

## Usage
Inside the `spawn-network` Rust project, just run `cargo run`, and you're off!






