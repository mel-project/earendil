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
```yaml
adjacencies:
  - [alice, rob]
  - [rob, bob]
```
In this example, alice is connected to rob, and rob is connected to bob.

### Install gen-earendil-shadow
Make sure gen-earendil-shadow is installed in your Cargo path.

### Compile Earendil
Build a release version of earendil. This program looks for the binary in the target directory. Since the remote machines may not have a compatible glibc version, build it with musl:
```shell
cargo build --release --target x86_64-unknown-linux-musl
```

If your machine can't use musl for whatever reason (you didn't install Gentoo properly :')), you can still build it inside a Docker image first:
```shell
docker run -v $PWD:/volume --rm -t clux/muslrust:stable cargo build --release
```

## Usage
Inside the `spawn-network` Rust project, just run `cargo run`, and you're off!






