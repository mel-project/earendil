terraform {
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "2.5.2"
    }
  }
}

provider "linode" {
  token = var.linode_api_token
}

resource "linode_instance" "earendil-node" {
  for_each = var.node_names

  image = "linode/ubuntu20.04"
  # label           = "${each.key}-node"
  label           = each.key
  group           = "earendil-test"
  region          = var.region
  type            = "g6-standard-1"
  swap_size       = 1024
  authorized_keys = var.authorized_keys
  root_pass       = var.linode_root_password
}


output "node_ips" {
  value       = { for instance in linode_instance.earendil-node : instance.label => instance.ip_address }
  description = "Public IP addresses for the nodes"
}
