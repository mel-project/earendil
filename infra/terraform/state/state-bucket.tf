terraform {
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.5.2"
    }
  }
}

provider "linode" {
  token = var.linode_api_token
}

resource "linode_object_storage_bucket" "terraform_state_bucket" {
  cluster = "us-east-1"
  label   = "state-bucket"
}
