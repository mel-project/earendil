variable "linode_api_token" {
  description = "Linode personal access token"
  type        = string
}

variable "authorized_keys" {
  description = "List of authorized SSH keys"
  type        = list(string)
}

variable "linode_root_password" {
  description = "Root password of the Linode instance"
  type        = string
}

variable "region" {
  default = "us-east"
}


variable "node_names" {
  description = "A set of node names for creating instances"
  type        = set(string)
}
