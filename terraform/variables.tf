variable "linode_api_token" {}
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
