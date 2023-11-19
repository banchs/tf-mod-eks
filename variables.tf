variable "env" {
  description = "AWS Environment"
  type        = string
}
variable "cluster_name" {
  type = string
}

variable "vpc_config" {
  type = any
}

variable "cluster_version" {
  type = string
}

variable "eks_managed_node_groups" {
  type    = any
  default = []
}

variable "aws_auth_roles" {
  type    = any
  default = []
}

variable "aws_auth_users" {
  type    = any
  default = []
}

variable "tags" {
  type    = any
  default = null
}

variable "load_balancer_controller" {
  type = any
  default = {
    enabled = false
  }
}

variable "additional_sg" {
  type = string
}

variable "service_account_name" {
  type    = string
  default = "aws-load-balancer-controller"
}