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


################################################################################
# Self Managed Node Group
################################################################################

variable "self_managed_node_groups" {
  description = "Map of self-managed node group definitions to create"
  type        = any
  default     = {}
}

variable "self_managed_node_group_defaults" {
  description = "Map of self-managed node group default configurations"
  type        = any
  default     = {}
}

variable "aws_auth_roles" {
  type    = list(any)
  default = []
}

variable "aws_auth_users" {
  type    = list(any)
  default = []
}

variable "aws_auth_accounts" {
  type    = list(any)
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

variable "domain_name" {
  type = string
}

variable "kms_key" {
  type = string
}


variable "public_subnets"{
  type = list(any)
}

variable "private_subnets"{
  type = list(any)
}

variable "intra_subnets"{
  type = list(any)
}