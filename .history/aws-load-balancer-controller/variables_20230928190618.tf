variable "env" {
  description = "AWS Environment"
  type        = string
}
variable "cluster_name" {
  type = string
}

variable "namespace" {
  type = string
  default = 
}

variable "eks_openid_connect_provider" {
  type = any
  default = ""
}

variable "load_balancer_controller_version" {
  type = string
  default = ""
}

variable "service_account_name" {
  type    = string
  default = "aws-load-balancer-controller"
}

