data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 18.0"

  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true
  vpc_id                         = var.vpc_config.vpc_id
  subnet_ids                     = var.vpc_config.vpc_subnets_ids

  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    disk_size = 20
  }
  self_managed_node_group_defaults = {
    vpc_security_group_ids = [var.additional_sg]
  }

  eks_managed_node_groups = var.eks_managed_node_groups
  node_security_group_additional_rules = {
    ingress_allow_access_from_control_plane = {
      type                          = "ingress"
      protocol                      = "tcp"
      from_port                     = 9443
      to_port                       = 9443
      source_cluster_security_group = true
      description                   = "Allow access from control plane to webhook port of AWS load balancer controller"
    }
  }

  # aws-auth configmap
  manage_aws_auth_configmap = false
  aws_auth_roles            = var.aws_auth_roles
  aws_auth_users            = var.aws_auth_users
  tags                      = merge(var.tags, {})
}

# EKS Cluster data

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

#Load balancer controller submodule

module "load_balancer_controller" {

  source                           = "./aws-load-balancer-controller"
  count                            = var.load_balancer_controller.enabled ? 1 : 0
  env                              = var.env
  cluster_name                     = module.eks.cluster_id
  load_balancer_controller_version = var.load_balancer_controller.version
  eks_openid_connect_provider = {
    arn = module.eks.oidc_provider_arn
    url = module.eks.oidc_provider
  }
  namespace = "kube-system"
}