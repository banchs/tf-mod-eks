data "aws_region" "current" {}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}


locals {
  name   = "goliiive-mvp"

}
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

# provider "kubernetes" {
#   host                   = module.eks.cluster_endpoint
#   cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

#   exec {
#     api_version = "client.authentication.k8s.io/v1beta1"
#     command     = "aws"
#     # This requires the awscli to be installed locally where Terraform is executed
#     args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
#   }
# }

# provider "kubernetes" {
#   host                   = module.eks.cluster_endpoint
#   #data.aws_eks_cluster.cluster.endpoint
#   cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
#   token                  = data.aws_eks_cluster_auth.cluster.token
#  # load_config_file       = false
#  # version                = "~> 1.9"
# }


resource "aws_iam_policy" "additional" {
  name = "${var.cluster_name}-additional"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_security_group" "additional" {
  name_prefix = "core-${var.env}-additional"
  vpc_id      = var.vpc_config.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }

  tags = merge(var.tags, { Name = "core-${var.env}-additional" })
}

module "eks" {
  source                         = "terraform-aws-modules/eks/aws"
  #version                        = "~> 19.0"
  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true
  vpc_id                         = var.vpc_config.vpc_id
  subnet_ids                     = var.vpc_config.vpc_subnets_ids
  control_plane_subnet_ids       = var.intra_subnets

  # EKS Managed Node Group(s)
  # eks_managed_node_group_defaults = {
  #   disk_size = 150
  # }

  # self_managed_node_group_defaults = {
  #   vpc_security_group_ids = [var.additional_sg]
  # }

  #eks_managed_node_groups = var.eks_managed_node_groups
  #self_managed_node_groups = var.self_managed_node_groups


  cluster_addons = {
    coredns = {
      preserve    = true
      most_recent = true

      timeouts = {
        create = "25m"
        delete = "10m"
      }
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }

  # External encryption key
  create_kms_key = false
  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = module.kms.key_arn
  }

  iam_role_additional_policies = {
    additional = aws_iam_policy.additional.arn
  }


  # vpc_id                   = module.vpc.vpc_id
  # subnet_ids               = module.vpc.private_subnets
  #control_plane_subnet_ids = module.vpc.intra_subnets

  # Extend cluster security group rules
  cluster_security_group_additional_rules = {
    ingress_nodes_ephemeral_ports_tcp = {
      description                = "Nodes on ephemeral ports"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "ingress"
      source_node_security_group = true
    }
    # Test: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2319
    ingress_source_security_group_id = {
      description              = "Ingress from another computed security group"
      protocol                 = "tcp"
      from_port                = 22
      to_port                  = 22
      type                     = "ingress"
      source_security_group_id = aws_security_group.additional.id
    }
  }

  # Extend node-to-node security group rules
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    # Test: https://github.com/terraform-aws-modules/terraform-aws-eks/pull/2319
    ingress_source_security_group_id = {
      description              = "Ingress from another computed security group"
      protocol                 = "tcp"
      from_port                = 22
      to_port                  = 22
      type                     = "ingress"
      source_security_group_id = aws_security_group.additional.id
    }
  }

  # Self Managed Node Group(s)
  # self_managed_node_group_defaults = {
  #   vpc_security_group_ids = [aws_security_group.additional.id]
  #   iam_role_additional_policies = {
  #     additional = aws_iam_policy.additional.arn
  #   }

  #   instance_refresh = {
  #     strategy = "Rolling"
  #     preferences = {
  #       min_healthy_percentage = 66
  #     }
  #   }
  # }

  # self_managed_node_groups = {
  #   spot = {
  #     instance_type = "m5.large"
  #     instance_market_options = {
  #       market_type = "spot"
  #     }

  #     pre_bootstrap_user_data = <<-EOT
  #       echo "foo"
  #       export FOO=bar
  #     EOT

  #     bootstrap_extra_args = "--kubelet-extra-args '--node-labels=node.kubernetes.io/lifecycle=spot'"

  #     post_bootstrap_user_data = <<-EOT
  #       cd /tmp
  #       sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
  #       sudo systemctl enable amazon-ssm-agent
  #       sudo systemctl start amazon-ssm-agent
  #     EOT
  #   }
  # }

  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    instance_types = ["m6i.large", "m5.large", "m5n.large", "m5zn.large"]

    attach_cluster_primary_security_group = true
    vpc_security_group_ids                = [aws_security_group.additional.id, var.additional_sg]
    iam_role_additional_policies = {
      additional = aws_iam_policy.additional.arn
    }
  }

  eks_managed_node_groups = {
   # blue = {}
    spot = {
      min_size     = 1
      max_size     = 10
      desired_size = 1

      instance_types = ["t3.large"]
      capacity_type  = "SPOT"
      labels = {
        Environment = var.env
        GithubRepo  = "terraform-aws-eks"
        GithubOrg   = "terraform-aws-modules"
      }

      taints = {
        dedicated = {
          key    = "dedicated"
          value  = "gpuGroup"
          effect = "NO_SCHEDULE"
        }
      }

      update_config = {
        max_unavailable_percentage = 33 # or set `max_unavailable`
      }

      tags = {
        ExtraTag = "example"
      }
    }
  }

  # # Fargate Profile(s)
  fargate_profiles = {
    default = {
      name = "default"
      selectors = [
        {
          namespace = "kube-system"
          labels = {
            k8s-app = "kube-dns"
          }
        },
        {
          namespace = "default"
        }
      ]

      tags = {
        Owner = "gbanchs"
      }

      timeouts = {
        create = "20m"
        delete = "20m"
      }
    }
  }

  # Create a new cluster where both an identity provider and Fargate profile is created
  # will result in conflicts since only one can take place at a time
  # # OIDC Identity provider
  # cluster_identity_providers = {
  #   sts = {
  #     client_id = "sts.amazonaws.com"
  #   }
  # }

  # aws-auth configmap
  manage_aws_auth_configmap = true

  # aws_auth_node_iam_role_arns_non_windows = [
  #   module.eks_managed_node_group.iam_role_arn,
  #   #module.self_managed_node_group.iam_role_arn,
  # ]
  # aws_auth_fargate_profile_pod_execution_role_arns = [
  #   module.fargate_profile.fargate_profile_pod_execution_role_arn
  # ]

  aws_auth_roles = [
    {
      rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/ci-github-actions"
      username = "ci-github-actions"
      groups   = ["system:masters"]
    },
    {
      rolearn  = module.eks_managed_node_group.iam_role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    },
    # {
    #   rolearn  = module.self_managed_node_group.iam_role_arn
    #   username = "system:node:{{EC2PrivateDNSName}}"
    #   groups = [
    #     "system:bootstrappers",
    #     "system:nodes",
    #   ]
    # }
    #,
    # {
    #   rolearn  = module.fargate_profile.fargate_profile_pod_execution_role_arn
    #   username = "system:node:{{SessionName}}"
    #   groups = [
    #     "system:bootstrappers",
    #     "system:nodes",
    #     "system:node-proxier",
    #   ]
    # }
  ]


  #aws_auth_roles            = var.aws_auth_roles
  aws_auth_users    = var.aws_auth_users
  aws_auth_accounts = var.aws_auth_accounts
  tags              = merge(var.tags, {})


}

################################################################################
# Sub-Module Usage on Existing/Separate Cluster
################################################################################

module "eks_managed_node_group" {

  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"
  name            = "separate-eks-mng"
  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version


  cluster_primary_security_group_id = module.eks.cluster_primary_security_group_id
  subnet_ids = var.vpc_config.vpc_subnets_ids

  vpc_security_group_ids = [
    module.eks.cluster_security_group_id, var.additional_sg
  ]

  ami_type = "BOTTLEROCKET_x86_64"
  platform = "bottlerocket"

  # this will get added to what AWS provides
  bootstrap_extra_args = <<-EOT
    # extra args added
    [settings.kernel]
    lockdown = "integrity"

    [settings.kubernetes.node-labels]
    "label1" = "foo"
    "label2" = "bar"
  EOT

  tags = merge(var.tags, { Separate = "eks-managed-node-group" })
}


# module "self_managed_node_group" {
#   source = "terraform-aws-modules/eks/aws"
#   #source = "../../modules/self-managed-node-group"

#   name                = "separate-self-mng"
#   cluster_name        = module.eks.cluster_name
#   cluster_version     = module.eks.cluster_version
#   cluster_endpoint    = module.eks.cluster_endpoint
#   cluster_auth_base64 = module.eks.cluster_certificate_authority_data

#   instance_type = "m5.large"

#   subnet_ids = module.vpc.private_subnets
#   vpc_security_group_ids = [
#     module.eks.cluster_primary_security_group_id,
#     module.eks.cluster_security_group_id,
#   ]

#   tags = merge(local.tags, { Separate = "self-managed-node-group" })
# }

# module "fargate_profile" {
#   source = "../../modules/fargate-profile"

#   name         = "separate-fargate-profile"
#   cluster_name = module.eks.cluster_name

#   subnet_ids = module.vpc.private_subnets
#   selectors = [{
#     namespace = "kube-system"
#   }]

#   tags = merge(local.tags, { Separate = "fargate-profile" })
# }

################################################################################
# Disabled creation
################################################################################

module "disabled_eks" {
  source = "terraform-aws-modules/eks/aws"

  create = false
}

module "disabled_fargate_profile" {
  source = "terraform-aws-modules/eks/aws//modules/fargate-profile"

  create = false
}

# module "disabled_eks_managed_node_group" {
#   source = "../../modules/eks-managed-node-group"

#   create = false
# }

# module "disabled_self_managed_node_group" {
#   source = "../../modules/self-managed-node-group"

#   create = false
# }


module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 1.5"

  aliases               = ["eks/${local.name}"]
  description           = "${local.name} cluster encryption key"
  enable_default_policy = true
  key_owners            = [data.aws_caller_identity.current.arn]

  tags = var.tags
}




#Load balancer controller submodule

module "load_balancer_controller" {

  source                           = "./aws-load-balancer-controller"
  count                            = var.load_balancer_controller.enabled ? 1 : 0
  env                              = var.env
  cluster_name                     = var.cluster_name
  load_balancer_controller_version = var.load_balancer_controller.version
  eks_openid_connect_provider = {
    arn = module.eks.oidc_provider_arn
    url = module.eks.oidc_provider
  }
  namespace = "kube-system"
  depends_on = [
    module.eks
  ]
}
