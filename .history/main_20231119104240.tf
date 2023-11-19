data "aws_region" "current" {}

data "aws_caller_identity" "current" {}



provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}


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

}

module "eks" {
  source = "terraform-aws-modules/eks/aws"
  #version = "~> 18.0"

  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true
  vpc_id                         = var.vpc_config.vpc_id
  subnet_ids                     = var.vpc_config.vpc_subnets_ids

  # cluster_addons = {
  #   coredns = {
  #     preserve    = true
  #     most_recent = true

  #     timeouts = {
  #       create = "15m"
  #       delete = "10m"
  #     }
  #   }
  #   # kube-proxy = {
  #   #   most_recent = true
  #   # }
  #   vpc-cni = {
  #     most_recent = true
  #   }
  # }
  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    disk_size              = 20
    vpc_security_group_ids = [var.additional_sg, aws_security_group.additional.id]
  }

  # self_managed_node_group_defaults = {
  #   vpc_security_group_ids = [var.additional_sg]  
  # }

  self_managed_node_groups = {

    main = {
      name           = "core-${var.env}"
      min_size       = 1
      max_size       = 20
      desired_size   = 8
      instance_types = ["t3.medium", "m4.large", "m5.large", "m5a.large", "t2.large", "t3.large", "t3a.large"]

      capacity_type = "SPOT"
      subnet_ids    = var.vpc_config.vpc_subnets_ids

      instance_market_options = {
        market_type = "spot"
      }

      pre_bootstrap_user_data = <<-EOT
        echo "foo"
        export FOO=bar
      EOT

      bootstrap_extra_args = "--kubelet-extra-args '--node-labels=node.kubernetes.io/lifecycle=spot'"

      post_bootstrap_user_data = <<-EOT
        cd /tmp
        sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
        sudo systemctl enable amazon-ssm-agent
        sudo systemctl start amazon-ssm-agent
      EOT
    }
  }



  eks_managed_node_groups = var.eks_managed_node_groups
  #  node_security_group_additional_rules = {
  #    ingress_allow_access_from_control_plane = {
  #      type                          = "ingress"
  #      protocol                      = "tcp"
  #      from_port                     = 9443
  #      to_port                       = 9443
  #      source_cluster_security_group = true
  #      description                   = "Allow access from control plane to webhook port of AWS load balancer controller"
  #    }
  #  }
  # sg-053de8b750eda4264
  # pendiente con este que va a borrar sg-038554732376893e0 

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
      source_security_group_id = var.additional_sg
    }
  }

  # Extend node-to-node security group rules
  node_security_group_additional_rules = {
    #  ingress_allow_access_from_control_plane = {
    #      type                          = "ingress"
    #      protocol                      = "tcp"
    #      from_port                     = 9443
    #      to_port                       = 9443
    #      source_cluster_security_group = true
    #      description                   = "Allow access from control plane to webhook port of AWS load balancer controller"
    #    }    
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
      source_security_group_id = var.additional_sg
    }
  }
  # Self Managed Node Group(s)
  self_managed_node_group_defaults = {
    vpc_security_group_ids = [aws_security_group.additional.id, var.additional_sg]
    iam_role_additional_policies = {
      additional = aws_iam_policy.additional.arn
    }

    instance_refresh = {
      strategy = "Rolling"
      preferences = {
        min_healthy_percentage = 66
      }
    }
  }




  # aws-auth configmap
  manage_aws_auth_configmap = true
  aws_auth_roles = [
    # {
    #   rolearn  = module.self_managed_node_group.iam_role_arn
    #   username = "system:node:{{EC2PrivateDNSName}}"
    #   groups = [
    #     "system:bootstrappers",
    #     "system:nodes",
    #   ]
    # },
    {
      rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/ci-github-actions"
      username = "ci-github-actions"
      groups   = ["system:masters"]
    },
  ]


  #var.aws_auth_roles
  aws_auth_users = var.aws_auth_users
  tags           = merge(var.tags, {})
}

# EKS Cluster data

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_name
}

#Load balancer controller submodule

# module "self_managed_node_group" {
#   source = "terraform-aws-modules/eks/aws//modules/self-managed-node-group"
#   #source = "../../modules/self-managed-node-group"
#   name                = "separate-self-mng"
#   cluster_name        = module.eks.cluster_name
#   cluster_version     = module.eks.cluster_version
#   cluster_endpoint    = module.eks.cluster_endpoint
#   cluster_auth_base64 = module.eks.cluster_certificate_authority_data
#   instance_type       = "t3.medium"
#   subnet_ids          = var.vpc_config.vpc_subnets_ids
#   vpc_security_group_ids = [
#     module.eks.cluster_primary_security_group_id,
#     module.eks.cluster_security_group_id,
#     var.additional_sg
#   ]
#   tags = merge(var.tags, { Separate = "self-managed-node-group" })
# }

# module "load_balancer_controller" {

#   source                           = "./aws-load-balancer-controller"
#   count                            = var.load_balancer_controller.enabled ? 1 : 0
#   env                              = var.env
#   cluster_name                     = module.eks.cluster_id
#   load_balancer_controller_version = var.load_balancer_controller.version
#   eks_openid_connect_provider = {
#     arn = module.eks.oidc_provider_arn
#     url = module.eks.oidc_provider
#   }
#   namespace = "kube-system"
# }