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


resource "helm_release" "aws-load-balancer-controller" {
  # depends_on = [
  #   kubernetes_service_account_v1.this
  # ]

  name       = "alb-controller-${var.env}"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  #version    = var.load_balancer_controller_version

  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }

  # set {
  #   name  = "serviceAccount.create"
  #   value = true
  # }

  # set {
  #   name  = "serviceAccount.name"
  #   value = var.service_account_name
  # }
}


#Assume policy for Load balancer controller

# data "aws_iam_policy_document" "this_assume" {

#   statement {
#     principals {
#       type        = "Federated"
#       identifiers = [var.eks_openid_connect_provider.arn]
#     }

#     actions = ["sts:AssumeRoleWithWebIdentity"]
#     effect  = "Allow"

#     condition {
#       test     = "StringEquals"
#       variable = "${var.eks_openid_connect_provider.url}:sub"
#       values   = ["system:serviceaccount:${var.namespace}:aws-load-balancer-controller"]
#     }

#     condition {
#       test     = "StringEquals"
#       variable = "${var.eks_openid_connect_provider.url}:aud"
#       values   = ["sts.amazonaws.com"]
#     }
#   }
# }

module "lb_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = "${var.service_account_name}-${var.env}"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn = module.eks.oidc_provider_arn
      #var.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

# resource "aws_iam_role" "this" {
#   name = "${var.service_account_name}-role-${var.env}"

#   assume_role_policy = data.aws_iam_policy_document.this_assume.json
#   inline_policy {
#     name = "AWSLoadBalancerControllerIAMPolicy"

#     policy = jsonencode({
#       "Version" : "2012-10-17",
#       "Statement" : [
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "iam:CreateServiceLinkedRole"
#           ],
#           "Resource" : "*",
#           "Condition" : {
#             "StringEquals" : {
#               "iam:AWSServiceName" : "elasticloadbalancing.amazonaws.com"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "ec2:DescribeAccountAttributes",
#             "ec2:DescribeAddresses",
#             "ec2:DescribeAvailabilityZones",
#             "ec2:DescribeInternetGateways",
#             "ec2:DescribeVpcs",
#             "ec2:DescribeVpcPeeringConnections",
#             "ec2:DescribeSubnets",
#             "ec2:DescribeSecurityGroups",
#             "ec2:DescribeInstances",
#             "ec2:DescribeNetworkInterfaces",
#             "ec2:DescribeTags",
#             "ec2:GetCoipPoolUsage",
#             "ec2:DescribeCoipPools",
#             "elasticloadbalancing:DescribeLoadBalancers",
#             "elasticloadbalancing:DescribeLoadBalancerAttributes",
#             "elasticloadbalancing:DescribeListeners",
#             "elasticloadbalancing:DescribeListenerCertificates",
#             "elasticloadbalancing:DescribeSSLPolicies",
#             "elasticloadbalancing:DescribeRules",
#             "elasticloadbalancing:DescribeTargetGroups",
#             "elasticloadbalancing:DescribeTargetGroupAttributes",
#             "elasticloadbalancing:DescribeTargetHealth",
#             "elasticloadbalancing:DescribeTags"
#           ],
#           "Resource" : "*"
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "cognito-idp:DescribeUserPoolClient",
#             "acm:ListCertificates",
#             "acm:DescribeCertificate",
#             "iam:ListServerCertificates",
#             "iam:GetServerCertificate",
#             "waf-regional:GetWebACL",
#             "waf-regional:GetWebACLForResource",
#             "waf-regional:AssociateWebACL",
#             "waf-regional:DisassociateWebACL",
#             "wafv2:GetWebACL",
#             "wafv2:GetWebACLForResource",
#             "wafv2:AssociateWebACL",
#             "wafv2:DisassociateWebACL",
#             "shield:GetSubscriptionState",
#             "shield:DescribeProtection",
#             "shield:CreateProtection",
#             "shield:DeleteProtection"
#           ],
#           "Resource" : "*"
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "ec2:AuthorizeSecurityGroupIngress",
#             "ec2:RevokeSecurityGroupIngress"
#           ],
#           "Resource" : "*"
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "ec2:CreateSecurityGroup"
#           ],
#           "Resource" : "*"
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "ec2:CreateTags"
#           ],
#           "Resource" : "arn:aws:ec2:*:*:security-group/*",
#           "Condition" : {
#             "StringEquals" : {
#               "ec2:CreateAction" : "CreateSecurityGroup"
#             },
#             "Null" : {
#               "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "ec2:CreateTags",
#             "ec2:DeleteTags"
#           ],
#           "Resource" : "arn:aws:ec2:*:*:security-group/*",
#           "Condition" : {
#             "Null" : {
#               "aws:RequestTag/elbv2.k8s.aws/cluster" : "true",
#               "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "ec2:AuthorizeSecurityGroupIngress",
#             "ec2:RevokeSecurityGroupIngress",
#             "ec2:DeleteSecurityGroup"
#           ],
#           "Resource" : "*",
#           "Condition" : {
#             "Null" : {
#               "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:CreateLoadBalancer",
#             "elasticloadbalancing:CreateTargetGroup"
#           ],
#           "Resource" : "*",
#           "Condition" : {
#             "Null" : {
#               "aws:RequestTag/elbv2.k8s.aws/cluster" : "false"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:CreateListener",
#             "elasticloadbalancing:DeleteListener",
#             "elasticloadbalancing:CreateRule",
#             "elasticloadbalancing:DeleteRule"
#           ],
#           "Resource" : "*"
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:AddTags",
#             "elasticloadbalancing:RemoveTags"
#           ],
#           "Resource" : [
#             "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
#             "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
#             "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
#           ],
#           "Condition" : {
#             "Null" : {
#               "aws:RequestTag/elbv2.k8s.aws/cluster" : "true",
#               "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:AddTags",
#             "elasticloadbalancing:RemoveTags"
#           ],
#           "Resource" : [
#             "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
#             "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
#             "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
#             "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
#           ]
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:ModifyLoadBalancerAttributes",
#             "elasticloadbalancing:SetIpAddressType",
#             "elasticloadbalancing:SetSecurityGroups",
#             "elasticloadbalancing:SetSubnets",
#             "elasticloadbalancing:DeleteLoadBalancer",
#             "elasticloadbalancing:ModifyTargetGroup",
#             "elasticloadbalancing:ModifyTargetGroupAttributes",
#             "elasticloadbalancing:DeleteTargetGroup"
#           ],
#           "Resource" : "*",
#           "Condition" : {
#             "Null" : {
#               "aws:ResourceTag/elbv2.k8s.aws/cluster" : "false"
#             }
#           }
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:RegisterTargets",
#             "elasticloadbalancing:DeregisterTargets"
#           ],
#           "Resource" : "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
#         },
#         {
#           "Effect" : "Allow",
#           "Action" : [
#             "elasticloadbalancing:SetWebAcl",
#             "elasticloadbalancing:ModifyListener",
#             "elasticloadbalancing:AddListenerCertificates",
#             "elasticloadbalancing:RemoveListenerCertificates",
#             "elasticloadbalancing:ModifyRule",
#             "elasticloadbalancing:AddTags"
#           ],
#           "Resource" : "*"
#         }
#       ]
#     })
#   }
#   max_session_duration = "3600"
# }

resource "kubernetes_service_account_v1" "this" {
  metadata {
    name      = var.service_account_name
    namespace = "kube-system"
    labels = {
      "app.kubernetes.io/name"      = "aws-load-balancer-controller"
      "app.kubernetes.io/component" = "controller"
    }
    annotations = {
      "eks.amazonaws.com/role-arn"               = module.lb_role.iam_role_arn
      "eks.amazonaws.com/sts-regional-endpoints" = "true"
    }
  }
}

resource "kubernetes_ingress_class_v1" "ingress" {
  # depends_on = [
  #   helm_release.aws-load-balancer-controlle
  # ]
  metadata {
    name = "aws-alb"
  }

  spec {
    controller = "ingress.k8s.aws/alb"
  }
}