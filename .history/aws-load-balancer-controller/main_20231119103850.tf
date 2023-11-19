resource "helm_release" "aws-load-balancer-controller" {
  # depends_on = [
  #   kubernetes_service_account_v1.this
  # ]

  name       = "alb-controller-${var.env}"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = var.namespace
  version    = var.load_balancer_controller_version

  # set {
  #   name  = "clusterName"
  #   value = var.cluster_name
  # }

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

  role_name                              = "$-${var.env}"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn = var.eks_openid_connect_provider.arn
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
    namespace = var.namespace
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