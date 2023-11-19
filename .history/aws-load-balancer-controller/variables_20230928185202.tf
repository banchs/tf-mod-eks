variable "env" {
  description = "AWS Environment"
  type        = string
}
variable "cluster_name" {
  type = string
}

variable "namespace" {
  type = string
}

variable "eks_openid_connect_provider" {
  type = any
}

variable "load_balancer_controller_version" {
  type = string
}

variable "service_account_name" {
  type    = string
  default = "aws-load-balancer-controller"
}



helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=eks-goliii \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller 