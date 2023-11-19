output "eks" {
  value = module.eks
}

output "cluster_id" {
  value = module.eks.cluster_name
}

output ""
