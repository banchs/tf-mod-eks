output "eks" {
  value = module.eks
}

output "cluster_id" {
  value = module.eks.cluster_name
}

output "cluster_certificate_authority_data" {
  value = module.eks.cluster_certificate_authority_data
}



cluster_endpoint