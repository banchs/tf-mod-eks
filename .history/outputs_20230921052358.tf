output "eks" {
  value = module.eks
}

output "cluster_id" {
  value = module.eks.cluster_name
}

output "cluster_certificate_authority_data" {
  valuecluster_certificate_authority_data
}
