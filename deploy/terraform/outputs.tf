output "cluster_name" {
  value = module.eks.cluster_name
}

output "configure_kubectl" {
  description = "Run this to point kubectl at the new cluster"
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "ecr_repository_url" {
  value = aws_ecr_repository.aegis.repository_url
}

output "msk_bootstrap_brokers_tls" {
  value = aws_msk_cluster.aegis.bootstrap_brokers_tls
}

output "rds_endpoint" {
  value = aws_db_instance.aegis.address
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.aegis.primary_endpoint_address
}

output "archive_bucket" {
  value = aws_s3_bucket.archive.id
}

output "irsa_role_arn" {
  value = module.irsa.iam_role_arn
}

output "app_secret_arn" {
  value = aws_secretsmanager_secret.app.arn
}
