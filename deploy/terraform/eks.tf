# Amazon EKS cluster with one managed node group.
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.24"

  cluster_name    = local.name
  cluster_version = var.cluster_version

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = var.admin_cidrs # lock this down to your own IP

  # The identity running terraform becomes cluster admin (EKS access entries).
  enable_cluster_creator_admin_permissions = true

  # Control-plane logs to CloudWatch - "audit" is the real Kubernetes audit log Aegis analyzes.
  cluster_enabled_log_types = ["api", "audit", "authenticator"]

  cluster_addons = {
    coredns                = {}
    kube-proxy             = {}
    eks-pod-identity-agent = {}
    vpc-cni = {
      # makes the NetworkPolicies in deploy/k8s/base actually enforced
      configuration_values = jsonencode({ enableNetworkPolicy = "true" })
    }
  }

  eks_managed_node_groups = {
    default = {
      instance_types = var.node_instance_types
      min_size       = 1
      max_size       = 4
      desired_size   = var.node_desired_size
      capacity_type  = "ON_DEMAND"
      # IMDSv2 only, hop limit 1: pods cannot steal the node's instance-role credentials
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
      }
    }
  }
}

# Container registry for the Aegis image.
resource "aws_ecr_repository" "aegis" {
  name                 = var.project
  image_tag_mutability = "IMMUTABLE" # a tag always means the same image (supply-chain hygiene)
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true # vulnerability scan of every pushed image
  }
  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "aegis" {
  repository = aws_ecr_repository.aegis.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last 20 images"
      selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 20 }
      action       = { type = "expire" }
    }]
  })
}
