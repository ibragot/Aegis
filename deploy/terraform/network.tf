# VPC: public subnets (load balancer, NAT) + private subnets (EKS nodes, MSK, RDS, ElastiCache).
# Nothing that stores data is reachable from the internet.
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.13"

  name = local.name
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, 200 + i)]

  enable_nat_gateway   = true
  single_nat_gateway   = true # one NAT keeps the lab cheap; use one per AZ in production
  enable_dns_hostnames = true

  # VPC Flow Logs - the real-world source of Aegis' "network" telemetry.
  enable_flow_log                                 = true
  create_flow_log_cloudwatch_log_group            = true
  create_flow_log_cloudwatch_iam_role             = true
  flow_log_max_aggregation_interval               = 60
  flow_log_cloudwatch_log_group_retention_in_days = 14

  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1 }
}

# One security group for the data stores: only the EKS worker nodes may connect.
resource "aws_security_group" "data" {
  name        = "${local.name}-data"
  description = "Kafka, PostgreSQL and Redis - reachable only from EKS nodes"
  vpc_id      = module.vpc.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "data_from_nodes" {
  for_each = {
    kafka_tls   = 9094
    kafka_iam   = 9098
    postgres    = 5432
    redis       = 6379
    kafka_plain = 9092
  }
  security_group_id            = aws_security_group.data.id
  referenced_security_group_id = module.eks.node_security_group_id
  from_port                    = each.value
  to_port                      = each.value
  ip_protocol                  = "tcp"
  description                  = "${each.key} from EKS nodes"
}

resource "aws_vpc_security_group_egress_rule" "data_all" {
  security_group_id = aws_security_group.data.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "-1"
}
