# ----------------------------------------------------------------------------- Amazon MSK (Kafka)
resource "aws_msk_configuration" "aegis" {
  name              = "${local.name}-config"
  kafka_versions    = ["3.6.0"]
  server_properties = <<-EOT
    auto.create.topics.enable=false
    default.replication.factor=2
    min.insync.replicas=1
    num.partitions=6
    log.retention.hours=72
  EOT
}

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/${local.name}"
  retention_in_days = 7
}

resource "aws_msk_cluster" "aegis" {
  cluster_name           = local.name
  kafka_version          = "3.6.0"
  number_of_broker_nodes = length(local.azs) # one broker per AZ

  broker_node_group_info {
    instance_type   = var.msk_instance_type
    client_subnets  = module.vpc.private_subnets
    security_groups = [aws_security_group.data.id]
    storage_info {
      ebs_storage_info {
        volume_size = 20
      }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS" # clients connect on 9094 with TLS
      in_cluster    = true
    }
  }

  # TLS without client auth keeps the lab simple; network access is restricted by the security group.
  # Production: enable IAM auth (port 9098) and give each service its own topic-level permissions.
  client_authentication {
    unauthenticated = true
  }

  configuration_info {
    arn      = aws_msk_configuration.aegis.arn
    revision = aws_msk_configuration.aegis.latest_revision
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }
}

# ----------------------------------------------------------------------------- RDS PostgreSQL
resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "aegis" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "aegis" {
  identifier                          = local.name
  engine                              = "postgres"
  engine_version                      = "16.4"
  instance_class                      = var.db_instance_class
  allocated_storage                   = 20
  max_allocated_storage               = 100
  db_name                             = "aegis"
  username                            = "aegis"
  password                            = random_password.db.result
  db_subnet_group_name                = aws_db_subnet_group.aegis.name
  vpc_security_group_ids              = [aws_security_group.data.id]
  publicly_accessible                 = false
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  backup_retention_period             = 1
  skip_final_snapshot                 = true  # lab only!
  deletion_protection                 = false # lab only!
}

# ----------------------------------------------------------------------------- ElastiCache Redis
resource "aws_elasticache_subnet_group" "aegis" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "aegis" {
  replication_group_id       = local.name
  description                = "Aegis detection state (windows, cooldowns)"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 1
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.aegis.name
  security_group_ids         = [aws_security_group.data.id]
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  automatic_failover_enabled = false
}

# ----------------------------------------------------------------------------- Secrets Manager
# Application secrets live in Secrets Manager, not in git or in the ConfigMap. Sync them into the
# cluster with the External Secrets Operator, or create the k8s Secret from them during deploy.
resource "aws_secretsmanager_secret" "app" {
  name                    = "${local.name}/app"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    DATABASE_URL      = "postgresql+psycopg://aegis:${random_password.db.result}@${aws_db_instance.aegis.address}:5432/aegis?sslmode=require"
    ANTHROPIC_API_KEY = "set-me" # replace in the console / CLI - never commit it
  })

  lifecycle {
    ignore_changes = [secret_string] # don't overwrite the key once you have set it
  }
}
