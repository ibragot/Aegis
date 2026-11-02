variable "project" {
  description = "Name prefix for every resource"
  type        = string
  default     = "aegis"
}

variable "environment" {
  description = "Environment name (lab, dev, prod...)"
  type        = string
  default     = "lab"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC"
  type        = string
  default     = "10.40.0.0/16"
}

variable "cluster_version" {
  description = "EKS Kubernetes version"
  type        = string
  default     = "1.31"
}

variable "admin_cidrs" {
  description = "CIDR blocks allowed to reach the EKS public API endpoint (set this to YOUR IP/32)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "node_instance_types" {
  description = "Instance types for the EKS managed node group"
  type        = list(string)
  default     = ["t3.large"]
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "msk_instance_type" {
  description = "Broker size for Amazon MSK (kafka.t3.small is the cheapest)"
  type        = string
  default     = "kafka.t3.small"
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "archive_retention_days" {
  description = "Days to keep raw logs in the S3 archive before expiry"
  type        = number
  default     = 365
}

variable "enable_cloudtrail" {
  description = "Create a real CloudTrail trail for this account (delivered to the archive bucket) - see README 'Ingesting real logs'"
  type        = bool
  default     = false
}
