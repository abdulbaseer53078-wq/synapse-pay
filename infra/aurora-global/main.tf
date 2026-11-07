# Aurora Global Database for the payments database (Stage 4, Step 17.2).
#
# One writer region (Mumbai, ap-south-1) and one read-only secondary (Hyderabad, ap-south-2), replicated at the
# storage layer, typically well under a second behind. Both regions are in India, as RBI data localization requires.
#
# This is active-passive for writes, not active-active: Hyderabad can't take payments until it is promoted, and
# promotion is a human decision (docs/step17.md). Replication is asynchronous, so an unplanned failover can lose
# the last moments of commits; docs/step17.md covers fencing, promotion and reconciling that window.
#
# Networking (VPCs, subnets, security groups) and the KMS keys are inputs, not created here.
# After any switchover or failover the roles are reversed in AWS: swap the primary/secondary inputs before the
# next apply, or Terraform will try to undo the failover.
#
# Apply with: terraform init && terraform plan && terraform apply   (state must live in an encrypted backend:
# it holds the master password)

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

variable "name" {
  type        = string
  default     = "synapsepay-payments"
  description = "Prefix for every identifier."
}

variable "primary_region" {
  type    = string
  default = "ap-south-1" # Mumbai
}

variable "secondary_region" {
  type    = string
  default = "ap-south-2" # Hyderabad
}

variable "engine_version" {
  type        = string
  default     = "16.4"
  description = "Aurora PostgreSQL version; must support global databases."
}

variable "instance_class" {
  type        = string
  default     = "db.r6g.large"
  description = "Global databases need memory-optimized classes (r5/r6g/r7g); serverless v1 isn't supported."
}

variable "instances_per_region" {
  type    = number
  default = 2 # a second instance per region for in-region failover, independent of the regional failover
}

variable "master_username" {
  type    = string
  default = "synapsepay_admin"
}

variable "master_password" {
  type        = string
  sensitive   = true
  description = "Pass via TF_VAR_master_password from the secrets manager; never commit it."
}

variable "primary_subnet_ids" {
  type        = list(string)
  description = "Private subnets in at least two AZs of the primary region."
}

variable "primary_security_group_ids" {
  type = list(string)
}

variable "primary_kms_key_arn" {
  type        = string
  description = "KMS key in the primary region for storage encryption."
}

variable "secondary_subnet_ids" {
  type        = list(string)
  description = "Private subnets in at least two AZs of the secondary region."
}

variable "secondary_security_group_ids" {
  type = list(string)
}

variable "secondary_kms_key_arn" {
  type        = string
  description = "KMS key in the secondary region: an encrypted secondary must use a key from its own region."
}

variable "max_replication_lag_ms" {
  type        = number
  default     = 1000 # Step 17.2 target; above it, the window a failover could lose is larger than accepted
  description = "Alarm threshold for the secondary's replication lag."
}

variable "alarm_topic_arn" {
  type        = string
  description = "SNS topic in the secondary region that pages on-call."
}

provider "aws" {
  alias  = "primary"
  region = var.primary_region
}

provider "aws" {
  alias  = "secondary"
  region = var.secondary_region
}

resource "aws_rds_global_cluster" "payments" {
  provider                  = aws.primary
  global_cluster_identifier = "${var.name}-global"
  engine                    = "aurora-postgresql"
  engine_version            = var.engine_version
  database_name             = "synapsepay"
  storage_encrypted         = true
  deletion_protection       = true
}

resource "aws_db_subnet_group" "primary" {
  provider   = aws.primary
  name       = "${var.name}-${var.primary_region}"
  subnet_ids = var.primary_subnet_ids
}

resource "aws_db_subnet_group" "secondary" {
  provider   = aws.secondary
  name       = "${var.name}-${var.secondary_region}"
  subnet_ids = var.secondary_subnet_ids
}

resource "aws_rds_cluster" "primary" {
  provider                        = aws.primary
  cluster_identifier              = "${var.name}-${var.primary_region}"
  global_cluster_identifier       = aws_rds_global_cluster.payments.id
  engine                          = aws_rds_global_cluster.payments.engine
  engine_version                  = aws_rds_global_cluster.payments.engine_version
  master_username                 = var.master_username
  master_password                 = var.master_password
  db_subnet_group_name            = aws_db_subnet_group.primary.name
  vpc_security_group_ids          = var.primary_security_group_ids
  storage_encrypted               = true
  kms_key_id                      = var.primary_kms_key_arn
  backup_retention_period         = 35 # the maximum: point-in-time recovery for a month
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${var.name}-${var.primary_region}-final"
  enabled_cloudwatch_logs_exports = ["postgresql"]

  lifecycle {
    ignore_changes = [global_cluster_identifier]
  }
}

resource "aws_rds_cluster_instance" "primary" {
  provider                     = aws.primary
  count                        = var.instances_per_region
  identifier                   = "${var.name}-${var.primary_region}-${count.index}"
  cluster_identifier           = aws_rds_cluster.primary.id
  engine                       = aws_rds_cluster.primary.engine
  engine_version               = aws_rds_cluster.primary.engine_version
  instance_class               = var.instance_class
  db_subnet_group_name         = aws_db_subnet_group.primary.name
  performance_insights_enabled = true
}

# Read-only until promoted. No master credentials: it replicates the primary's.
resource "aws_rds_cluster" "secondary" {
  provider                        = aws.secondary
  cluster_identifier              = "${var.name}-${var.secondary_region}"
  global_cluster_identifier       = aws_rds_global_cluster.payments.id
  engine                          = aws_rds_global_cluster.payments.engine
  engine_version                  = aws_rds_global_cluster.payments.engine_version
  db_subnet_group_name            = aws_db_subnet_group.secondary.name
  vpc_security_group_ids          = var.secondary_security_group_ids
  storage_encrypted               = true
  kms_key_id                      = var.secondary_kms_key_arn
  backup_retention_period         = 35
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${var.name}-${var.secondary_region}-final"
  enabled_cloudwatch_logs_exports = ["postgresql"]

  lifecycle {
    ignore_changes = [replication_source_identifier, global_cluster_identifier]
  }

  depends_on = [aws_rds_cluster_instance.primary] # the secondary can only attach once the primary has a writer
}

resource "aws_rds_cluster_instance" "secondary" {
  provider                     = aws.secondary
  count                        = var.instances_per_region
  identifier                   = "${var.name}-${var.secondary_region}-${count.index}"
  cluster_identifier           = aws_rds_cluster.secondary.id
  engine                       = aws_rds_cluster.secondary.engine
  engine_version               = aws_rds_cluster.secondary.engine_version
  instance_class               = var.instance_class
  db_subnet_group_name         = aws_db_subnet_group.secondary.name
  performance_insights_enabled = true
}

# "< 1 second" is a target to watch, not an assumption: page when the secondary falls behind.
resource "aws_cloudwatch_metric_alarm" "replication_lag" {
  provider            = aws.secondary
  alarm_name          = "${var.name}-global-replication-lag"
  alarm_description   = "Hyderabad is more than ${var.max_replication_lag_ms} ms behind Mumbai: a failover now could lose that much. See docs/step17.md."
  namespace           = "AWS/RDS"
  metric_name         = "AuroraGlobalDBReplicationLag"
  dimensions          = { DBClusterIdentifier = aws_rds_cluster.secondary.cluster_identifier }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = var.max_replication_lag_ms
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching" # no metric means replication may have stopped
  alarm_actions       = [var.alarm_topic_arn]
  ok_actions          = [var.alarm_topic_arn]
}

output "global_cluster_id" {
  value = aws_rds_global_cluster.payments.id
}

output "primary_writer_endpoint" {
  value = aws_rds_cluster.primary.endpoint
}

output "secondary_cluster_arn" {
  value       = aws_rds_cluster.secondary.arn
  description = "Target for switchover-global-cluster / failover-global-cluster (docs/step17.md)."
}

output "secondary_reader_endpoint" {
  value = aws_rds_cluster.secondary.reader_endpoint
}
