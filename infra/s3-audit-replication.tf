# Cross-region replication of the audit WORM bucket (Stage 4, Step 17.3).
#
# The audit trail's immutable copy must survive the loss of the region that wrote it. Every object under audit/
# is replicated to a bucket in the second region that is itself Object-Locked (COMPLIANCE), with Replication
# Time Control: S3 commits to replicating 99.99% of objects within 15 minutes, and most arrive within seconds.
# Replication is asynchronous: objects written in the last moments before a region dies may arrive late or
# not at all. That is why a failover starts a new chain epoch (docs/step17.md) instead of reusing the key space.
#
# Kafka is not replicated (no MirrorMaker 2): the WORM chain is built from Postgres, and Kafka is a fan-out
# that the new region rebuilds from the replicated outbox cursors.
#
# Replicas keep each object's retention date. Deletes are never replicated (delete-marker replication is off),
# so nothing done in one region can remove the other region's copy.
# Objects written before this rule existed are not replicated by it: copy them once with S3 Batch Replication.
#
# If AWS rejects the replication configuration on an Object-Locked source bucket, older accounts may still
# need the bucket's Object Lock token from AWS Support (the `token` argument).

variable "replica_region" {
  type    = string
  default = "ap-south-2" # Hyderabad: both copies stay in India (RBI data localization)
}

variable "replica_bucket_name" {
  type        = string
  description = "Globally unique name for the replica, e.g. synapsepay-audit-prod-hyd"
}

variable "replica_kms_key_arn" {
  type        = string
  default     = null
  description = "KMS key in the replica region. Required if kms_key_arn is set: SSE-KMS objects are re-encrypted under it."
}

variable "replication_alarm_topic_arn" {
  type        = string
  default     = null
  description = "SNS topic (in the source region) to page when objects fail to replicate. Null: no alarm."
}

provider "aws" {
  alias  = "replica"
  region = var.replica_region
}

resource "aws_s3_bucket" "audit_replica" {
  provider            = aws.replica
  bucket              = var.replica_bucket_name
  object_lock_enabled = true
  force_destroy       = false

  tags = { Purpose = "synapsepay-audit-log-replica", Retention = "${var.retention_days}d" }
}

resource "aws_s3_bucket_versioning" "audit_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.audit_replica.id
  versioning_configuration { status = "Enabled" }
}

# Replicas carry their source object's retention; this default only covers anything written here directly.
resource "aws_s3_bucket_object_lock_configuration" "audit_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.audit_replica.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.audit_replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.replica_kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.replica_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_replica" {
  provider                = aws.replica
  bucket                  = aws_s3_bucket.audit_replica.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "replication_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_replication" {
  name               = "${var.bucket_name}-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json
}

# Read versions (with their retention) from the source; write replicas to the destination. Never delete.
data "aws_iam_policy_document" "audit_replication" {
  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.audit.arn]
  }
  statement {
    actions = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
    "s3:GetObjectRetention", "s3:GetObjectLegalHold"]
    resources = ["${aws_s3_bucket.audit.arn}/audit/*"]
  }
  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateTags"]
    resources = ["${aws_s3_bucket.audit_replica.arn}/audit/*"]
  }
  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [1]
    content {
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_arn]
    }
  }
  dynamic "statement" {
    for_each = var.replica_kms_key_arn == null ? [] : [1]
    content {
      actions   = ["kms:Encrypt"]
      resources = [var.replica_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "audit_replication" {
  role   = aws_iam_role.audit_replication.id
  policy = data.aws_iam_policy_document.audit_replication.json
}

resource "aws_s3_bucket_replication_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  role   = aws_iam_role.audit_replication.arn

  rule {
    id     = "audit-to-${var.replica_region}"
    status = "Enabled"
    filter {
      prefix = "audit/"
    }
    delete_marker_replication {
      status = "Disabled"
    }

    dynamic "source_selection_criteria" {
      for_each = var.kms_key_arn == null ? [] : [1]
      content {
        sse_kms_encrypted_objects {
          status = "Enabled"
        }
      }
    }

    destination {
      bucket        = aws_s3_bucket.audit_replica.arn
      storage_class = "STANDARD"

      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }

      dynamic "encryption_configuration" {
        for_each = var.replica_kms_key_arn == null ? [] : [1]
        content {
          replica_kms_key_id = var.replica_kms_key_arn
        }
      }
    }
  }

  # Replication needs versioning on both sides first.
  depends_on = [aws_s3_bucket_versioning.audit, aws_s3_bucket_versioning.audit_replica]
}

# A replica that silently stops is worse than none: page when objects fail to replicate.
resource "aws_cloudwatch_metric_alarm" "audit_replication_failed" {
  count               = var.replication_alarm_topic_arn == null ? 0 : 1
  alarm_name          = "${var.bucket_name}-replication-failed"
  alarm_description   = "Audit WORM objects are failing to replicate to ${var.replica_region}."
  namespace           = "AWS/S3"
  metric_name         = "OperationsFailedReplication"
  dimensions          = { SourceBucket = aws_s3_bucket.audit.bucket, DestinationBucket = aws_s3_bucket.audit_replica.bucket, RuleId = "audit-to-${var.replica_region}" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.replication_alarm_topic_arn]
}

output "replica_bucket" { value = aws_s3_bucket.audit_replica.bucket }
