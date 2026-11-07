# The audit WORM bucket (Stage 1, Step 7.4).
#
# Object Lock must be enabled when the bucket is created — it cannot be turned on later, and a bucket created
# without it can never satisfy the retention requirement. COMPLIANCE mode is the strict one: not even the
# account root can delete an object or shorten its retention before the date. GOVERNANCE mode can be bypassed
# by principals with s3:BypassGovernanceRetention, which defeats the purpose here.
#
# Apply with: terraform init && terraform apply
# Not run by the test suite; the local sink (AUDIT_WORM_BACKEND=local) is what development uses.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

variable "bucket_name" {
  type        = string
  description = "Globally unique name, e.g. synapsepay-audit-prod"
}

variable "retention_days" {
  type        = number
  default     = 1825 # five years, per RBI's record-retention requirement
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key for SSE-KMS. Object Lock works with SSE-S3 too, but a CMK gives key-level control."
  default     = null
}

resource "aws_s3_bucket" "audit" {
  bucket              = var.bucket_name
  object_lock_enabled = true
  force_destroy       = false # a WORM bucket must never be casually destroyed

  tags = { Purpose = "synapsepay-audit-log", Retention = "${var.retention_days}d" }
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# The ingester writes; it cannot delete or overwrite. Only a designated break-glass role may read.
data "aws_iam_policy_document" "audit" {
  statement {
    sid       = "AuditWriterAppendOnly"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/audit/*"]
  }
  statement {
    sid       = "DenyDeletionAndOverwrite"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/audit/*"]
    condition {
      # PutObject is only allowed when the object does not already exist (append-only, not overwrite).
      test     = "StringEquals"
      variable = "s3:if-none-match"
      values   = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit.json
}

output "bucket" { value = aws_s3_bucket.audit.bucket }
output "prefix" { value = "audit" }
