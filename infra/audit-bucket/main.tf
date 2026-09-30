data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  objects    = "${aws_s3_bucket.audit.arn}/${var.prefix}/*"
}

# --- Encryption key (separate from the app's keys; key deletion is itself a 30-day, logged event) ---
resource "aws_kms_key" "audit" {
  description             = "Audit archive encryption (${var.bucket_name})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.bucket_name}"
  target_key_id = aws_kms_key.audit.key_id
}

# --- Bucket: Object Lock can only be enabled at creation ---
resource "aws_s3_bucket" "audit" {
  bucket              = var.bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled" # required by Object Lock; cannot be suspended afterwards
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = var.lock_mode
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
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

resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Locked versions can't expire early; this only moves them to cheaper storage and cleans up after retention.
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    id     = "archive"
    status = "Enabled"
    # Segments only: journal records are ~1 KB and Glacier IR bills a 128 KB minimum per object.
    filter {
      and {
        prefix                   = "${var.prefix}/"
        object_size_greater_than = 131072
      }
    }
    transition {
      days          = var.archive_transition_days
      storage_class = "GLACIER_IR"
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyUnencryptedOrWrongKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.audit.arn]
    }
  }

  statement {
    sid       = "DenyGovernanceBypass"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    dynamic "condition" {
      for_each = length(var.break_glass_principal_arns) > 0 ? [1] : []
      content {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.break_glass_principal_arns
      }
    }
  }

  # Only admins may change lock/versioning/lifecycle or delete the bucket. Skipped when no admins are
  # listed, so the deploying principal can't lock itself out.
  dynamic "statement" {
    for_each = length(var.admin_principal_arns) > 0 ? [1] : []
    content {
      sid    = "DenyLockAndPolicyTampering"
      effect = "Deny"
      actions = ["s3:PutBucketObjectLockConfiguration", "s3:PutBucketVersioning", "s3:DeleteBucket",
      "s3:PutLifecycleConfiguration", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
      resources = [aws_s3_bucket.audit.arn]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      condition {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.admin_principal_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.bucket.json
  # Apply the deny rules last so bucket configuration isn't blocked mid-apply.
  depends_on = [
    aws_s3_bucket_public_access_block.audit,
    aws_s3_bucket_object_lock_configuration.audit,
    aws_s3_bucket_lifecycle_configuration.audit,
    aws_s3_bucket_server_side_encryption_configuration.audit,
  ]
}

# --- Least-privilege policies ---
# Shipper: write new segments + read back its own head check. No delete, no list, no retention changes
# beyond what PutObject sets (s3:PutObjectRetention is required to pass ObjectLock* headers on PutObject).
data "aws_iam_policy_document" "shipper" {
  statement {
    sid       = "WriteSegments"
    actions   = ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject"]
    resources = [local.objects]
  }
  statement {
    sid       = "Encrypt"
    actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
    resources = [aws_kms_key.audit.arn]
  }
}

resource "aws_iam_policy" "shipper" {
  name   = "${var.bucket_name}-shipper"
  policy = data.aws_iam_policy_document.shipper.json
}

resource "aws_iam_role_policy_attachment" "shipper" {
  for_each   = toset([for arn in var.shipper_principal_arns : element(split("/", arn), length(split("/", arn)) - 1) if strcontains(arn, ":role/")])
  role       = each.value
  policy_arn = aws_iam_policy.shipper.arn
}

# Verifier / auditors: read-only across all versions, incl. retention and delete markers.
data "aws_iam_policy_document" "verifier" {
  statement {
    sid       = "ListVersions"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [aws_s3_bucket.audit.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.prefix}/*"]
    }
  }
  statement {
    sid       = "ReadVersions"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"]
    resources = [local.objects]
  }
  statement {
    sid       = "Decrypt"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.audit.arn]
  }
}

resource "aws_iam_policy" "verifier" {
  name   = "${var.bucket_name}-verifier"
  policy = data.aws_iam_policy_document.verifier.json
}

# --- Record every access to the archive itself (who read, wrote or tried to delete what) ---
resource "aws_cloudtrail" "audit_data_events" {
  name                          = "${var.bucket_name}-data-events"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = false
  enable_log_file_validation    = true

  advanced_event_selector {
    name = "Audit bucket object access"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.audit.arn}/"]
    }
  }
  depends_on = [aws_s3_bucket_policy.trail]
}

resource "aws_s3_bucket" "trail" {
  bucket = "${var.bucket_name}-trail"
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}
