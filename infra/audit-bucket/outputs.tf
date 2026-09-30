output "bucket" {
  value = aws_s3_bucket.audit.id
}

output "kms_key_arn" {
  value = aws_kms_key.audit.arn
}

output "gateway_policy_arn" {
  value = aws_iam_policy.gateway.arn
}

output "verifier_policy_arn" {
  value = aws_iam_policy.verifier.arn
}

output "gateway_env" {
  description = "Values for .env"
  value = {
    AUDIT_S3_BUCKET         = aws_s3_bucket.audit.id
    AUDIT_S3_PREFIX         = var.prefix
    AUDIT_S3_REGION         = var.region
    AUDIT_S3_ENDPOINT_URL   = ""
    AUDIT_S3_LOCK_MODE      = var.lock_mode
    AUDIT_S3_RETENTION_DAYS = tostring(var.retention_days)
    AUDIT_S3_KMS_KEY_ID     = aws_kms_key.audit.arn
  }
}
