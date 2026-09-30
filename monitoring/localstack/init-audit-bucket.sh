#!/bin/sh
# LocalStack ready hook: create the local audit archive bucket with Object Lock + default retention.
# Mirrors infra/audit-bucket (Terraform) closely enough to exercise the shipper and verifier.
set -e
BUCKET="${AUDIT_S3_BUCKET:-meta-audit-local}"
awslocal s3api create-bucket --bucket "$BUCKET" --object-lock-enabled-for-bucket >/dev/null 2>&1 || true
awslocal s3api put-object-lock-configuration --bucket "$BUCKET" --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":1}}}'
echo "audit bucket $BUCKET ready (Object Lock COMPLIANCE, 1 day default)"

# Secrets Manager: local copies of the two production secrets (see infra/app-secrets).
awslocal secretsmanager create-secret --name meta-api-tester/app --secret-string \
  "{\"META_ACCESS_TOKEN\":\"mock-token-from-secrets-manager\",\"META_APP_SECRET\":\"mock-app-secret\",\"AUDIT_JOURNAL_TOKEN\":\"${JOURNAL_TOKEN}\"}" \
  >/dev/null 2>&1 || true
awslocal secretsmanager create-secret --name meta-api-tester/audit-gateway --secret-string \
  "{\"AUDIT_JOURNAL_TOKEN\":\"${JOURNAL_TOKEN}\",\"AUDIT_JOURNAL_TOKEN_PREVIOUS\":\"\"}" >/dev/null 2>&1 || true
echo "secrets meta-api-tester/app and meta-api-tester/audit-gateway ready"
