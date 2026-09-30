# Two secrets, split by consumer, so the app can't read gateway-only material and vice versa.
# Values are NOT managed here (no plaintext in Terraform state): set them with
#   aws secretsmanager put-secret-value --secret-id <prefix>/app --secret-string file://app.json
# Keys are settings names, e.g. {"META_ACCESS_TOKEN": "...", "META_APP_SECRET": "...",
#   "META_WEBHOOK_VERIFY_TOKEN": "...", "APP_API_KEYS": "...", "AUDIT_JOURNAL_TOKEN": "..."}
# Gateway: {"AUDIT_JOURNAL_TOKEN": "...", "AUDIT_JOURNAL_TOKEN_PREVIOUS": ""}

resource "aws_kms_key" "secrets" {
  description             = "${var.name_prefix} application secrets"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_secretsmanager_secret" "app" {
  name                    = "${var.name_prefix}/app"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "gateway" {
  name                    = "${var.name_prefix}/audit-gateway"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30
}

data "aws_iam_policy_document" "read_app" {
  statement {
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.app.arn]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "read_gateway" {
  statement {
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.gateway.arn]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "read_app" {
  name   = "${var.name_prefix}-read-app-secret"
  policy = data.aws_iam_policy_document.read_app.json
}

resource "aws_iam_policy" "read_gateway" {
  name   = "${var.name_prefix}-read-gateway-secret"
  policy = data.aws_iam_policy_document.read_gateway.json
}

resource "aws_iam_role_policy_attachment" "app" {
  for_each   = toset([for arn in var.app_principal_arns : element(split("/", arn), length(split("/", arn)) - 1) if strcontains(arn, ":role/")])
  role       = each.value
  policy_arn = aws_iam_policy.read_app.arn
}

resource "aws_iam_role_policy_attachment" "gateway" {
  for_each   = toset([for arn in var.gateway_principal_arns : element(split("/", arn), length(split("/", arn)) - 1) if strcontains(arn, ":role/")])
  role       = each.value
  policy_arn = aws_iam_policy.read_gateway.arn
}
