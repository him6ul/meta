output "app_secret_id" {
  value = aws_secretsmanager_secret.app.name
}

output "gateway_secret_id" {
  value = aws_secretsmanager_secret.gateway.name
}

output "env" {
  value = {
    app     = { SECRETS_MANAGER_SECRET_ID = aws_secretsmanager_secret.app.name, SECRETS_MANAGER_REGION = var.region }
    gateway = { SECRETS_MANAGER_SECRET_ID = aws_secretsmanager_secret.gateway.name, SECRETS_MANAGER_REGION = var.region }
  }
}
