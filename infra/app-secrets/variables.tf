variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type        = string
  default     = "meta-api-tester"
  description = "Secrets are created as <prefix>/app and <prefix>/audit-gateway."
}

variable "app_principal_arns" {
  type        = list(string)
  default     = []
  description = "Roles that run the app (read <prefix>/app only)."
}

variable "gateway_principal_arns" {
  type        = list(string)
  default     = []
  description = "Roles that run the audit gateway/shipper (read <prefix>/audit-gateway only)."
}
