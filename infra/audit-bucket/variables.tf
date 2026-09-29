variable "region" {
  type    = string
  default = "us-east-1"
}

variable "bucket_name" {
  type        = string
  description = "Globally unique name for the audit archive bucket."
}

variable "prefix" {
  type    = string
  default = "audit/meta-api-tester"
}

variable "lock_mode" {
  type        = string
  default     = "GOVERNANCE"
  description = <<-EOT
    Default Object Lock mode. GOVERNANCE lets principals with s3:BypassGovernanceRetention delete early (use while
    validating). COMPLIANCE cannot be shortened or removed by anyone, including the root account, until the
    retention expires. Objects written under COMPLIANCE cannot be deleted and will incur storage cost for the
    full period. Switch to COMPLIANCE deliberately.
  EOT
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  default     = 365
  description = "Default retention applied to every object version (the shipper also sets it explicitly per object)."
}

variable "shipper_principal_arns" {
  type        = list(string)
  default     = []
  description = "IAM roles/users that run the audit shipper (write-only). Attach aws_iam_policy.shipper otherwise."
}

variable "break_glass_principal_arns" {
  type        = list(string)
  default     = []
  description = "Only these principals may use s3:BypassGovernanceRetention (GOVERNANCE mode). Empty = nobody."
}

variable "archive_transition_days" {
  type    = number
  default = 90
}

variable "admin_principal_arns" {
  type        = list(string)
  default     = []
  description = "Principals (incl. your Terraform deployer role) allowed to change lock/versioning/lifecycle/policy. Empty = no deny statement."
}
