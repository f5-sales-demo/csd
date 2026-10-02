variable "alert_receiver_email" {
  description = "Email destination for Page Tamper alerts. Sensitive for CLI display; also stored in the encrypted Terraform state."
  type        = string
  sensitive   = true
  nullable    = false

  validation {
    condition     = length(var.alert_receiver_email) >= 3 && length(var.alert_receiver_email) <= 254 && can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.alert_receiver_email))
    error_message = "alert_receiver_email must be a valid email address."
  }
}

module "page_tamper_alerts" {
  source = "./modules/csd-page-tamper-alerts"

  namespace = var.namespace
  email     = var.alert_receiver_email

  depends_on = [xcsh_namespace.csd, terraform_data.require_csd]
}

output "xcsh_alert_receiver_name" {
  description = "Namespace-scoped Page Tamper Alert Receiver resource name."
  value       = module.page_tamper_alerts.receiver_name
}

output "xcsh_alert_policy_name" {
  description = "Namespace-scoped Page Tamper Alert Policy resource name."
  value       = module.page_tamper_alerts.policy_name
}