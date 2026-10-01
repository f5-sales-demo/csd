output "namespace" {
  description = "Namespace containing the Page Tamper alert resources."
  value       = var.namespace
}

output "receiver_name" {
  description = "Namespace-scoped Page Tamper Alert Receiver name."
  value       = xcsh_alert_receiver.page_tamper.name
}

output "policy_name" {
  description = "Namespace-scoped Page Tamper Alert Policy name."
  value       = xcsh_alert_policy.page_tamper.name
}

output "alertname_regex" {
  description = "Alert names routed by the namespace-scoped Page Tamper policy."
  value       = one(xcsh_alert_policy.page_tamper.routes).alertname_regex
}
