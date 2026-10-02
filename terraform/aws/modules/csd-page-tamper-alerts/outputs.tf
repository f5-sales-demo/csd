output "receiver_name" {
  description = "Namespace-scoped Page Tamper Alert Receiver resource name."
  value       = xcsh_alert_receiver.page_tamper.name
}

output "policy_name" {
  description = "Namespace-scoped Page Tamper Alert Policy resource name."
  value       = xcsh_alert_policy.page_tamper.name
}

output "namespace" {
  description = "Namespace containing the Page Tamper alert resources."
  value       = var.namespace
}

output "alertname_regex" {
  description = "Alert-name regular expression routed by the Page Tamper policy."
  value       = "^ClientSideDefenseHttpHeader(Modified|Compromised)$"
}
