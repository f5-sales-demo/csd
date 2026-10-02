resource "xcsh_alert_receiver" "page_tamper" {
  name      = "csd-page-tamper-alert-receiver"
  namespace = var.namespace

  email {
    email = var.email
  }
}

resource "xcsh_alert_policy" "page_tamper" {
  name      = "csd-page-tamper-alert-policy"
  namespace = var.namespace

  receivers {
    name      = xcsh_alert_receiver.page_tamper.name
    namespace = xcsh_alert_receiver.page_tamper.namespace
  }

  routes {
    alertname_regex = "^ClientSideDefenseHttpHeader(Modified|Compromised)$"
    send            = {}
  }
}
