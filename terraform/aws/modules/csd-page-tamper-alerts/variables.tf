variable "namespace" {
  description = "F5 Distributed Cloud namespace for this alert delivery policy."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.namespace) <= 63 && can(regex("^[a-z]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS label of at most 63 characters."
  }
}

variable "email" {
  description = "Sensitive email destination for Page Tamper alert notifications."
  type        = string
  sensitive   = true
  nullable    = false

  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.email))
    error_message = "email must be a valid email address."
  }
}
