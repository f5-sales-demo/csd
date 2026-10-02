variable "namespace" {
  description = "F5 Distributed Cloud namespace for the Page Tamper alert resources."
  type        = string
  nullable    = false

  validation {
    condition     = length(var.namespace) <= 63 && can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS label containing lowercase letters, digits, or hyphens, with alphanumeric endpoints and at most 63 characters."
  }
}

variable "email" {
  description = "Sensitive destination email address for Page Tamper alerts."
  type        = string
  sensitive   = true
  nullable    = false

  validation {
    condition     = length(var.email) >= 3 && length(var.email) <= 254 && can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.email))
    error_message = "email must be a valid email address."
  }
}
