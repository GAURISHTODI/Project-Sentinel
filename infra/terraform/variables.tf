variable "root_dir" {
  description = "Repository root. secrets/ and infra/tls/ are written beneath it. Leave null to use the repo that contains this module."
  type        = string
  default     = null
}

variable "cert_validity_hours" {
  description = "Validity of the dev CA and the server certificate."
  type        = number
  default     = 19800 # about 825 days
}
