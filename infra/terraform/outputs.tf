output "ca_cert_pem" {
  description = "Public CA certificate. Clients verify the Postgres certificate against it."
  value       = tls_self_signed_cert.ca.cert_pem
}

output "secret_files" {
  description = "Paths of the files written for docker-compose secrets."
  value = [
    local_sensitive_file.postgres_password.filename,
    local_sensitive_file.redis_password.filename,
    local_sensitive_file.jwt_secret.filename,
  ]
}
