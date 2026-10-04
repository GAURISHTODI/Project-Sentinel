locals {
  root = coalesce(var.root_dir, abspath("${path.module}/../.."))
}

# Credentials for the compose stack. Each is written to secrets/ (gitignored) as a file, which
# docker-compose mounts as a Docker secret. Changing one here only affects a new database volume:
# Postgres reads POSTGRES_PASSWORD_FILE on first start, not on later starts.
resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "random_password" "redis" {
  length  = 32
  special = false
}

resource "random_password" "jwt" {
  length  = 64
  special = false
}

resource "local_sensitive_file" "postgres_password" {
  content  = random_password.postgres.result
  filename = "${local.root}/secrets/postgres_password.txt"
}

resource "local_sensitive_file" "redis_password" {
  content  = random_password.redis.result
  filename = "${local.root}/secrets/redis_password.txt"
}

resource "local_sensitive_file" "jwt_secret" {
  content  = random_password.jwt.result
  filename = "${local.root}/secrets/jwt_secret.txt"
}

# Dev certificate authority for Postgres TLS (replaces infra/tls/make_dev_ca.sh).
resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = var.cert_validity_hours
  allowed_uses          = ["cert_signing", "crl_signing", "digital_signature"]

  subject {
    common_name = "Sentinel Dev CA"
  }
}

resource "tls_private_key" "server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "server" {
  private_key_pem = tls_private_key.server.private_key_pem
  dns_names       = ["localhost", "postgres"]
  ip_addresses    = ["127.0.0.1"]

  subject {
    common_name = "localhost"
  }
}

resource "tls_locally_signed_cert" "server" {
  cert_request_pem      = tls_cert_request.server.cert_request_pem
  ca_private_key_pem    = tls_private_key.ca.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.ca.cert_pem
  validity_period_hours = var.cert_validity_hours
  allowed_uses          = ["server_auth", "digital_signature", "key_encipherment"]
}

resource "local_sensitive_file" "ca_key" {
  content  = tls_private_key.ca.private_key_pem
  filename = "${local.root}/infra/tls/ca.key"
}

resource "local_sensitive_file" "ca_cert" {
  content  = tls_self_signed_cert.ca.cert_pem
  filename = "${local.root}/infra/tls/ca.crt"
}

resource "local_sensitive_file" "server_key" {
  content  = tls_private_key.server.private_key_pem
  filename = "${local.root}/infra/tls/server.key"
}

resource "local_sensitive_file" "server_cert" {
  content  = tls_locally_signed_cert.server.cert_pem
  filename = "${local.root}/infra/tls/server.crt"
}
