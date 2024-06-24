
resource "tls_private_key" "ca_private_key" {
  algorithm = "RSA"
}
#
resource "local_file" "ca_key" {
  content  = tls_private_key.ca_private_key.private_key_pem
  filename = "${path.module}/data/private.key"
}

resource "tls_self_signed_cert" "ca_cert" {
  private_key_pem = tls_private_key.ca_private_key.private_key_pem

  is_ca_certificate = true

  subject {
    country     = "US"
    common_name = "Root CA"
  }

  validity_period_hours = 72

  allowed_uses = [
    "digital_signature",
    "cert_signing",
    "crl_signing",
  ]
}

resource "local_file" "ca_cert" {
  content  = tls_self_signed_cert.ca_cert.cert_pem
  filename = "${path.module}/data/ca.crt"
}

# Create private key for server certificate 
resource "tls_private_key" "internal" {
  algorithm = "RSA"
}

resource "local_file" "internal_key" {
  content  = tls_private_key.internal.private_key_pem
  filename = "${path.module}/data/tls.key"
}

# Create CSR for for server certificate 
resource "tls_cert_request" "internal_csr" {

  private_key_pem = tls_private_key.internal.private_key_pem

  dns_names = ["*.*.*.*"]
  ip_addresses = ["192.168.200.1", "192.168.200.2", "192.168.200.3", "192.168.200.4", "192.168.200.5",
  "192.168.200.6", "192.168.200.7", "192.168.200.0"]

  subject {
    country             = "US"
    organizational_unit = "Development"
  }
}

# Sign Seerver Certificate by Private CA 
resource "tls_locally_signed_cert" "internal" {
  // CSR by the development servers
  cert_request_pem = tls_cert_request.internal_csr.cert_request_pem
  // CA Private key 
  ca_private_key_pem = tls_private_key.ca_private_key.private_key_pem
  // CA certificate
  ca_cert_pem = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 24

  set_subject_key_id = true

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
    "client_auth",
  ]
}

resource "local_file" "internal_cert" {
  content  = tls_locally_signed_cert.internal.cert_pem
  filename = "${path.module}/data/tls.crt"
}


