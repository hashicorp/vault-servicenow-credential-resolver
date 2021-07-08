listener "tcp" {
  address = "0.0.0.0:8300"
  tls_disable = false
  tls_cert_file = "/vault/config/vault-agent.pem"
  tls_key_file = "/vault/config/vault-agent-key.pem"
}

cache {
  use_auto_auth_token = true
}

vault {
  address = "http://vault:8200"
}

auto_auth {
    method {
        type = "approle"
        config = {
            role_id_file_path = "/vault/config/roleID"
            secret_id_file_path = "/vault/config/secretID"
        }
    }
}
