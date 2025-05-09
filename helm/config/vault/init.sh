#!/bin/sh

# Check if Vault is already initialized
echo "Initialize Vault (if not already initialized)"
vault status

if vault status | grep -q "Initialized.*true"; then
  echo "Vault already initialized"
  exit 0
fi

# Exit on any error hereafter
set -e

echo "Vault not initialized, initializing now..."
vault operator init -key-shares=1 -key-threshold=1 -format=json > /vault/file/init.json

UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' /vault/file/init.json)
ROOT_TOKEN=$(jq -r '.root_token' /vault/file/init.json)
echo "UNSEAL_KEY: $UNSEAL_KEY"
echo "ROOT_TOKEN: $ROOT_TOKEN"

vault operator unseal "$UNSEAL_KEY"
vault login "$ROOT_TOKEN"

echo "Enable Transit Secrets Engine"
vault secrets enable transit

echo "Create an encryption key"
vault write -f transit/keys/my-encryption-key

echo "Enable Userpass Authentication"
vault auth enable userpass

echo "Create a User with Userpass Authentication"
vault write auth/userpass/users/myuser password=mypassword policies=transit-policy

echo "Enable AppRole Authentication"
vault auth enable approle

echo "Create a Policy for Transit Secrets Engine"
vault policy write transit-policy - <<EOF
path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

echo "Create an AppRole with the defined policy"
vault write auth/approle/role/my-role \
    token_policies="transit-policy" \
    token_ttl=120m \
    token_max_ttl=120m

echo "Generate Secret ID"
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/my-role/secret-id)

# Output Role ID
ROLE_ID=$(vault read -field=role_id auth/approle/role/my-role/role-id)
echo "Role ID: $ROLE_ID"

# Output Secret ID
echo "Secret ID: $SECRET_ID"