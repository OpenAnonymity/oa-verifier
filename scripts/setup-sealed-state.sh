#!/usr/bin/env bash
# One-time Azure setup for sealed persistence on the SHARED verifier (oa-verifier-2).
#
# Creates, idempotently, in resource group oa-verifier:
#   * a Key Vault (Premium, RBAC, purge protection) that holds
#       - the sealing key (KEK): RSA-HSM, exportable, with an SKR release policy
#       - the sealed blobs, as secrets (TLS bundle, station registry)
#   * role assignments:
#       - the container group's user-assigned identity may release the KEK
#         (Key Vault Crypto Service Release User) and read/write the secrets
#         (Key Vault Secrets Officer)
#       - the GitHub deploy service principal may update the KEK's release
#         policy (Key Vault Crypto Officer) -- build-and-sign.yml does this
#         before every deploy so the new build's policy hash is allowed
#       - you (the person running this) may create the key (Crypto Officer)
#
# The KEK is created with a PLACEHOLDER release policy (hostdata = 64 zeros):
# nothing can release it until the first deploy writes the real policy hash.
#
# Run it in Azure Cloud Shell (bash) as an Owner of the subscription/resource
# group. Re-running is safe. It never touches the container group, the
# production verifier, or any existing key/secret. Nothing here is a secret:
# vault and key NAMES are all the workflow needs.
#
# Usage:
#   bash setup-sealed-state.sh                 # defaults below
#   VAULT_NAME=myvault bash setup-sealed-state.sh
#
# Then set the repository variables it prints (Settings -> Secrets and
# variables -> Actions -> Variables, or the printed `gh variable set` lines).
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-oa-verifier}"
LOCATION="${LOCATION:-eastus}"
VAULT_NAME="${VAULT_NAME:-oa-verifier2-sealed}"          # 3-24 chars, globally unique
KEK_NAME="${KEK_NAME:-oa-verifier2-sealing-kek}"
IDENTITY_NAME="${IDENTITY_NAME:-oa-verifier-pull}"         # the group's user-assigned identity
DEPLOY_SP_NAME="${DEPLOY_SP_NAME:-github-oa-verifier}"     # display name of the AZURE_CREDENTIALS principal
DEPLOY_SP_OBJECT_ID="${DEPLOY_SP_OBJECT_ID:-}"             # set this to skip the name lookup
ACR_NAME="${ACR_NAME:-oaverifieracr}"
MAA_AUTHORITY="${MAA_AUTHORITY:-https://sharedeus.eus.attest.azure.net}"
GITHUB_REPO="${GITHUB_REPO:-OpenAnonymity/oa-verifier}"

say()  { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\n!! %s\n' "$*" >&2; exit 1; }

command -v az >/dev/null || die "az not found; run this in Azure Cloud Shell (bash)"
command -v jq >/dev/null || die "jq not found"

say "Subscription"
az account show --query "{name:name, id:id, user:user.name}" -o table
SUB_ID=$(az account show --query id -o tsv)
ME_OID=$(az ad signed-in-user show --query id -o tsv)
note "signed in as object id $ME_OID"

az group show -n "$RESOURCE_GROUP" -o none || die "resource group $RESOURCE_GROUP not found in this subscription"

# ---------------------------------------------------------------------------
say "Key Vault $VAULT_NAME (Premium, RBAC, purge protection)"
if az keyvault show -n "$VAULT_NAME" -g "$RESOURCE_GROUP" -o none 2>/dev/null; then
  note "exists"
else
  if az keyvault list-deleted --query "[?name=='$VAULT_NAME']" -o tsv | grep -q .; then
    die "a soft-deleted vault named $VAULT_NAME exists; recover it (az keyvault recover) or pick another VAULT_NAME"
  fi
  az keyvault create -n "$VAULT_NAME" -g "$RESOURCE_GROUP" -l "$LOCATION" \
    --sku premium --enable-rbac-authorization true \
    --enable-purge-protection true --retention-days 90 -o none
  note "created"
fi
VAULT_ID=$(az keyvault show -n "$VAULT_NAME" -g "$RESOURCE_GROUP" --query id -o tsv)
VAULT_URL=$(az keyvault show -n "$VAULT_NAME" -g "$RESOURCE_GROUP" --query properties.vaultUri -o tsv)
VAULT_URL="${VAULT_URL%/}"
SKU=$(az keyvault show -n "$VAULT_NAME" -g "$RESOURCE_GROUP" --query properties.sku.name -o tsv)
[ "${SKU,,}" = "premium" ] || die "vault $VAULT_NAME is sku=$SKU; secure key release needs Premium (HSM-backed keys)"
RBAC=$(az keyvault show -n "$VAULT_NAME" -g "$RESOURCE_GROUP" --query properties.enableRbacAuthorization -o tsv)
[ "${RBAC,,}" = "true" ] || die "vault $VAULT_NAME is not in RBAC mode; this script assigns RBAC roles"
note "$VAULT_URL"

assign() { # assign <role> <principal-object-id> <scope> <label>
  local role="$1" oid="$2" scope="$3" label="$4"
  if az role assignment list --assignee "$oid" --role "$role" --scope "$scope" --query "[0].id" -o tsv 2>/dev/null | grep -q .; then
    note "$label already has '$role'"
  else
    az role assignment create --role "$role" --assignee-object-id "$oid" --assignee-principal-type "${5:-ServicePrincipal}" --scope "$scope" -o none
    note "$label granted '$role'"
  fi
}

say "Your own access to create the key"
assign "Key Vault Crypto Officer" "$ME_OID" "$VAULT_ID" "you" User

# ---------------------------------------------------------------------------
say "Container group identity $IDENTITY_NAME"
if ! az identity show -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" -o none 2>/dev/null; then
  az identity create -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" -l "$LOCATION" -o none
  note "created"
fi
ID_RES=$(az identity show -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" --query id -o tsv)
ID_PRINCIPAL=$(az identity show -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" --query principalId -o tsv)
ID_CLIENT=$(az identity show -n "$IDENTITY_NAME" -g "$RESOURCE_GROUP" --query clientId -o tsv)
note "resource id: $ID_RES"
note "client id:   $ID_CLIENT"
ACR_ID=$(az acr show -n "$ACR_NAME" --query id -o tsv 2>/dev/null || true)
if [ -n "$ACR_ID" ]; then
  assign "AcrPull" "$ID_PRINCIPAL" "$ACR_ID" "identity (on $ACR_NAME)"
else
  note "ACR $ACR_NAME not found in this subscription; skipping AcrPull (set ACR_NAME if it lives elsewhere)"
fi

# ---------------------------------------------------------------------------
say "GitHub deploy principal"
if [ -z "$DEPLOY_SP_OBJECT_ID" ]; then
  DEPLOY_SP_OBJECT_ID=$(az ad sp list --display-name "$DEPLOY_SP_NAME" --query "[0].id" -o tsv 2>/dev/null || true)
fi
if [ -z "$DEPLOY_SP_OBJECT_ID" ]; then
  note "could not find a service principal named '$DEPLOY_SP_NAME'."
  note "Principals with role assignments on $RESOURCE_GROUP:"
  az role assignment list -g "$RESOURCE_GROUP" --query "[?principalType=='ServicePrincipal'].{name:principalName, objectId:principalId, role:roleDefinitionName}" -o table || true
  die "re-run with DEPLOY_SP_OBJECT_ID=<objectId of the principal AZURE_CREDENTIALS uses>"
fi
note "object id: $DEPLOY_SP_OBJECT_ID"

# ---------------------------------------------------------------------------
say "Sealing key $KEK_NAME (RSA-HSM 3072, exportable, placeholder release policy)"
PLACEHOLDER=$(mktemp)
cat > "$PLACEHOLDER" <<EOF
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "$MAA_AUTHORITY",
      "allOf": [
        {"claim": "x-ms-sevsnpvm-hostdata", "equals": "0000000000000000000000000000000000000000000000000000000000000000"},
        {"claim": "x-ms-attestation-type", "equals": "sevsnpvm"},
        {"claim": "x-ms-compliance-status", "equals": "azure-compliant-uvm"},
        {"claim": "x-ms-sevsnpvm-is-debuggable", "equals": "false"}
      ]
    }
  ]
}
EOF
if az keyvault key show --vault-name "$VAULT_NAME" -n "$KEK_NAME" -o none 2>/dev/null; then
  note "exists (release policy left as is; the deploy workflow maintains it)"
  EXPORTABLE=$(az keyvault key show --vault-name "$VAULT_NAME" -n "$KEK_NAME" --query "attributes.exportable" -o tsv)
  [ "${EXPORTABLE,,}" = "true" ] || die "$KEK_NAME exists but is not exportable; SKR cannot release it. Pick another KEK_NAME."
else
  # RBAC propagation can take a few minutes right after the role assignment.
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if az keyvault key create --vault-name "$VAULT_NAME" -n "$KEK_NAME" \
         --kty RSA-HSM --size 3072 --exportable true --policy @"$PLACEHOLDER" -o none 2>/tmp/kek-err; then
      note "created"; break
    fi
    if grep -qi "forbidden\|does not have keys create permission\|Caller is not authorized" /tmp/kek-err && [ "$attempt" -lt 10 ]; then
      note "waiting for role assignment to propagate ($attempt/10)..."; sleep 30
    else
      cat /tmp/kek-err >&2; die "could not create the key"
    fi
  done
fi
rm -f "$PLACEHOLDER"
KEK_ID=$(az keyvault key show --vault-name "$VAULT_NAME" -n "$KEK_NAME" --query key.kid -o tsv)
KEK_RES="$VAULT_ID/keys/$KEK_NAME"
note "$KEK_ID"

# ---------------------------------------------------------------------------
say "Role assignments"
assign "Key Vault Crypto Service Release User" "$ID_PRINCIPAL" "$KEK_RES" "identity"
assign "Key Vault Secrets Officer" "$ID_PRINCIPAL" "$VAULT_ID" "identity"
assign "Key Vault Crypto Officer" "$DEPLOY_SP_OBJECT_ID" "$KEK_RES" "deploy principal"

# ---------------------------------------------------------------------------
say "Done. Set these GitHub repository VARIABLES on $GITHUB_REPO (not secrets):"
cat <<EOF

  STATION_STATE_STORE      = keyvault-sealed
  TLS_CERT_STORE           = keyvault-sealed
  SEALED_KEK_VAULT         = $VAULT_URL
  SEALED_KEK_NAME          = $KEK_NAME
  SEALED_SECRET_VAULT      = $VAULT_URL
  SEALED_MSI_CLIENT_ID     = $ID_CLIENT
  ACI_PULL_IDENTITY_ID     = $ID_RES
  KEK_RELEASE_KEEP_HASHES  = 4

With the GitHub CLI:

  gh variable set STATION_STATE_STORE     -R $GITHUB_REPO -b keyvault-sealed
  gh variable set TLS_CERT_STORE          -R $GITHUB_REPO -b keyvault-sealed
  gh variable set SEALED_KEK_VAULT        -R $GITHUB_REPO -b "$VAULT_URL"
  gh variable set SEALED_KEK_NAME         -R $GITHUB_REPO -b "$KEK_NAME"
  gh variable set SEALED_SECRET_VAULT     -R $GITHUB_REPO -b "$VAULT_URL"
  gh variable set SEALED_MSI_CLIENT_ID    -R $GITHUB_REPO -b "$ID_CLIENT"
  gh variable set ACI_PULL_IDENTITY_ID    -R $GITHUB_REPO -b "$ID_RES"
  gh variable set KEK_RELEASE_KEEP_HASHES -R $GITHUB_REPO -b 4

Notes:
  * ACI_PULL_IDENTITY_ID may already be set; it must point at the SAME identity
    as SEALED_MSI_CLIENT_ID ($IDENTITY_NAME).
  * The key's release policy is a placeholder until the first deploy from main
    writes the real policy hash (workflow step "Authorize this build's policy
    hash for sealed-state key release").
  * Purge protection means the vault and key cannot be permanently deleted for
    90 days after a soft delete. That is deliberate: losing the key loses the
    saved state, and every station would need a person to log in again.
EOF
