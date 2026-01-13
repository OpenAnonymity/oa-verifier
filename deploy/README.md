# Deployment Guide

This folder contains the ARM template for deploying the oa-verifier as an Azure Confidential Container.

## CI/CD Pipeline

The build and signing process is fully automated via GitHub Actions:

1. **On push to main/tags**: GitHub Actions builds the container
2. **Signing**: Image is signed with Sigstore (keyless, using GitHub OIDC)
3. **Registry**: Pushed to both GHCR (primary) and ACR (for Azure deployment)
4. **Attestation**: GitHub provenance attestation is recorded

### Verifying the Image

Before deployment, verify the image provenance:

```bash
# Verify Sigstore signature
cosign verify ghcr.io/OWNER/oa-verifier@sha256:DIGEST \
  --certificate-identity-regexp='https://github.com/OWNER/REPO/.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'

# Verify GitHub attestation
gh attestation verify oci://ghcr.io/OWNER/oa-verifier@sha256:DIGEST --owner OWNER
```

## Files

- `aci-template.json` - ARM template with embedded CCE policy
- `deploy.sh` - Deployment script (for manual deployments)

## GitHub Secrets Required

Configure these secrets in your GitHub repository settings:

| Secret | Description |
|--------|-------------|
| `ACR_USERNAME` | Azure Container Registry username |
| `ACR_PASSWORD` | Azure Container Registry password |
| `AZURE_CREDENTIALS` | Azure service principal credentials (JSON) |

### Creating Azure Credentials

```bash
# Create service principal
az ad sp create-for-rbac --name "oa-verifier-deploy" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{resource-group} \
  --sdk-auth

# Output JSON goes into AZURE_CREDENTIALS secret
```

## Manual Deployment

### Prerequisites

```bash
# Azure CLI with confcom extension
az extension add --name confcom

# Docker (for policy generation)
docker --version

# Logged into Azure
az login
```

### Steps

#### 1. Get Latest Image Digest

Check the latest build in GitHub Actions or:

```bash
# From GHCR
docker pull ghcr.io/OWNER/oa-verifier:latest
docker inspect ghcr.io/OWNER/oa-verifier:latest --format='{{index .RepoDigests 0}}'
```

#### 2. Update Template with Digest

Edit `aci-template.json` and update the image reference:

```json
"image": "ghcr.io/OWNER/oa-verifier@sha256:YOUR_DIGEST"
```

#### 3. Generate CCE Policy

```bash
# Pull images locally first (required for policy generation)
docker pull ghcr.io/OWNER/oa-verifier@sha256:YOUR_DIGEST
docker pull mcr.microsoft.com/aci/skr:2.13

# Generate and inject policy
az confcom acipolicygen -a aci-template.json --disable-stdio
```

#### 4. Record Policy Hash

```bash
# Extract and save policy hash for verification
POLICY_B64=$(jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' aci-template.json)
POLICY_HASH=$(echo "$POLICY_B64" | base64 -d | sha256sum | cut -d' ' -f1)
echo "Policy Hash: $POLICY_HASH"
```

#### 5. Deploy

```bash
az deployment group create \
  --resource-group YOUR_RG \
  --template-file aci-template.json
```

#### 6. Get Service URL

```bash
az container show --name oa-verifier --resource-group YOUR_RG \
  --query "{IP:ipAddress.ip, FQDN:ipAddress.fqdn}" -o table
```

## Image Registries

| Registry | URL | Purpose |
|----------|-----|---------|
| **GHCR** (primary) | `ghcr.io/OWNER/oa-verifier` | Signed images, provenance attestation |
| **ACR** (mirror) | `oaverifieracr.azurecr.io/oa-verifier` | Azure deployment (faster pulls) |

Both registries contain identical images (same digest). The Sigstore signature is valid for either.

## Trust Chain

```
Source Code (GitHub)
    ↓ [GitHub Actions builds]
Container Image (signed by Sigstore)
    ↓ [Policy generated from image layers]
CCE Policy (contains layer hashes)
    ↓ [SHA256 hash]
Policy Hash (measured by AMD SEV-SNP hardware)
    ↓ [Returned in attestation]
MAA Token (signed by Azure)
```

## Verification

See [../docs/ATTESTATION.md](../docs/ATTESTATION.md) for how users can verify:
1. Sigstore provenance (image was built by GitHub Actions)
2. MAA attestation (enclave is running the expected code)
