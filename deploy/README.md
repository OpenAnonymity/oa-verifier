# Deployment Guide

This folder contains the ARM template for deploying the oa-verifier as an Azure Confidential Container.

## Files

- `aci-template.json` - ARM template with embedded CCE policy

## Prerequisites

```bash
# Azure CLI with confcom extension
az extension add --name confcom

# Docker (for policy generation)
docker --version

# Logged into Azure
az login
```

## Deployment Steps

### 1. Build and Push Container

```bash
# Create ACR (if needed)
az acr create --name YOUR_ACR --resource-group YOUR_RG --sku Basic --admin-enabled true

# Build in Azure (no local Docker needed)
cd ..
az acr build --registry YOUR_ACR --image oa-verifier:latest .
```

### 2. Update Template with Your Image

Edit `aci-template.json` and update the image reference with your ACR and digest:

```json
"image": "YOUR_ACR.azurecr.io/oa-verifier@sha256:YOUR_DIGEST"
```

### 3. Generate CCE Policy

```bash
# Pull images locally first
docker pull YOUR_ACR.azurecr.io/oa-verifier@sha256:YOUR_DIGEST
docker pull mcr.microsoft.com/aci/skr:2.13

# Generate and inject policy
az confcom acipolicygen -a aci-template.json --disable-stdio
```

### 4. Deploy

```bash
az deployment group create \
  --resource-group YOUR_RG \
  --template-file aci-template.json
```

### 5. Get Service URL

```bash
az container show --name oa-verifier --resource-group YOUR_RG \
  --query "{IP:ipAddress.ip, FQDN:ipAddress.fqdn}" -o table
```

## Current Deployment

| Property | Value |
|----------|-------|
| Container Image | `oaverifieracr.azurecr.io/oa-verifier@sha256:dd547f4905b35fe57eab3d389348723547fcffbb56128433aee302f90260db91` |
| CCE Policy Hash | `bb4ce8d9e736e60acb2e74b6e20db6c947088f6feea0a4918b23e00881c288b5` |
| Service URL | `http://oa-verifier.eastus.azurecontainer.io:8000` |

## Updating the Deployment

When you change the code:

1. Rebuild: `az acr build --registry oaverifieracr --image oa-verifier:latest .`
2. Update image digest in `aci-template.json`
3. Pull new image: `docker pull oaverifieracr.azurecr.io/oa-verifier@sha256:NEW_DIGEST`
4. Regenerate policy: `az confcom acipolicygen -a aci-template.json --disable-stdio`
5. Delete old container: `az container delete --name oa-verifier --resource-group oa-verifier --yes`
6. Deploy: `az deployment group create --resource-group oa-verifier --template-file aci-template.json`

## Verification

See [../docs/ATTESTATION.md](../docs/ATTESTATION.md) for how users can verify the attestation.

