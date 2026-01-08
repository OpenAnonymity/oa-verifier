#!/bin/bash
set -e

# ============================================================================
# OA-VERIFIER DEPLOYMENT SCRIPT
# Handles: code updates, policy regeneration, and deployment to ACI
# ============================================================================

# Configuration
RESOURCE_GROUP="${RESOURCE_GROUP:-oa-verifier}"
ACR_NAME="${ACR_NAME:-oaverifieracr}"
CONTAINER_NAME="oa-verifier"
LOCATION="${LOCATION:-eastus}"
SECRETS_FILE="${SECRETS_FILE:-deploy/.env}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ============================================================================
# STEP 0: Check prerequisites
# ============================================================================
check_prerequisites() {
    log "Checking prerequisites..."
    
    command -v az >/dev/null 2>&1 || error "Azure CLI not found. Install from https://aka.ms/InstallAzureCLI"
    command -v docker >/dev/null 2>&1 || error "Docker not found."
    command -v jq >/dev/null 2>&1 || error "jq not found. Install with: sudo apt install jq"
    
    # Check az confcom extension
    if ! az extension show --name confcom >/dev/null 2>&1; then
        log "Installing confcom extension..."
        az extension add --name confcom
    fi
    
    # Check secrets file
    if [[ ! -f "$SECRETS_FILE" ]]; then
        warn "Secrets file not found: $SECRETS_FILE"
        warn "Creating template..."
        create_secrets_template
        error "Please edit $SECRETS_FILE with your actual secrets, then re-run."
    fi
    
    log "Prerequisites OK"
}

create_secrets_template() {
    cat > "$SECRETS_FILE" << 'EOF'
# OA-Verifier Environment Variables
# This file is in .gitignore - do not commit!

STATION_REGISTRY_URL=http://localhost:8005
STATION_REGISTRY_SECRET=your-secret-here
CHALLENGE_MIN_INTERVAL=0
CHALLENGE_MAX_INTERVAL=0
EOF
}

# ============================================================================
# STEP 1: Build container
# ============================================================================
build_container() {
    log "Building container..."
    
    docker build -t ${ACR_NAME}.azurecr.io/oa-verifier:latest .
    
    log "Container built successfully"
}

# ============================================================================
# STEP 2: Push to ACR
# ============================================================================
push_to_acr() {
    log "Logging into ACR..."
    az acr login --name $ACR_NAME
    
    log "Pushing container to ACR..."
    docker push ${ACR_NAME}.azurecr.io/oa-verifier:latest
    
    # Get the digest for reproducibility
    DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' ${ACR_NAME}.azurecr.io/oa-verifier:latest 2>/dev/null || \
             az acr repository show-manifests --name $ACR_NAME --repository oa-verifier --top 1 --orderby time_desc --query "[0].digest" -o tsv)
    
    log "Container pushed. Digest: $DIGEST"
    
    # Update template with digest
    if [[ -n "$DIGEST" ]]; then
        # Extract just the sha256:xxx part if full path
        DIGEST_ONLY=$(echo "$DIGEST" | grep -o 'sha256:[a-f0-9]*')
        if [[ -n "$DIGEST_ONLY" ]]; then
            log "Updating template with digest: $DIGEST_ONLY"
            sed -i "s|${ACR_NAME}.azurecr.io/oa-verifier@sha256:[a-f0-9]*|${ACR_NAME}.azurecr.io/oa-verifier@${DIGEST_ONLY}|g" deploy/aci-template.json
            sed -i "s|${ACR_NAME}.azurecr.io/oa-verifier:latest|${ACR_NAME}.azurecr.io/oa-verifier@${DIGEST_ONLY}|g" deploy/aci-template.json
        fi
    fi
}

# ============================================================================
# STEP 3: Generate CCE policy
# ============================================================================
generate_policy() {
    log "Generating CCE policy..."
    
    # Generate policy with wildcards for secrets
    # The tool modifies the template in-place with -a flag
    az confcom acipolicygen \
        -a deploy/aci-template.json \
        --approve-wildcards \
        --disable-stdio
    
    # Extract and display policy hash
    POLICY_B64=$(jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' deploy/aci-template.json)
    POLICY_HASH=$(echo "$POLICY_B64" | base64 -d | sha256sum | cut -d' ' -f1)
    
    log "Policy generated. Hash: $POLICY_HASH"
    
    # Save hash to file for reference
    echo "$POLICY_HASH" > deploy/policy-hash.txt
    
    # Update verification script with new hash
    if [[ -f "scripts/verify_attestation.py" ]]; then
        sed -i "s/DEFAULT_POLICY_HASH = \".*\"/DEFAULT_POLICY_HASH = \"${POLICY_HASH}\"/" scripts/verify_attestation.py
        log "Updated verify_attestation.py with new hash"
    fi
}

# ============================================================================
# STEP 4: Create deployment template with secrets
# ============================================================================
create_deploy_template() {
    log "Creating deployment template with secrets..."
    
    # Load secrets
    source "$SECRETS_FILE"
    
    # Copy template
    cp deploy/aci-template.json deploy/aci-deploy.json
    
    # Replace placeholders with actual secrets using jq
    jq --arg url "$STATION_REGISTRY_URL" \
       --arg secret "$STATION_REGISTRY_SECRET" \
       --arg min_interval "$CHALLENGE_MIN_INTERVAL" \
       --arg max_interval "$CHALLENGE_MAX_INTERVAL" \
       '(.resources[0].properties.containers[0].properties.environmentVariables[] | 
         select(.name == "STATION_REGISTRY_URL")) |= . + {"value": $url} |
        (.resources[0].properties.containers[0].properties.environmentVariables[] | 
         select(.name == "STATION_REGISTRY_SECRET")) |= del(.value) + {"secureValue": $secret} |
        (.resources[0].properties.containers[0].properties.environmentVariables[] | 
         select(.name == "CHALLENGE_MIN_INTERVAL")) |= . + {"value": $min_interval} |
        (.resources[0].properties.containers[0].properties.environmentVariables[] | 
         select(.name == "CHALLENGE_MAX_INTERVAL")) |= . + {"value": $max_interval}' \
       deploy/aci-deploy.json > deploy/aci-deploy.tmp.json && mv deploy/aci-deploy.tmp.json deploy/aci-deploy.json
    
    log "Deployment template created: deploy/aci-deploy.json"
    warn "This file contains secrets - do not commit!"
}

# ============================================================================
# STEP 5: Delete existing container group (if exists)
# ============================================================================
delete_existing() {
    log "Checking for existing container group..."
    
    if az container show --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP >/dev/null 2>&1; then
        log "Deleting existing container group..."
        az container delete --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP --yes
        
        # Wait for deletion
        log "Waiting for deletion to complete..."
        sleep 30
    fi
}

# ============================================================================
# STEP 6: Deploy to ACI
# ============================================================================
deploy() {
    log "Deploying to ACI..."
    
    az deployment group create \
        --resource-group $RESOURCE_GROUP \
        --template-file deploy/aci-deploy.json \
        --verbose
    
    log "Deployment complete!"
    
    # Get the IP address
    IP=$(az container show --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP --query "ipAddress.ip" -o tsv)
    FQDN=$(az container show --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP --query "ipAddress.fqdn" -o tsv)
    
    log "Container running at:"
    log "  IP: https://${IP}:8443"
    log "  FQDN: https://${FQDN}:8443"
    log "  Self-signed TLS (use curl -k to skip cert verification)"
    log "  TLS terminates inside the enclave, not at Azure"
}

# ============================================================================
# STEP 7: Verify deployment
# ============================================================================
verify() {
    log "Waiting for container to be ready..."
    sleep 30
    
    # Use FQDN for verification
    source "$SECRETS_FILE"
    VERIFY_URL=$(az container show --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP --query "ipAddress.fqdn" -o tsv)
    
    log "Testing broadcast endpoint..."
    if curl -sfk "https://${VERIFY_URL}:8443/broadcast" >/dev/null 2>&1; then
        log "Broadcast check passed!"
    else
        warn "Broadcast check failed - container may still be starting"
        warn "Trying direct IP..."
        IP=$(az container show --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP --query "ipAddress.ip" -o tsv)
        if curl -sfk "https://${IP}:8443/broadcast" >/dev/null 2>&1; then
            log "Direct IP check passed (TLS cert may not match)"
        fi
    fi
    
    log "Testing attestation endpoint..."
    ATTESTATION=$(curl -sfk "https://${VERIFY_URL}:8443/attestation" 2>/dev/null || echo "")
    if [[ -n "$ATTESTATION" ]]; then
        RETURNED_HASH=$(echo "$ATTESTATION" | jq -r '.summary.cce_policy_hash // .summary.host_data // "unknown"')
        EXPECTED_HASH=$(cat deploy/policy-hash.txt 2>/dev/null || echo "unknown")
        
        log "Attestation response received:"
        log "  Policy hash: $RETURNED_HASH"
        
        if [[ "$RETURNED_HASH" == "$EXPECTED_HASH" ]]; then
            log "  Policy hash matches expected!"
        else
            warn "  Hash differs from expected: $EXPECTED_HASH"
        fi
    else
        warn "Could not fetch attestation - container may still be starting"
    fi
}

# ============================================================================
# STEP 8: Cleanup
# ============================================================================
cleanup() {
    log "Cleaning up sensitive files..."
    rm -f deploy/aci-deploy.json
    log "Cleanup complete"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "=============================================="
    echo "  OA-VERIFIER DEPLOYMENT"
    echo "=============================================="
    
    cd "$(dirname "$0")/.."
    
    check_prerequisites
    build_container
    push_to_acr
    generate_policy
    create_deploy_template
    delete_existing
    deploy
    verify
    cleanup
    
    echo ""
    echo "=============================================="
    echo "  DEPLOYMENT COMPLETE"
    echo "=============================================="
    echo ""
    log "New policy hash: $(cat deploy/policy-hash.txt)"
    log "Update documentation and verification scripts with this hash."
}

# Run
main "$@"

