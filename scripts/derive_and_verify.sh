#!/usr/bin/env bash
#
# Zero-Trust Attestation Verification
# 
# This script derives the expected policy hash from source code and verifies
# the live service against it. You trust NOTHING except your own audit.
#
# Usage:
#   ./derive_and_verify.sh [--skip-build] [--service-url URL]
#
# Requirements:
#   - Docker
#   - Azure CLI with confcom extension (az extension add --name confcom)
#   - Python 3 with: pip install requests pyjwt cryptography
#

set -e

# Colors for output (disable if not in terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Default values
SERVICE_URL="https://oa-verifier.eastus.azurecontainer.io:8443"
SKIP_BUILD=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --service-url)
            SERVICE_URL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--service-url URL]"
            echo ""
            echo "Options:"
            echo "  --skip-build     Skip Docker build (use existing local image)"
            echo "  --service-url    Service URL to verify (default: $SERVICE_URL)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

printf "${BLUE}"
echo "============================================================"
echo "  ZERO-TRUST ATTESTATION VERIFICATION"
echo "  Deriving expected hash from source code"
echo "============================================================"
printf "${NC}\n"

# Step 1: Remind user to audit
printf "${YELLOW}[STEP 0] CODE AUDIT REMINDER${NC}\n"
echo "  Before proceeding, you should have audited:"
echo "  - $REPO_ROOT/internal/server/handlers.go"
echo "  - $REPO_ROOT/internal/server/server.go"
echo "  - $REPO_ROOT/Dockerfile"
echo ""
read -p "  Have you audited the code? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    printf "${RED}  Please audit the code first!${NC}\n"
    exit 1
fi

# Step 2: Build container
echo ""
printf "${YELLOW}[STEP 1] Building container from source...${NC}\n"

if [ "$SKIP_BUILD" = true ]; then
    echo "  Skipping build (--skip-build specified)"
else
    cd "$REPO_ROOT"
    # Build and capture exit code properly
    set +e
    docker build -t oa-verifier-local:verify . 2>&1 | while read line; do
        echo "  $line"
    done
    BUILD_EXIT=${PIPESTATUS[0]}
    set -e
    
    if [ $BUILD_EXIT -ne 0 ]; then
        printf "${RED}  ✗ Container build FAILED (exit code: $BUILD_EXIT)${NC}\n"
        echo ""
        echo "  Common causes:"
        echo "  1. Corrupted Go files - run: git checkout internal/server/"
        echo "  2. Missing dependencies"
        echo "  3. Syntax errors in code"
        exit 1
    fi
    printf "${GREEN}  ✓ Container built successfully${NC}\n"
fi

# Step 3: Create temporary ARM template for policy generation
echo ""
printf "${YELLOW}[STEP 2] Generating CCE policy...${NC}\n"

TEMP_DIR=$(mktemp -d)
TEMPLATE_FILE="$TEMP_DIR/template.json"
POLICY_FILE="$TEMP_DIR/policy.rego"

# Get the image digest from the local build
IMAGE_ID=$(docker inspect --format='{{.Id}}' oa-verifier-local:verify 2>/dev/null || echo "")
if [ -z "$IMAGE_ID" ]; then
    printf "${RED}  Error: Could not find local image. Run without --skip-build${NC}\n"
    exit 1
fi
echo "  Local image ID: ${IMAGE_ID:7:12}..."

# Create ARM template matching deployment config
cat > "$TEMPLATE_FILE" << 'EOF'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.ContainerInstance/containerGroups",
    "apiVersion": "2023-05-01",
    "name": "oa-verifier",
    "location": "eastus",
    "properties": {
      "sku": "Confidential",
      "containers": [{
        "name": "oa-verifier",
        "properties": {
          "image": "oa-verifier-local:verify",
          "command": ["/app/verifier"],
          "ports": [{"port": 8443, "protocol": "TCP"}],
          "resources": {"requests": {"cpu": 1.0, "memoryInGB": 2.0}},
          "environmentVariables": [
            {"name": "MAA_ENDPOINT", "value": "http://localhost:8080/attest/maa"},
            {"name": "MAA_PROVIDER_URL", "value": "sharedeus.eus.attest.azure.net"}
          ]
        }
      }],
      "osType": "Linux",
      "confidentialComputeProperties": {"ccePolicy": ""}
    }
  }]
}
EOF

# Check if az confcom is available
if ! az confcom --help &>/dev/null; then
    printf "${RED}  Error: Azure confcom extension not installed${NC}\n"
    echo "  Install with: az extension add --name confcom"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Check if running on MacOS (confcom doesn't support MacOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    printf "${RED}  Error: az confcom does not support MacOS${NC}\n"
    echo ""
    echo "  Options:"
    echo "  1. Run this script on a Linux machine"
    echo "  2. Use: python verify_attestation.py --policy-hash <KNOWN_HASH>"
    echo "  3. Use Docker: docker run -it mcr.microsoft.com/azure-cli ..."
    echo ""
    echo "  See: https://github.com/Azure/azure-cli-extensions/issues/confcom"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Generate policy
echo "  Generating policy from local image layers..."
echo "  (This may take 1-2 minutes...)"

# Run with error output visible
if ! az confcom acipolicygen -a "$TEMPLATE_FILE" --print-policy > "$POLICY_FILE" 2>&1; then
    printf "${RED}  Error: Failed to generate policy${NC}\n"
    echo "  Error output:"
    cat "$POLICY_FILE"
    rm -rf "$TEMP_DIR"
    exit 1
fi

if [ ! -s "$POLICY_FILE" ]; then
    printf "${RED}  Error: Policy file is empty${NC}\n"
    rm -rf "$TEMP_DIR"
    exit 1
fi

POLICY_SIZE=$(wc -c < "$POLICY_FILE")
printf "${GREEN}  ✓ Policy generated (${POLICY_SIZE} bytes)${NC}\n"

# Step 4: Compute hash
echo ""
printf "${YELLOW}[STEP 3] Computing policy hash...${NC}\n"

COMPUTED_HASH=$(sha256sum "$POLICY_FILE" | cut -d' ' -f1)
echo "  SHA256: $COMPUTED_HASH"
printf "${GREEN}  ✓ Hash computed from YOUR build${NC}\n"

# Save for reference
echo "$COMPUTED_HASH" > "$TEMP_DIR/computed_hash.txt"
cp "$POLICY_FILE" "$TEMP_DIR/policy_backup.rego"

# Step 5: Run verification
echo ""
printf "${YELLOW}[STEP 4] Verifying live service...${NC}\n"
echo "  Service URL: $SERVICE_URL"
echo "  Expected Hash: $COMPUTED_HASH"
echo ""

cd "$SCRIPT_DIR"
python3 verify_attestation.py \
    --url "$SERVICE_URL" \
    --policy-hash "$COMPUTED_HASH" \
    --verbose

VERIFY_EXIT=$?

# Cleanup
rm -rf "$TEMP_DIR"

# Final summary
echo ""
printf "${BLUE}============================================================${NC}\n"
if [ $VERIFY_EXIT -eq 0 ]; then
    printf "${GREEN}  ZERO-TRUST VERIFICATION COMPLETE${NC}\n"
    echo ""
    echo "  You have verified that:"
    echo "  1. You audited the source code"
    echo "  2. You built the container yourself"
    echo "  3. You computed the expected policy hash"
    echo "  4. The live service matches YOUR expectations"
    echo ""
    echo "  Trust chain: [Your Audit] → [Your Build] → [Hardware Attestation]"
else
    printf "${RED}  VERIFICATION FAILED${NC}\n"
    echo ""
    echo "  The live service does NOT match your local build."
    echo "  Possible reasons:"
    echo "  1. Different base image versions"
    echo "  2. Different environment variables in deployment"
    echo "  3. Sidecar containers not included in your policy"
    echo "  4. The service is running different code"
fi
printf "${BLUE}============================================================${NC}\n"

exit $VERIFY_EXIT

