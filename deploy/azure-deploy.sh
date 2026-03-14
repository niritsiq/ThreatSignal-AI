#!/bin/bash
# =============================================================================
# ThreatSignal AI — Azure Container Apps Deployment Script
# =============================================================================
# Run this script once to create all Azure resources and deploy the container.
# Pre-requisites:
#   - az CLI installed and logged in (az login)
#   - Docker Desktop running
#   - .env file with your API keys
#
# Usage:
#   chmod +x deploy/azure-deploy.sh
#   ./deploy/azure-deploy.sh
# =============================================================================

set -e  # exit immediately if any command fails

# ── Configuration ─────────────────────────────────────────────────────────────
RESOURCE_GROUP="threatsignal-rg"
LOCATION="eastus"
ACR_NAME="threatsignalacr"           # must be globally unique — change if taken
CONTAINER_APP_ENV="threatsignal-env"
CONTAINER_APP_NAME="threatsignal-api"
IMAGE_NAME="threatsignal-ai"
IMAGE_TAG="latest"

# Load API keys from .env (if present)
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

echo "=== ThreatSignal AI — Azure Deployment ==="
echo "Resource Group : $RESOURCE_GROUP"
echo "Location       : $LOCATION"
echo "ACR            : $ACR_NAME"
echo ""

# ── Step 1: Resource Group ────────────────────────────────────────────────────
echo "[1/6] Creating resource group..."
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none
echo "      Done."

# ── Step 2: Container Registry ────────────────────────────────────────────────
echo "[2/6] Creating Azure Container Registry (ACR)..."
az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Basic \
  --admin-enabled true \
  --output none
echo "      Done."

# ── Step 3: Build index locally (needed inside the image) ────────────────────
echo "[3/6] Building FAISS breach index locally..."
python scripts/build_index.py
echo "      Done."

# ── Step 4: Build and push Docker image via ACR ───────────────────────────────
echo "[4/6] Building Docker image in Azure (no local Docker push needed)..."
az acr build \
  --registry "$ACR_NAME" \
  --image "$IMAGE_NAME:$IMAGE_TAG" \
  .
echo "      Done. Image: ${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}"

# ── Step 5: Container Apps Environment ───────────────────────────────────────
echo "[5/6] Creating Container Apps environment..."
az containerapp env create \
  --name "$CONTAINER_APP_ENV" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none
echo "      Done."

# ── Step 6: Deploy Container App ─────────────────────────────────────────────
echo "[6/6] Deploying container app..."

# Get ACR credentials
ACR_PASSWORD=$(az acr credential show \
  --name "$ACR_NAME" \
  --query "passwords[0].value" \
  --output tsv)

az containerapp create \
  --name "$CONTAINER_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$CONTAINER_APP_ENV" \
  --image "${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}" \
  --registry-server "${ACR_NAME}.azurecr.io" \
  --registry-username "$ACR_NAME" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 8000 \
  --ingress external \
  --cpu 0.25 \
  --memory 0.5Gi \
  --min-replicas 0 \
  --max-replicas 1 \
  --env-vars \
    SHODAN_API_KEY="${SHODAN_API_KEY}" \
    OPENAI_API_KEY="${OPENAI_API_KEY}" \
    AZURE_OPENAI_ENDPOINT="${AZURE_OPENAI_ENDPOINT:-}" \
    AZURE_OPENAI_API_KEY="${AZURE_OPENAI_API_KEY:-}" \
    LLM_MODEL="gpt-4o-mini" \
    EMBEDDING_MODEL="text-embedding-3-small" \
    BREACH_DATASET_PATH="data/breach_cases.jsonl" \
    FAISS_INDEX_PATH="data/breach_index.faiss" \
    LOG_LEVEL="INFO" \
  --output none

echo "      Done."
echo ""

# ── Get the live URL ──────────────────────────────────────────────────────────
APP_URL=$(az containerapp show \
  --name "$CONTAINER_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" \
  --output tsv)

echo "=============================================="
echo "  Deployment complete!"
echo "  Live URL: https://${APP_URL}"
echo "  Health:   curl https://${APP_URL}/health"
echo "=============================================="
echo ""
echo "To analyze a domain:"
echo "  curl -X POST https://${APP_URL}/analyze \\"
echo '    -H "Content-Type: application/json" \'
echo '    -d "{\"domain\": \"okta.com\", \"time_horizon_days\": 30}"'
