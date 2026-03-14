#!/bin/bash
# =============================================================================
# ThreatSignal AI — Update existing Azure deployment with a new image
# =============================================================================
# Run this after code changes to rebuild and redeploy without recreating
# all Azure resources.
#
# Usage:
#   chmod +x deploy/azure-update.sh
#   ./deploy/azure-update.sh
# =============================================================================

set -e

RESOURCE_GROUP="threatsignal-rg"
ACR_NAME="threatsignalacr"
CONTAINER_APP_NAME="threatsignal-api"
IMAGE_NAME="threatsignal-ai"
IMAGE_TAG="latest"

echo "=== ThreatSignal AI — Updating deployment ==="

# Rebuild FAISS index (in case breach data changed)
echo "[1/3] Rebuilding FAISS index..."
python scripts/build_index.py

# Rebuild and push image
echo "[2/3] Building new image in ACR..."
az acr build \
  --registry "$ACR_NAME" \
  --image "$IMAGE_NAME:$IMAGE_TAG" \
  .

# Update container app to use the new image
echo "[3/3] Updating container app..."
az containerapp update \
  --name "$CONTAINER_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --image "${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}" \
  --output none

APP_URL=$(az containerapp show \
  --name "$CONTAINER_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" \
  --output tsv)

echo ""
echo "Updated! Live at: https://${APP_URL}"
echo "Health check:     curl https://${APP_URL}/health"
