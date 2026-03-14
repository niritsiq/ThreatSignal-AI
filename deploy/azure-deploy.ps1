# ThreatSignal AI - Azure Container Apps Deployment (PowerShell)
# Usage: .\deploy\azure-deploy.ps1

$ErrorActionPreference = "Stop"

$RESOURCE_GROUP = "threatsignal-rg"
$LOCATION = "francecentral"
$ACR_NAME = "threatsignalacr"
$CONTAINER_APP_ENV = "threatsignal-env"
$CONTAINER_APP_NAME = "threatsignal-api"
$IMAGE_NAME = "threatsignal-ai"
$IMAGE_TAG = "latest"

# Load .env file into environment variables
Get-Content .env | ForEach-Object {
    if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
        $key = $matches[1].Trim()
        $val = $matches[2].Trim()
        [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
    }
}

$SHODAN_KEY = [System.Environment]::GetEnvironmentVariable("SHODAN_API_KEY", "Process")
$OPENAI_KEY = [System.Environment]::GetEnvironmentVariable("OPENAI_API_KEY", "Process")

Write-Host "ThreatSignal AI - Azure Deployment"
Write-Host "Resource Group: $RESOURCE_GROUP"
Write-Host "Location: $LOCATION"
Write-Host "ACR: $ACR_NAME"
Write-Host ""

# 1. Resource Group
Write-Host "[1/7] Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none
Write-Host "Done."

# 2. Container Registry
Write-Host "[2/7] Creating Azure Container Registry..."
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --admin-enabled true --location $LOCATION --output none
Write-Host "Done."

# 3. Build FAISS index
Write-Host "[3/7] Building FAISS breach index..."
python scripts/build_index.py
Write-Host "Done."

# 4. Build Docker image locally and push to ACR
Write-Host "[4/7] Building Docker image locally..."
$ACR_SERVER = "${ACR_NAME}.azurecr.io"
$FULL_IMAGE = "${ACR_SERVER}/${IMAGE_NAME}:${IMAGE_TAG}"

az acr login --name $ACR_NAME
docker build -t $FULL_IMAGE .
Write-Host "Pushing image to ACR..."
docker push $FULL_IMAGE
Write-Host "Done."

# 5. Register providers
Write-Host "[5/7] Registering required Azure providers..."
az provider register -n Microsoft.App --wait
az provider register -n Microsoft.OperationalInsights --wait
Write-Host "Done."

# 6. Container Apps Environment (no Log Analytics needed)
Write-Host "[6/7] Creating Container Apps environment..."
az containerapp env create `
  --name $CONTAINER_APP_ENV `
  --resource-group $RESOURCE_GROUP `
  --location $LOCATION `
  --logs-destination none `
  --output none
Write-Host "Done."

# 7. Deploy Container App
Write-Host "[7/7] Deploying container app..."
$ACR_PASSWORD = az acr credential show --name $ACR_NAME --query "passwords[0].value" --output tsv

az containerapp create `
  --name $CONTAINER_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --environment $CONTAINER_APP_ENV `
  --image $FULL_IMAGE `
  --registry-server $ACR_SERVER `
  --registry-username $ACR_NAME `
  --registry-password $ACR_PASSWORD `
  --target-port 8000 `
  --ingress external `
  --cpu 0.25 `
  --memory 0.5Gi `
  --min-replicas 0 `
  --max-replicas 1 `
  --env-vars "SHODAN_API_KEY=$SHODAN_KEY" "OPENAI_API_KEY=$OPENAI_KEY" "LLM_MODEL=gpt-4o-mini" "EMBEDDING_MODEL=text-embedding-3-small" "BREACH_DATASET_PATH=data/breach_cases.jsonl" "FAISS_INDEX_PATH=data/breach_index.faiss" "LOG_LEVEL=INFO" `
  --output none

Write-Host "Done."

$APP_URL = az containerapp show `
  --name $CONTAINER_APP_NAME `
  --resource-group $RESOURCE_GROUP `
  --query "properties.configuration.ingress.fqdn" `
  --output tsv

Write-Host ""
Write-Host "Deployment complete!"
Write-Host "Live URL : https://$APP_URL"
Write-Host "Health   : curl https://$APP_URL/health"
