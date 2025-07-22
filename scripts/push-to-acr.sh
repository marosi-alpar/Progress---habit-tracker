#!/bin/bash
set -e

# Variables
ACR_NAME="androidinternship"
ACR_LOGIN_SERVER="androidinternship.azurecr.io"
IMAGE_NAME="progr3ss-backend-ai"
IMAGE_TAG="latest"
DOCKERFILE_PATH="./Dockerfile"

# Build the Docker image
echo "Building Docker image..."
docker build -t $IMAGE_NAME:$IMAGE_TAG -f $DOCKERFILE_PATH .

# Tag the image for ACR
echo "Tagging image for ACR..."
docker tag $IMAGE_NAME:$IMAGE_TAG $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG

# Log in to Azure Container Registry
echo "Logging in to Azure Container Registry..."
az acr login --name $ACR_NAME

# Push the image to ACR
echo "Pushing image to ACR..."
docker push $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG

echo "Image pushed to $ACR_LOGIN_SERVER/$IMAGE_NAME:$IMAGE_TAG successfully!" 