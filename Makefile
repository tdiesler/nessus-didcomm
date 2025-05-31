
PROJECT_VERSION := $(shell mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

TARGET ?= prod
KUBE_CONTEXT_PROD := "ebsi"
IMAGE_REGISTRY_PROD := "registry.vps6c.eu.ebsi:30443/"

KUBE_CONTEXT_LOCAL := "docker-desktop"
IMAGE_REGISTRY_LOCAL := ""

IMAGE_NAME := nessusio/nessus-identity-portal
IMAGE_TAG := "latest"

# Set the IMAGE_REGISTRY based on the deployment TARGET
ifeq ($(TARGET), prod)
  KUBE_CONTEXT := $(KUBE_CONTEXT_PROD)
  IMAGE_REGISTRY := $(IMAGE_REGISTRY_PROD)
endif
ifeq ($(TARGET), local)
  KUBE_CONTEXT := $(KUBE_CONTEXT_LOCAL)
  IMAGE_REGISTRY := $(IMAGE_REGISTRY_LOCAL)
endif

clean:
	@mvn clean

package: clean
	@mvn package -DskipTests

# Build the Docker images
images: package
		@docker buildx build --platform linux/amd64 \
			--build-arg PROJECT_VERSION=$(PROJECT_VERSION) \
			-t $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG) \
			-t $(IMAGE_NAME):$(IMAGE_TAG) \
			-f ./portal/Dockerfile ./portal;
		@if [ $(TARGET) != "local" ]; then \
			echo "Pushing $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG) ..."; \
			docker push $(IMAGE_REGISTRY)$(IMAGE_NAME):$(IMAGE_TAG); \
		fi

uninstall:
	@helm --kube-context $(KUBE_CONTEXT) uninstall ebsi-portal --ignore-not-found

upgrade: images
	@helm --kube-context $(KUBE_CONTEXT) upgrade --install ebsi-portal ./helm -f ./helm/values-ebsi-portal.yaml
