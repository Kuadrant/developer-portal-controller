##@ Kind

## Targets to help install and use kind for development https://kind.sigs.k8s.io

KIND_CLUSTER_NAME ?= devportal-controller-local

.PHONY: kind-create-cluster
kind-create-cluster: kind ## Create the "kuadrant-local" kind cluster.
	$(KIND) create cluster --name $(KIND_CLUSTER_NAME) --config utils/kind-cluster.yaml

.PHONY: kind-delete-cluster
kind-delete-cluster: kind ## Delete the "kuadrant-local" kind cluster.
	- $(KIND) delete cluster --name $(KIND_CLUSTER_NAME)

kind-load-image: ## Load image to local cluster
	$(eval TMP_DIR := $(shell mktemp -d))
	$(CONTAINER_TOOL) save -o $(TMP_DIR)/image.tar $(IMG) \
	   && KIND_EXPERIMENTAL_PROVIDER=$(CONTAINER_TOOL) $(KIND) load image-archive $(TMP_DIR)/image.tar $(IMG) --name $(KIND_CLUSTER_NAME) ; \
	   EXITVAL=$$? ; \
	   rm -rf $(TMP_DIR) ;\
	   exit $${EXITVAL}
