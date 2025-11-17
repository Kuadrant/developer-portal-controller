##@ Kuadrant core resources

.PHONY: kuadrant-core-install
kuadrant-core-install: kustomize ## Install Gateway API CRDs
	-$(KUSTOMIZE) build config/dependencies/kuadrant-core | kubectl create -f -
