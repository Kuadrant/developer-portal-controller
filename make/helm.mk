##@ Helm

CHART_NAME ?= developer-portal-controller
CHART_DIRECTORY ?= charts/$(CHART_NAME)
HELM_NAMESPACE ?= developer-portal-controller-system

.PHONY: helm-build
helm-build: manifests yq ## Sync CRDs and RBAC from config/ into the helm chart and stamp its version from VERSION.
	rm -rf $(CHART_DIRECTORY)/crds
	mkdir -p $(CHART_DIRECTORY)/crds $(CHART_DIRECTORY)/rbac
	cp config/crd/bases/*.yaml $(CHART_DIRECTORY)/crds/
	cp config/rbac/role.yaml $(CHART_DIRECTORY)/rbac/role.yaml
	V="$(VERSION)" $(YQ) -i '.version = strenv(V) | .appVersion = strenv(V)' $(CHART_DIRECTORY)/Chart.yaml

.PHONY: helm-lint
helm-lint: helm ## Lint the helm chart.
	$(HELM) lint $(CHART_DIRECTORY)

.PHONY: helm-install
helm-install: helm ## Install or upgrade the helm chart in the K8s cluster specified in ~/.kube/config.
	$(HELM) upgrade --install $(CHART_NAME) $(CHART_DIRECTORY) --namespace $(HELM_NAMESPACE) --create-namespace

.PHONY: helm-uninstall
helm-uninstall: helm ## Uninstall the helm chart.
	$(HELM) uninstall $(CHART_NAME) --namespace $(HELM_NAMESPACE)

## Tool Binaries
HELM ?= $(LOCALBIN)/helm
YQ ?= $(LOCALBIN)/yq

## Tool Versions
HELM_VERSION ?= v3.15.0
YQ_VERSION ?= v4.34.2

.PHONY: helm
helm: $(HELM) ## Download helm locally if necessary.
$(HELM): $(LOCALBIN)
	$(call go-install-tool,$(HELM),helm.sh/helm/v3/cmd/helm,$(HELM_VERSION))

.PHONY: yq
yq: $(YQ) ## Download yq locally if necessary.
$(YQ): $(LOCALBIN)
	$(call go-install-tool,$(YQ),github.com/mikefarah/yq/v4,$(YQ_VERSION))
