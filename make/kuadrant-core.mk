##@ Kuadrant core resources

.PHONY: kuadrant-core-install
kuadrant-core-install: kustomize ## Install Kuadrant API CRDs on local cluster
	-$(KUSTOMIZE) build config/dependencies/kuadrant-core | kubectl create -f -

$(LOCALBIN)/crd/kuadrant:
	@mkdir -p $(LOCALBIN)/crd/kuadrant

$(LOCALBIN)/crd/kuadrant/extensions.kuadrant.io_planpolicies.yaml: | $(LOCALBIN)/crd/kuadrant
	@echo "Copying Kuadrant Operator CRDs: extensions.kuadrant.io_planpolicies.yaml"
	@KUADRANT_DIR=$$(go list -m -f '{{.Dir}}' github.com/kuadrant/kuadrant-operator); \
		cp $$KUADRANT_DIR/config/crd/bases/extensions.kuadrant.io_planpolicies.yaml $(LOCALBIN)/crd/kuadrant/ 2>/dev/null || true;

$(LOCALBIN)/crd/kuadrant/kuadrant.io_authpolicies.yaml: | $(LOCALBIN)/crd/kuadrant
	@echo "Copying Kuadrant Operator CRDs: kuadrant.io_authpolicies.yaml"
	@KUADRANT_DIR=$$(go list -m -f '{{.Dir}}' github.com/kuadrant/kuadrant-operator); \
		cp $$KUADRANT_DIR/config/crd/bases/kuadrant.io_authpolicies.yaml $(LOCALBIN)/crd/kuadrant/ 2>/dev/null || true;

$(LOCALBIN)/crd/kuadrant/kuadrant.io_kuadrants.yaml: | $(LOCALBIN)/crd/kuadrant
	@echo "Copying Kuadrant Operator CRDs: kuadrant.io_kuadrants.yaml"
	@KUADRANT_DIR=$$(go list -m -f '{{.Dir}}' github.com/kuadrant/kuadrant-operator); \
		cp $$KUADRANT_DIR/config/crd/bases/kuadrant.io_kuadrants.yaml $(LOCALBIN)/crd/kuadrant/ 2>/dev/null || true;

.PHONY: kuadrant-crds
kuadrant-crds: $(LOCALBIN)/crd/kuadrant/extensions.kuadrant.io_planpolicies.yaml $(LOCALBIN)/crd/kuadrant/kuadrant.io_authpolicies.yaml $(LOCALBIN)/crd/kuadrant/kuadrant.io_kuadrants.yaml  ## Copy Kuadrant Operator CRDs for testing on envtest environment
