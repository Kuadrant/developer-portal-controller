.PHONY: local-cluster-setup
local-cluster-setup:
	@echo ""
	@echo "deleting kind cluster..."
	@$(MAKE) kind-delete-cluster
	@echo ""
	@echo "creating kind cluster..."
	@$(MAKE) kind-create-cluster
	@echo ""
	@echo "installing developer portal controller APIs..."
	@$(MAKE) install
	@echo ""
	@echo "installing Gateway API APIs..."
	@$(MAKE) gateway-api-install
	@echo ""
	@echo "installing kuadrant core APIs..."
	@$(MAKE) kuadrant-core-install
	@echo ""
	@echo "cluster ready! Kuadrant and Gateway API APIs installed."
	@echo ""

.PHONY: local-env-setup
local-env-setup:
	@$(MAKE) local-cluster-setup
	@$(MAKE) demo-install

.PHONY: local-setup
local-setup:
	@$(MAKE) local-env-setup
	@$(MAKE) local-deploy
