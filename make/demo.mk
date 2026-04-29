demo-install:
	@echo "installing demo resources..."
	@# Create Kuadrant CR
	@kubectl apply -f utils/demo/kuadrant.yaml
	@# Install gamestore demo resources
	@kubectl apply -f utils/demo/gamestore.yaml
	@echo ""
	@echo "patching resource statuses (simulating Istio/Kuadrant controllers)..."
	@# Patch Kuadrant status
	@kubectl patch kuadrant kuadrant -n kuadrant-system --type=merge --subresource=status --patch='{"status":{"conditions":[{"type":"Ready","status":"True","reason":"InstallationSuccessful","message":"Kuadrant is ready","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}],"observedGeneration":1}}'
	@# Patch Gateway status
	@kubectl patch gateway gamestore -n gamestore --type=merge --subresource=status --patch='{"status":{"conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"Gateway accepted","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"},{"type":"Programmed","status":"True","reason":"Programmed","message":"Gateway programmed","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}],"addresses":[{"type":"IPAddress","value":"172.31.200.0"}]}}'
	@# Patch HTTPRoute status
	@kubectl patch httproute gamestore -n gamestore --type=merge --subresource=status --patch='{"status":{"parents":[{"controllerName":"istio.io/gateway-controller","conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"Route was valid","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'","observedGeneration":1}],"parentRef":{"group":"gateway.networking.k8s.io","kind":"Gateway","name":"gamestore","namespace":"gamestore"}}]}}'
	@# Patch AuthPolicy status
	@kubectl patch authpolicy gamestore-auth -n gamestore --type=merge --subresource=status --patch='{"status":{"conditions":[{"type":"Accepted","status":"True","reason":"Accepted","message":"AuthPolicy has been accepted","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"},{"type":"Enforced","status":"True","reason":"Enforced","message":"AuthPolicy has been enforced","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}],"observedGeneration":1}}'
	@# Patch PlanPolicy status
	@kubectl patch planpolicy gamestore-plan -n gamestore --type=merge --subresource=status --patch='{"status":{"conditions":[{"type":"Available","status":"True","reason":"PlanPolicyAccepted","message":"PlanPolicy has been successfully accepted","lastTransitionTime":"'$$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"}],"observedGeneration":1}}'
	@echo ""
	@echo "demo resources installed and statuses patched!"
