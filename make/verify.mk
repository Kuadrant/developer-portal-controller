##@ Verify

## Targets to verify actions that generate/modify code have been executed and output committed

.PHONY: verify-manifests
verify-manifests: manifests ## Verify manifests update.
	git diff --exit-code ./config
	[ -z "$$(git ls-files --other --exclude-standard --directory --no-empty-directory ./config)" ]

.PHONY: verify-fmt
verify-fmt: fmt ## Verify fmt update.
	git diff --exit-code ./api ./internal

.PHONY: verify-fmt
verify-tidy: fmt ## Verify tidy update.
	git diff --exit-code -- go.mod go.sum

.PHONY: verify-generate
verify-generate: generate ## Verify generate update.
	git diff --exit-code ./api ./internal

.PHONY: verify-go-mod
verify-go-mod: ## Verify go.mod matches source code
	go mod tidy
	git diff --exit-code ./go.mod

