.DEFAULT_GOAL := help

GO_PACKAGES := $(shell go list ./... 2>/dev/null)

.PHONY: help
help: ## Show available make targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*##/ { printf "  %-16s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: check
check: fmt vet test ## Run the standard local verification suite

.PHONY: fmt
fmt: ## Format Go code
	@if [ -n "$(GO_PACKAGES)" ]; then go fmt $(GO_PACKAGES); else echo "no Go packages"; fi

.PHONY: vet
vet: ## Run go vet
	@if [ -n "$(GO_PACKAGES)" ]; then go vet $(GO_PACKAGES); else echo "no Go packages"; fi

.PHONY: test
test: ## Run Go tests
	@if [ -n "$(GO_PACKAGES)" ]; then go test $(GO_PACKAGES); else echo "no Go packages"; fi

.PHONY: tidy
tidy: ## Tidy Go modules
	go mod tidy

.PHONY: clean
clean: ## Remove local build and coverage artifacts
	rm -rf bin coverage.out coverage.html
	go clean -testcache
