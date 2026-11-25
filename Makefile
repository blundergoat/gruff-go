.DEFAULT_GOAL := help

GO_PACKAGES := $(shell go list ./... 2>/dev/null)
GO_PACKAGE_DIRS := $(shell go list -f '{{.Dir}}' ./... 2>/dev/null)

.PHONY: help
help: ## Show available make targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*##/ { printf "  %-16s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: check
check: fmt-check vet test ## Run the standard local verification suite without rewriting files

.PHONY: fmt
fmt: ## Format Go code
	@if [ -n "$(GO_PACKAGES)" ]; then go fmt $(GO_PACKAGES); else echo "no Go packages"; fi

.PHONY: fmt-check
fmt-check: ## Fail when gofmt would change a package Go file; run make fmt to fix
	@dirs=$$(go list -f '{{.Dir}}' ./...) || exit 1; \
	if [ -z "$$dirs" ]; then echo "no Go packages"; exit 0; fi; \
	unformatted=$$(printf '%s\n' "$$dirs" | while IFS= read -r dir; do \
		[ -n "$$dir" ] || continue; \
		for file in "$$dir"/*.go; do \
			[ -f "$$file" ] || continue; \
			gofmt -l "$$file" || exit 1; \
		done; \
	done) || exit 1; \
	if [ -n "$$unformatted" ]; then printf 'needs gofmt (run make fmt):\n%s\n' "$$unformatted"; exit 1; fi

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
	@if [ -d bin ]; then find bin -mindepth 1 ! -name gruff-go.sh -exec rm -rf {} +; fi
	rm -f coverage.out coverage.html
	go clean -testcache
