BUILDKITE_TESTER_IMAGE=buildkite/plugin-tester:v3.0.1

# NOTE(jaosorior): This hasn't been released in two years...
#                  we should ask for a fix.
BUILDKITE_LINTER_IMAGE=buildkite/plugin-linter:latest

.PHONY: lint
lint: | plugin-arg-docs
	docker run --rm -v "$$PWD:/plugin:ro" $(BUILDKITE_LINTER_IMAGE) --id equinixmetal-buildkite/trivy

.PHONY: test
test:
	docker run --rm -v "$$PWD:/plugin:ro" $(BUILDKITE_TESTER_IMAGE)

.PHONY: plugin-arg-docs
plugin-arg-docs: ## Ensures that the plugin arguments are documented
	@echo "Checking that all properties are documented in the README"
	@yq '.configuration.properties | keys' plugin.yml | awk '{print $$2}' | xargs -n1 -I % grep -qE "### \`%\`" README.md || \
		{ echo "All properties must be documented in the README"; exit 1; }
