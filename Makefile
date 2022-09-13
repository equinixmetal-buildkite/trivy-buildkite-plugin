.PHONY: lint
lint: | plugin-arg-docs
	docker run --rm -v "$$PWD:/plugin:ro" buildkite/plugin-linter --id equinixmetal-buildkite/trivy

.PHONY: test
test:
	docker run --rm -v "$$PWD:/plugin:ro" buildkite/plugin-tester

.PHONY: plugin-arg-docs
plugin-arg-docs: ## Ensures that the plugin arguments are documented
	@echo "Checking that all properties are documented in the README"
	@yq '.configuration.properties | keys' plugin.yml | awk '{print $$2}' | xargs -n1 -I % grep -qE "### \`%\`" README.md || \
		{ echo "All properties must be documented in the README"; exit 1; }
