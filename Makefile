BUILDKITE_TESTER_IMAGE=buildkite/plugin-tester:v2.0.0

# NOTE(jaosorior): This hasn't been released in two years...
#                  we should ask for a fix.
BUILDKITE_LINTER_IMAGE=buildkite/plugin-linter:latest

PLUGIN_REF=equinixmetal-buildkite/trivy

# Must be set before doing a release
TAG?=

.PHONY: lint
lint: | plugin-arg-docs
	docker run --rm -v "$$PWD:/plugin:ro" $(BUILDKITE_LINTER_IMAGE) --id $(PLUGIN_REF)

.PHONY: test
test:
	docker run --rm -v "$$PWD:/plugin:ro" $(BUILDKITE_TESTER_IMAGE)

.PHONY: plugin-arg-docs
plugin-arg-docs: ## Ensures that the plugin arguments are documented
	@echo "Checking that all properties are documented in the README"
	@yq '.configuration.properties | keys' plugin.yml | awk '{print $$2}' | xargs -n1 -I % grep -qE "### \`%\`" README.md || \
		{ echo "All properties must be documented in the README"; exit 1; }

.PHONY: release
release: ## Issues a release
	@test -n "$(TAG)" || (echo "The TAG variable must be set" && exit 1)
	@echo "Releasing $(TAG)"
	git checkout -b "$(TAG)"
	sed -i "s%$(PLUGIN_REF).*:%$(PLUGIN_REF)#$(TAG):%" README.md
	git add README.md
	git commit -m "Release $(TAG)"
	git tag "$(TAG)"
	git push --follow-tags origin "$(TAG)"