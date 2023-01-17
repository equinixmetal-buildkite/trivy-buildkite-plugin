BUILDKITE_TESTER_IMAGE=buildkite/plugin-tester:v4.0.0

# NOTE(jaosorior): This hasn't been released in two years...
#                  we should ask for a fix.
BUILDKITE_LINTER_IMAGE=buildkite/plugin-linter:latest

PLUGIN_REF=equinixmetal-buildkite/trivy

# Must be set before doing a release
TAG?=

# Enable debug logging for plugin-tester image
TEST_DEBUG?=
ifdef TEST_DEBUG
	TTY_FLAG = -t
else
	TTY_FLAG =
endif

.PHONY: lint
lint: | plugin-arg-docs
	docker run --rm -v "$$PWD:/plugin:ro" $(BUILDKITE_LINTER_IMAGE) --id $(PLUGIN_REF)

.PHONY: test
test:
	docker run --rm $(TTY_FLAG) -v "$$PWD:/plugin:ro" $(BUILDKITE_TESTER_IMAGE)

.PHONY: plugin-arg-docs
plugin-arg-docs: ## Ensures that the plugin arguments are documented
	@echo "Checking that all properties are documented in the README"
	@yq '.configuration.properties | keys' plugin.yml | awk '{print $$2}' | xargs -n1 -I % grep -qE "### \`%\`" README.md || \
		{ echo "All properties must be documented in the README"; exit 1; }

.PHONY: release
release: ## Issues a release
	@test -n "$(TAG)" || (echo "The TAG variable must be set" && exit 1)
	@echo "Releasing $(TAG)"
	git checkout -b "release-$(TAG)"
	sed -i "s%$(PLUGIN_REF).*:%$(PLUGIN_REF)#$(TAG):%" README.md
	git add README.md
	git commit -m "Release $(TAG)"
	git tag -m "Release $(TAG)" "$(TAG)"
	git push origin "release-$(TAG)"
	git push origin "$(TAG)"
