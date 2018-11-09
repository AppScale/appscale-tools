#
# Makefile is mainly used to perform a version bump on the software.
#
.PHONY: bump-major bump-minor bump-patch help all test

all: help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-10s\033[0m - %s\n", $$1, $$2} /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Testing
test: checkenv-VIRTUAL_ENV ## Run Python unit tests
	@python -m unittest discover -b -v -s test

##@ Build
build: checkenv-VIRTUAL_ENV ## Build distro for pypi upload
	@python setup.py sdist bdist_wheel

clean: ## Clean build artifiacts
	rm -rf build
	rm -rf dist
	rm -rf appscale_tools.egg-info
	
##@ Utilities
bump-major: ## Bump major version number for appscale
	util/bump_version.sh major

bump-minor: ## Bump minor version number for appscale
	util/bump_version.sh minor

bump-patch: ## Bump patch version number for appscale
	util/bump_version.sh patch

checkenv-%:
	$(if $($*), ,$(error virtualenv was not detected, exiting))
