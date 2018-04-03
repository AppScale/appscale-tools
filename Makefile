#
# Makefile is mainly used to perform a version bump on the software.
#
.PHONY: bump-major bump-minor bump-patch help all

all: help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-10s\033[0m - %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bump-major: ## Bump major version number for appscale
	util/bump_version.sh major

bump-minor: ## Bump minor version number for appscale
	util/bump_version.sh minor

bump-patch: ## Bump patch version number for appscale
	util/bump_version.sh patch
