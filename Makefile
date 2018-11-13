#
# Makefile is mainly used to perform a version bump on the software.
#
.PHONY: bump-major bump-minor bump-patch help all test

AGENTS_REPO?=https://github.com/scragraham/appscale-agents
AGENTS_BRANCH?=topic-agent-init

all: help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-10s\033[0m - %s\n", $$1, $$2} /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Testing
test: checkenv-VIRTUAL_ENV ## Run Python unit tests
	@pip install flexmock
	@pip install mock
	@python -m unittest discover -b -v -s test

##@ Installation
venv: ## Create virtualenv environment
	virtualenv venv

install: checkenv-VIRTUAL_ENV ## Install via pip, ensuring a virtualenv
	pip install .

install-no-venv: ## Install via pip without ensuring a virtualenv
	pip install .

install-deps: checkenv-VIRTUAL_ENV ## Install appscale specific dependencies (appscale.agents)
	pip install -e git+$(AGENTS_REPO)@$(AGENTS_BRANCH)#egg=appscale.agents
	

##@ Build
build: checkenv-VIRTUAL_ENV ## Build distro for pypi upload
	@python setup.py sdist bdist_wheel

clean: ## Clean build artifiacts
	$(info 'Removing pyc files')
	@find . -name "*.pyc" -delete
	rm -rf build
	rm -rf dist
	rm -rf appscale_tools.egg-info

venv-clean: ## Remove Virtualenv
	rm -rf venv
	
##@ Utilities
bump-major: ## Bump major version number for appscale
	util/bump_version.sh major

bump-minor: ## Bump minor version number for appscale
	util/bump_version.sh minor

bump-patch: ## Bump patch version number for appscale
	util/bump_version.sh patch

checkenv-%:
	$(if $($*), ,$(error virtualenv was not detected, exiting))
