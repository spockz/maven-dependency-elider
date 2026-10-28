# WHY: Gives the Maven repository fast and comprehensive checks matching its Java build and lint policy.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

MAVEN ?= ./mvnw
MAVEN_ARGS ?= --batch-mode --no-transfer-progress
MAVEN_THREADS ?= $(MAKE_JOBS)
MARKDOWNLINT ?= .scratch/tools/node_modules/.bin/markdownlint-cli2
DEPENDENCY_CHECK_VERSION ?= 13.0.0
SERVE_PORT ?= 8080
MAKE_JOBS ?= 12
# Bound test JVMs separately because reactor -T can run multiple modules at once.
TEST_FORKS ?= 4

ifeq ($(MAKELEVEL),0)
.NOTPARALLEL:
endif

.DEFAULT_GOAL := check

.PHONY: check check-parallel java-check check-ci tools fix fmt lint lint-check lint-parallel lint-java lint-markdown vuln test-core test-plugin test-all test-examples verify-docs site serve

check: ## Format, then run Java checks/tests and Markdown lint concurrently
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory -j$(MAKE_JOBS) check-parallel

check-parallel: java-check lint-markdown

java-check:
	$(MAKE) --no-print-directory lint-java
	$(MAKE) --no-print-directory test-plugin

check-ci: lint vuln test-all verify-docs ## Run all lint, vulnerability, test, and documentation checks

tools: ## Download the Markdown linter used by repository documentation checks
	command -v npm >/dev/null
	npm install --prefix .scratch/tools --no-save --package-lock=false --no-audit --no-fund markdownlint-cli2@0.23.2

fix: fmt ## Apply repository formatters

fmt: ## Format Java sources and remove unused imports
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) spotless:apply

lint: lint-java lint-markdown ## Run all Java and documentation linters

lint-check: ## Apply formatting, then run Java and Markdown linters concurrently
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory -j$(MAKE_JOBS) lint-parallel

lint-parallel: lint-java lint-markdown

lint-java: ## Run Checkstyle, PMD, and SpotBugs
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) compile spotless:check checkstyle:check pmd:check spotbugs:check

lint-markdown: ## Lint Markdown documentation
	test -x "$(MARKDOWNLINT)"
	"$(MARKDOWNLINT)" "docs/**/*.md" "*.md" "dependency-elider-maven-plugin/src/site/**/*.md"

lint-vale: ## Run prose checks on documentation
	command -v "$(VALE)" >/dev/null
	"$(VALE)" docs

vuln: ## Check dependencies against the OWASP vulnerability database
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) org.owasp:dependency-check-maven:$(DEPENDENCY_CHECK_VERSION):check

test-core: ## Run core library unit tests
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl elider-core -DforkCount=$(TEST_FORKS) -DreuseForks=true test

# Nested Maven installs write reactor targets, so the lifecycle test follows the forked unit suite.
test-plugin: test-core ## Run core and plugin tests, isolating nested lifecycle builds
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl dependency-elider-maven-plugin -am install -DskipTests
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl dependency-elider-maven-plugin -Dtest='!DependencyContextLifecycleIntegrationTest' -DforkCount=$(TEST_FORKS) -DreuseForks=true test
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl dependency-elider-maven-plugin -Dtest=DependencyContextLifecycleIntegrationTest -DforkCount=1 -DreuseForks=true test

test-all: ## Run the complete reactor verification suite
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) verify

test-examples: ## Run baseline, trace-driven elision, package, and runtime checks for all examples
	JAVA_HOME="$(JAVA_HOME)" MAVEN="$(MAVEN)" MAVEN_ARGS="$(MAVEN_ARGS) -T $(MAVEN_THREADS)" ./examples/run-elision-cycle.sh

site: ## Build the Maven plugin documentation site locally
	./scripts/generate-site-index.sh
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl dependency-elider-maven-plugin -am compile site -DskipTests

serve: site ## Build the documentation site and serve it using Caddy
	command -v caddy >/dev/null 2>&1 || { echo "Error: caddy is not installed or not in PATH. Please install Caddy: https://caddyserver.com" >&2; exit 1; }
	caddy file-server --root dependency-elider-maven-plugin/target/site --listen :$(SERVE_PORT)

verify-docs: lint-markdown ## Verify Markdown documentation
