# WHY: Gives the Maven repository fast and comprehensive checks matching its Java build and lint policy.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

MAVEN ?= ./mvnw
MAVEN_ARGS ?= --batch-mode --no-transfer-progress
MARKDOWNLINT ?= .scratch/tools/node_modules/.bin/markdownlint-cli2
DEPENDENCY_CHECK_VERSION ?= 13.0.0
SERVE_PORT ?= 8080

.DEFAULT_GOAL := check
.NOTPARALLEL: check check-ci

.PHONY: check check-ci tools fix fmt lint lint-check lint-java lint-markdown vuln test-core test-plugin test-all test-examples verify-docs site serve

check: lint-check test-core test-plugin ## Run formatter, static analysis, and core and plugin tests

check-ci: lint vuln test-all verify-docs ## Run all lint, vulnerability, test, and documentation checks

tools: ## Download the Markdown linter used by repository documentation checks
	command -v npm >/dev/null
	npm install --prefix .scratch/tools --no-save --package-lock=false --no-audit --no-fund markdownlint-cli2@0.23.2

fix: fmt ## Apply repository formatters

fmt: ## Format Java sources and remove unused imports
	$(MAVEN) $(MAVEN_ARGS) spotless:apply

lint: lint-java lint-markdown ## Run all Java and documentation linters

lint-check: fmt lint-java lint-markdown ## Apply safe formatting, then run blocking linters

lint-java: ## Run Checkstyle, PMD, and SpotBugs
	$(MAVEN) $(MAVEN_ARGS) compile spotless:check checkstyle:check pmd:check spotbugs:check

lint-markdown: ## Lint Markdown documentation
	command -v "$(MARKDOWNLINT)" >/dev/null
	"$(MARKDOWNLINT)" "docs/**/*.md" "*.md" "dependency-elider-maven-plugin/src/site/**/*.md"

lint-vale: ## Run prose checks on documentation
	command -v "$(VALE)" >/dev/null
	"$(VALE)" docs

vuln: ## Check dependencies against the OWASP vulnerability database
	$(MAVEN) $(MAVEN_ARGS) org.owasp:dependency-check-maven:$(DEPENDENCY_CHECK_VERSION):check

test-core: ## Run core library unit tests
	$(MAVEN) $(MAVEN_ARGS) -pl elider-core test

test-plugin: ## Run Maven plugin unit tests with required core dependencies
	$(MAVEN) $(MAVEN_ARGS) -pl dependency-elider-maven-plugin -am test

test-all: ## Run the complete reactor verification suite
	$(MAVEN) $(MAVEN_ARGS) verify

test-examples: ## Run baseline, trace-driven elision, package, and runtime checks for all examples
	JAVA_HOME="$(JAVA_HOME)" MAVEN="$(MAVEN)" MAVEN_ARGS="$(MAVEN_ARGS)" ./examples/run-elision-cycle.sh

site: ## Build the Maven plugin documentation site locally
	./scripts/generate-site-index.sh
	$(MAVEN) $(MAVEN_ARGS) -pl dependency-elider-maven-plugin -am compile site -DskipTests

serve: site ## Build the documentation site and serve it using Caddy
	command -v caddy >/dev/null 2>&1 || { echo "Error: caddy is not installed or not in PATH. Please install Caddy: https://caddyserver.com" >&2; exit 1; }
	caddy file-server --root dependency-elider-maven-plugin/target/site --listen :$(SERVE_PORT)

verify-docs: lint-markdown ## Verify Markdown documentation
