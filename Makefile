# WHY: Gives the Maven repository fast and comprehensive checks matching its Java build and lint policy.
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

MVND ?= .scratch/toolchains/maven-mvnd-1.0.6/bin/mvnd
ifeq ($(USE_MVND),true)
MAVEN ?= $(MVND)
else
MAVEN ?= ./mvnw
endif
MAVEN_ARGS ?= --batch-mode --no-transfer-progress
MAVEN_THREADS ?= $(MAKE_JOBS)
MARKDOWNLINT ?= .scratch/tools/node_modules/.bin/markdownlint-cli2
NODE ?= node
GO ?= go
GOFMT ?= gofmt
OSV_SCANNER ?= osv-scanner
DEPENDENCY_CHECK_VERSION ?= 13.0.0
SERVE_PORT ?= 8080
PROFILE_MODULE ?= dependency-elider-maven-plugin
PROFILE_TESTS ?= MavenElisionServiceEffectiveOutputCacheTest,ElideMojoTest,ForcedUnchangedSiblingClosureTest,NoExtensionAnalyzeBanPredictionTest
PROFILE_OUTPUT ?= target/elider-test-profile.jfr
SPRING_BOOT_PROFILE_OUTPUT ?= target/elider-spring-boot-profile.jfr
JFR_BIN ?= $(if $(JAVA_HOME),$(JAVA_HOME)/bin/jfr,jfr)
MAKE_JOBS ?= 12
# Keep aggregate test concurrency bounded across reactor modules, forks, and JUnit classes.
TEST_MAVEN_THREADS ?= 2
CORE_TEST_FORKS ?= 1
CORE_TEST_JUNIT_PARALLELISM ?= 2
PLUGIN_TEST_FORKS ?= 4
PLUGIN_TEST_JUNIT_PARALLELISM ?= 4

ifeq ($(MAKELEVEL),0)
.NOTPARALLEL:
endif

.DEFAULT_GOAL := check

.PHONY: help check check-fast check-parallel check-transcripts update-transcripts java-check check-ci tools fix fmt lint lint-check lint-parallel lint-java lint-markdown vuln test-core test-plugin test-all coverage profile-tests profile-spring-boot test-examples test-reactor-example test-example-scheduler test-catalog-reproducibility test-format test-sbom-comparison scan-sbom verify-docs site serve

help: ## Show available Make targets and when to use them
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check: ## Full pre-commit/CI check: format, lint Java/Markdown, run all tests, and verify transcripts
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory -j$(MAKE_JOBS) check-parallel
	$(MAKE) --no-print-directory check-transcripts

check-fast: ## Fast inner-loop check: format, lint Java, and run core + plugin tests (skips transcripts)
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory java-check

update-transcripts: ## Re-run configured example goals and update their documentation transcripts
	$(GO) run scripts/update-transcripts.go --update

check-transcripts: test-catalog-reproducibility ## Verify configured command transcripts without rewriting documentation
	$(GO) test scripts/update-transcripts.go scripts/update-transcripts_test.go
	$(GO) run scripts/update-transcripts.go --check

test-catalog-reproducibility: ## Verify the published example catalog archive has stable bytes
	JAVA_HOME="$(JAVA_HOME)" MAVEN="$(MAVEN)" MAVEN_ARGS="$(MAVEN_ARGS)" bash ./scripts/test-catalog-reproducibility.sh

check-parallel: java-check lint-markdown test-example-scheduler test-format test-sbom-comparison

java-check:
	$(MAKE) --no-print-directory lint-java
	$(MAKE) --no-print-directory test-plugin

check-ci: lint vuln test-all verify-docs ## Run all lint, vulnerability, test, and documentation checks

tools: ## Download the Markdown linter used by repository documentation checks
	command -v npm >/dev/null
	npm install --prefix .scratch/tools --no-save --package-lock=false --no-audit --no-fund markdownlint-cli2@0.23.2

fix: fmt ## Apply repository formatters

fmt: ## Format Java and Go sources and fix supported Markdown issues
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) spotless:apply
	$(GOFMT) -w scripts
	test -x "$(MARKDOWNLINT)"
	"$(MARKDOWNLINT)" "docs/**/*.md" "*.md" "dependency-elider-maven-plugin/src/site/**/*.md" --fix

lint: fmt lint-java lint-markdown ## Apply automatic formatting, then run all Java and documentation linters

lint-check: ## Apply formatting, then run Java and Markdown linters concurrently
	$(MAKE) --no-print-directory fmt
	$(MAKE) --no-print-directory -j$(MAKE_JOBS) lint-parallel

lint-parallel: lint-java lint-markdown

lint-java: ## Run Checkstyle, PMD, and SpotBugs
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) package -DskipTests -Djacoco.skip=true spotless:check checkstyle:check pmd:check spotbugs:check

lint-markdown: ## Lint Markdown documentation
	test -x "$(MARKDOWNLINT)"
	"$(MARKDOWNLINT)" "docs/**/*.md" "*.md" "dependency-elider-maven-plugin/src/site/**/*.md"

lint-vale: ## Run prose checks on documentation
	command -v "$(VALE)" >/dev/null
	"$(VALE)" docs

vuln: ## Check dependencies against the OWASP vulnerability database
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) org.owasp:dependency-check-maven:$(DEPENDENCY_CHECK_VERSION):check

test-core: ## Run core, native-image, and lifecycle library tests and JaCoCo coverage verification
	$(MAVEN) $(MAVEN_ARGS) -T $(TEST_MAVEN_THREADS) -pl elider-core,elider-native-image,elider-maven-lifecycle -Dcore.forkCount=$(CORE_TEST_FORKS) -DreuseForks=true -Dcore.test.parallelism=$(CORE_TEST_JUNIT_PARALLELISM) verify

test-plugin: test-core ## Run core and plugin tests, isolating nested lifecycle builds
	$(MAVEN) $(MAVEN_ARGS) -T $(TEST_MAVEN_THREADS) -pl dependency-elider-maven-plugin -am install -DskipTests -Djacoco.skip=true
	$(MAVEN) $(MAVEN_ARGS) -T $(TEST_MAVEN_THREADS) -pl dependency-elider-maven-plugin -Dsurefire.forkCount=$(PLUGIN_TEST_FORKS) -Dsurefire.reuseForks=true -Dplugin.test.parallelism=$(PLUGIN_TEST_JUNIT_PARALLELISM) verify

test-all: ## Run the complete reactor verification suite
	$(MAVEN) $(MAVEN_ARGS) -T $(TEST_MAVEN_THREADS) -Dcore.forkCount=$(CORE_TEST_FORKS) -Dcore.test.parallelism=$(CORE_TEST_JUNIT_PARALLELISM) -Dsurefire.forkCount=$(PLUGIN_TEST_FORKS) -Dsurefire.reuseForks=true -Dplugin.test.parallelism=$(PLUGIN_TEST_JUNIT_PARALLELISM) verify

coverage: ## Run a clean test suite and generate JaCoCo HTML and XML reports (use when inspecting line coverage)
	$(MAVEN) $(MAVEN_ARGS) -T $(TEST_MAVEN_THREADS) -Dcore.forkCount=$(CORE_TEST_FORKS) -Dcore.test.parallelism=$(CORE_TEST_JUNIT_PARALLELISM) -Dsurefire.forkCount=$(PLUGIN_TEST_FORKS) -Dsurefire.reuseForks=true -Dplugin.test.parallelism=$(PLUGIN_TEST_JUNIT_PARALLELISM) clean verify

profile-tests: ## Profile slow tests with JFR and print hot methods/elider stacks (use to diagnose CPU bottlenecks; set PROFILE_MODULE, PROFILE_TESTS, PROFILE_OUTPUT)
	mkdir -p "$(dir $(PROFILE_OUTPUT))"
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl $(PROFILE_MODULE) -am package -DskipTests -Djacoco.skip=true
	$(MAVEN) $(MAVEN_ARGS) -pl $(PROFILE_MODULE) test -Dtest="$(PROFILE_TESTS)" -Dsurefire.forkCount=1 -DargLine="-XX:StartFlightRecording=filename=$(abspath $(PROFILE_OUTPUT)),settings=profile,dumponexit=true"
	"$(JFR_BIN)" view hot-methods "$(PROFILE_OUTPUT)" | head -n 40
	"$(JFR_BIN)" print --events jdk.ExecutionSample --stack-depth 25 "$(PROFILE_OUTPUT)" | grep -E "io\.github\.spockz\.elider\." | sed 's/^[[:space:]]*//' | sort | uniq -c | sort -nr | head -n 35

profile-spring-boot: ## Profile example-spring-boot-app elision + trimming with JFR
	mkdir -p "$(dir $(SPRING_BOOT_PROFILE_OUTPUT))"
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl dependency-elider-maven-plugin -am install -DskipTests -Djacoco.skip=true
	$(MAVEN) $(MAVEN_ARGS) -f examples/logback-vulnerability-mapping-catalog/pom.xml install -DskipTests
	trace_file="$$(mktemp --suffix=.log)"; \
	trap 'rm -f "$$trace_file"' EXIT; \
	printf 'io.github.spockz.example.springboot.ExampleApplication\norg.springframework.boot.SpringApplication\n' > "$$trace_file"; \
	MAVEN_OPTS="$${MAVEN_OPTS:-} -XX:StartFlightRecording=filename=$(abspath $(SPRING_BOOT_PROFILE_OUTPUT)),settings=profile,dumponexit=true" \
		$(MAVEN) $(MAVEN_ARGS) --offline -f examples/example-spring-boot-app/pom.xml -DskipTests=true \
		-Delide.mode=elision -Delide.trimJars=true -Dmaven.compiler.proc=none "-Delide.traceFiles=$$trace_file" \
		-Delide.trimRoots=freemarker.template.Configuration,groovy.text.markup.MarkupTemplateEngine,jakarta.validation.Validation,org.webjars.WebJarAssetLocator,org.reactivestreams.Publisher,io.micrometer.context.ContextSnapshot,reactor.core.publisher.Flux,reactor.core.publisher.Mono,reactor.util.context.Context,jakarta.servlet.jsp.jstl.core.Config,javax.annotation.Nonnull,edu.umd.cs.findbugs.annotations.SuppressFBWarnings,com.thoughtworks.xstream.XStream,com.thoughtworks.xstream.io.xml.StaxDriver \
		-Delide.trimSkipArtifacts=org.springframework.boot:spring-boot:3.3.5:jar:,org.springframework.boot:spring-boot-autoconfigure:3.3.5:jar:,org.springframework.boot:spring-boot-actuator:3.3.5:jar:,org.springframework.boot:spring-boot-actuator-autoconfigure:3.3.5:jar:,org.springframework:spring-web:6.1.14:jar:,org.springframework:spring-webmvc:6.1.14:jar:,org.springframework:spring-context:6.1.14:jar:,org.springframework:spring-context-support:6.1.14:jar:,org.springframework:spring-beans:6.1.14:jar:,org.springframework:spring-aop:6.1.14:jar:,org.springframework:spring-expression:6.1.14:jar:,org.springframework:spring-core:6.1.14:jar:,org.springframework:spring-messaging:6.1.14:jar:,org.springframework:spring-tx:6.1.14:jar:,io.projectreactor:reactor-core:3.6.11:jar:,io.micrometer:micrometer-core:1.13.6:jar:,io.micrometer:micrometer-observation:1.13.6:jar:,io.micrometer:micrometer-commons:1.13.6:jar:,io.micrometer:micrometer-jakarta9:1.13.6:jar:,org.apache.groovy:groovy-templates:4.0.23:jar:,org.springframework.kafka:spring-kafka:3.2.4:jar:,org.apache.kafka:kafka-clients:3.7.1:jar: \
		clean package
	"$(JFR_BIN)" view hot-methods "$(SPRING_BOOT_PROFILE_OUTPUT)" | awk 'NR<=40'
	"$(JFR_BIN)" view allocation-by-site "$(SPRING_BOOT_PROFILE_OUTPUT)" | awk 'NR<=35'
	"$(JFR_BIN)" print --events jdk.ExecutionSample --stack-depth 25 "$(SPRING_BOOT_PROFILE_OUTPUT)" | grep -E "io\.github\.spockz\.elider\." | sed 's/^[[:space:]]*//' | sort | uniq -c | sort -nr | awk 'NR<=35'

test-examples: ## Run baseline and trace-driven package checks for single-project and reactor examples
	JAVA_HOME="$(JAVA_HOME)" MAVEN="$(MAVEN)" MAVEN_ARGS="$(MAVEN_ARGS) -T $(MAVEN_THREADS)" ./examples/run-elision-cycle.sh

test-reactor-example: ## Verify sequential and threaded multi-module reactor builds and reports
	REACTOR_ONLY=true JAVA_HOME="$(JAVA_HOME)" MAVEN="$(MAVEN)" MAVEN_ARGS="$(MAVEN_ARGS) -T $(MAVEN_THREADS)" ./examples/run-elision-cycle.sh

test-example-scheduler: ## Verify bounded standalone example fixture worker behavior
	bash ./examples/test-fixture-scheduler.sh

test-format: ## Verify automatic formatting fixes Go and Markdown inputs
	MARKDOWNLINT="$(MARKDOWNLINT)" bash ./scripts/test-format.sh

test-sbom-comparison: ## Test package-level OSV SBOM comparison behavior with a fake scanner
	$(NODE) --test scripts/compare-sbom-inventories.test.js

scan-sbom: test-examples ## Compare baseline and post-elision SBOM findings for both CVE fixtures
	command -v "$(OSV_SCANNER)" >/dev/null 2>&1 || { echo "Error: OSV-Scanner is required for scan-sbom. Set OSV_SCANNER to its executable." >&2; exit 1; }
	OSV_SCANNER_BIN="$(OSV_SCANNER)" $(NODE) scripts/compare-sbom-inventories.js examples/example-cve-unused-app/target/baseline-sbom.cdx.json examples/example-cve-unused-app/target/dependency-elider-sbom.cdx.json --output-dir examples/example-cve-unused-app/target/sbom-comparison
	OSV_SCANNER_BIN="$(OSV_SCANNER)" $(NODE) scripts/compare-sbom-inventories.js examples/example-cve-safe-class-app/target/baseline-sbom.cdx.json examples/example-cve-safe-class-app/target/dependency-elider-sbom.cdx.json --output-dir examples/example-cve-safe-class-app/target/sbom-comparison

site: ## Build the Maven plugin documentation site locally
	./scripts/generate-site-index.sh
	$(MAVEN) $(MAVEN_ARGS) -T $(MAVEN_THREADS) -pl dependency-elider-maven-plugin -am compile site -DskipTests

serve: site ## Build the documentation site and serve it using Caddy
	command -v caddy >/dev/null 2>&1 || { echo "Error: caddy is not installed or not in PATH. Please install Caddy: https://caddyserver.com" >&2; exit 1; }
	caddy file-server --root dependency-elider-maven-plugin/target/site --listen :$(SERVE_PORT)

verify-docs: lint-markdown ## Verify Markdown documentation
