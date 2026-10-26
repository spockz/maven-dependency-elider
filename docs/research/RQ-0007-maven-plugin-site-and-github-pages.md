<!-- WHY: Evaluates generating a user-facing Maven plugin documentation site and automated publishing via GitHub Actions and GitHub Pages without legacy Maven site-deploy baggage. -->
# RQ-0007: Maven Plugin Documentation Site and GitHub Pages Publishing

* **Status**: Partially implemented; release versioning and complete link validation remain open
* **Category**: Documentation & Publishing
* **Date**: 2026-10-26
* **Last Updated**: 2026-10-26

Abbreviations: Continuous Integration (CI), Abstract Syntax Tree (AST), Application Programming Interface (API), Pull Request (PR), Java Development Kit (JDK), Architecture Decision Record (ADR), Research Question (RQ), Content Delivery Network (CDN), OpenID Connect (OIDC).

---

## 1. Context & Research Questions

The `maven-dependency-elider` repository delivers both a core analysis/elision engine (`elider-core`) and a Maven plugin (`dependency-elider-maven-plugin`). For Maven plugin consumers, documentation accessibility and accuracy are paramount. Users need precise descriptions of plugin goals (`analyze`, `elide`), configuration properties (`elide.traceFiles`, `elide.reportFile`, `elide.excludedArtifacts`, etc.), supported runtime telemetry formats, lifecycle phase bindings, and troubleshooting diagnostics.

User guidance starts from `README.md`; the detailed plugin guide now lives at `dependency-elider-maven-plugin/src/site/markdown/usage.md`. User FAQ and contributor records remain under `docs/`. The generated Maven site combines the usage guide with Mojo parameter references.

Maven provides the `maven-site-plugin` and `maven-plugin-report-plugin` to generate static sites directly from plugin descriptors, Mojo annotations, and Javadoc. Concurrently, GitHub Actions and GitHub Pages support zero-credential artifact deployments (`actions/deploy-pages`), eliminating the need for legacy Wagon-based `site-deploy` mechanisms.

### Primary Research Questions

* **RQ-0007.1 (Resolved)**: Which documentation assets belong on the public user-facing plugin site versus remaining repository-internal for contributors?
* **RQ-0007.2 (Resolved)**: Can Maven plugin reports generate goal and parameter reference pages from Mojo metadata and Javadocs?
* **RQ-0007.3 (Resolved)**: Which site-generation architecture is used for the plugin documentation?
* **RQ-0007.4 (Resolved)**: Which publishing approach is used for the current development site?
* **RQ-0007.5 (Open)**: What versioning and URL hierarchy should be adopted for default-branch snapshots versus immutable tagged releases?
* **RQ-0007.6 (Open)**: Which CI checks should verify site links in addition to build success and required generated pages?

The resolved answers are recorded below with implementation references. Tagged-release versioning and comprehensive link validation have not been implemented.

---

## 2. Audience Segmentation & Information Architecture

A key finding is that repository documentation serves two fundamentally different personas:

1. **Plugin Consumers (End Users)**: Developers and build engineers configuring `dependency-elider-maven-plugin` in their Maven projects. They require actionable installation instructions, exact Mojo parameter tables, lifecycle phase recommendations, sensor capture flags, report schemas, and troubleshooting advice.
2. **Engine Contributors & Architects**: Maintainers developing `elider-core`, bytecode slicing algorithms, benchmarks, or framework integrations. They require internal specifications, ADRs, research investigations, test matrices, and agent workflows.

Mixing contributor-internal artifacts into the user-facing site creates noise and cognitive overload.

### 2.1 Content Segmentation Matrix

| Document / Domain | User-Facing Plugin Site | Repository-Only (`docs/` & Git) | Rationale |
| :--- | :--- | :--- | :--- |
| **Plugin Overview (`index.html`)** | Yes | Synced from `README.md` | Primary landing page explaining value, prerequisites, and quick-start. |
| **Mojo Goal Reference (`plugin-info.html`)** | Yes | No | Generated directly from Mojos (`analyze`, `elide`, `help`) with parameter types, expressions, and defaults. |
| **User Guide / Usage (`usage.html`)** | Yes | Relocated to `dependency-elider-maven-plugin/src/site/markdown/usage.md` | Comprehensive walkthrough of CLI analysis, lifecycle bindings, and skip flags. |
| **Telemetry Sensors Guide (`sensors.html`)** | Yes | No | Actionable command lines for generating CDS lists, class-load logs, JFR events, JaCoCo execs, and GraalVM reflection configs. |
| **Class Usage Report Spec (`report-schema.html`)** | Yes | No | Detailed explanation of `dependency-elider-class-usage.json`, evidence categories, and attribution rules. |
| **User FAQ** | Linked from the README to `docs/faq.md` on GitHub | Repository-only | The site README links to the maintained user FAQ; there is no separate generated `faq.html` page. |
| **Architecture Decision Records (`docs/adr/`)** | No | Yes | Contributor design history and immutable architectural boundaries. |
| **Research Questions (`docs/research/`)** | No | Yes | Exploratory investigations, empirical benchmarks, and prospective studies. |
| **Session Handovers (`docs/handovers/`)** | No | Yes | Ephemeral engineering continuity notes. |
| **Benchmark Suite (`elider-benchmarks/`)** | No | Yes | Performance budget harness and internal microbenchmarks. |
| **Agent Skills & Prompts (`.agents/`)** | No | Yes | Development toolchain and pairing protocols. |

### 2.2 Relocation of Usage Documentation & Role of README.md

To enforce clean separation of concerns:

1. **Keep the Detailed Usage Guide with the Plugin Module**:
   * `dependency-elider-maven-plugin/src/site/markdown/usage.md` is the maintained user guide.
   * Maven Site builds render it as `usage.html` alongside generated goal references (`plugin-info.html`, `analyze-mojo.html`, `elide-mojo.html`).
2. **Retain Duplication of `README.md`**:
   * The repository root `README.md` is retained as the canonical entry point for GitHub visitors browsing the source repository.
   * `scripts/generate-site-index.sh` adapts the root `README.md` into a generated `index.md` during the site build.
   * The generator rewrites the usage guide link to `usage.html` and repository-only FAQ, ADR, research, and handover links to GitHub URLs.
3. **Purification of `docs/`**:
   * The root `docs/` directory is preserved exclusively for contributor-facing and architectural documentation: Architecture Decision Records (`docs/adr/`), Research Questions (`docs/research/`), and Session Handovers (`docs/handovers/`).
   * User FAQs and contributor records remain distinguishable in `docs/`; the detailed usage guide is maintained with the plugin.

### 2.3 Implementation status

| Question | Current answer | Evidence |
| :--- | :--- | :--- |
| RQ-0007.1 | Resolved. README and usage content are user-facing; FAQ and architecture/research/handovers are repository records. | `README.md`, `dependency-elider-maven-plugin/src/site/markdown/usage.md`, `docs/faq.md`, `scripts/generate-site-index.sh` |
| RQ-0007.2 | Resolved. Maven plugin reports generate plugin and goal reference pages from plugin metadata/Javadocs. | `dependency-elider-maven-plugin/pom.xml`, `.github/workflows/pages.yml` |
| RQ-0007.3 | Resolved. Dedicated plugin module site uses Maven Site 3.21.0, Fluido skin, and Doxia 2.x. | `pom.xml`, `dependency-elider-maven-plugin/src/site/site.xml` |
| RQ-0007.4 | Resolved for the development site. GitHub Actions builds/verifies assets and deploys the site artifact to Pages; `site-deploy` is not used. | `.github/workflows/pages.yml`, `Makefile` |
| RQ-0007.5 | Open. The current workflow publishes from `main`; snapshot/release URL and version-retention policy remain undecided. | `.github/workflows/pages.yml` |
| RQ-0007.6 | Open. CI verifies site build and required pages, but does not comprehensively validate generated relative links. | `.github/workflows/pages.yml`, `scripts/generate-site-index.sh` |

---

## 3. Site Tooling Evaluation

### 3.1 Maven Site Plugin & Doxia Compatibility

Empirical testing during research revealed a critical compatibility boundary:

* **Maven 3.9 Default / `maven-site-plugin:3.12.1`**: Bundles Apache Doxia 1.11. When executing with modern reporting plugins like `maven-project-info-reports-plugin:3.9.0`, it encounters a `NoSuchMethodError: 'void org.apache.maven.doxia.sink.Sink.tableRows()'` due to binary incompatibility between Doxia 1.x and Doxia 2.x report implementations.
* **`maven-site-plugin:3.21.0` (Recommended)**: Upgrades to Apache Doxia 2.0.0 and Doxia Sitetools 2.0.0. It resolves all Doxia 2.x LinkageErrors, natively formats responsive HTML5, and supports Markdown documents (`.md`) out of the box via `doxia-module-markdown`.

### 3.2 Mojo Parameter Synchronization via `maven-plugin-report-plugin`

Standalone documentation engines (e.g. MkDocs, Docusaurus, Sphinx) require manually duplicating parameter names, default values, user property keys (`-Delide.traceFiles`), and descriptions. This inevitably suffers from drift as Mojos evolve.

In contrast, `org.apache.maven.plugins:maven-plugin-report-plugin:3.15.1` (matching `maven-plugin-tools.version: 3.15.1` configured in the project) generates:

* `plugin-info.html`: Overview table listing all goals, descriptions, and required Java/Maven versions.
* `analyze-mojo.html`: Detailed page for `dependency-elider:analyze`, documenting `@Parameter` variables, types, user property expressions, required attributes, and Mojo javadocs.
* `elide-mojo.html`: Detailed page for `dependency-elider:elide`, including default lifecycle phase binding (`INITIALIZE`) and resolution scope (`test`).
* `help-mojo.html`: Help goal usage instructions.

**Empirical Requirement**: The reporting mojo requires the plugin descriptor (`plugin.xml`) and compiled classes to be present. In a multi-module reactor, running `mvn compile site` or ensuring inter-module dependencies are compiled beforehand guarantees clean generation without missing artifact errors.

### 3.3 Site Skin & Presentation

The standard default skin (`maven-default-skin`) renders dated 1990s-era HTML framesets.
We recommend `org.apache.maven.skins:maven-fluido-skin:2.0.0-M9`:

* Clean, modern, responsive layout based on Bootstrap.
* Full support for GitHub project ribbon, top bar navigation, syntax highlighting, and responsive mobile navigation.
* Standard across prominent Apache and GitHub Maven plugins.

### 3.4 Site Scope: Root Multi-Module Aggregator vs. Dedicated Plugin Site

The repository is structured as a reactor: parent POM, `elider-core`, `dependency-elider-maven-plugin`, `elider-benchmarks`, and `examples`.

* **Option A: Multi-module staged site (`mvn site site:stage`)**: Generates an overarching parent site with submodule links. The plugin documentation is nested under `/dependency-elider-maven-plugin/`.
* **Option B: Dedicated plugin site**: Deploys `dependency-elider-maven-plugin/target/site/` directly to the website root, with dedicated pages for the core engine's telemetry architecture.
* **Evaluation**: End users seek `https://spockz.github.io/maven-dependency-elider/` to immediately view the Maven plugin usage and goal reference. Burying the plugin under sub-paths harms usability. The recommended structure configures the documentation site in `dependency-elider-maven-plugin` (or a dedicated root site descriptor that spotlights the plugin goals at the root).

---

## 4. Publishing Architecture Comparison

| Evaluation Dimension | Option 1: Repository Only | Option 2: Local / CI Only | Option 3: GitHub Actions + Pages (Recommended) | Option 4: Maven `site-deploy` |
| :--- | :--- | :--- | :--- | :--- |
| **Public Discoverability** | Low (Raw markdown in repo) | None (Unpublished build output) | High (Clean, indexable static HTTPS site) | High |
| **Mojo Doc Sync** | Poor (Manual markdown tables) | High (Generated in build) | High (Generated from Mojo annotations) | High |
| **Credential Security** | N/A | N/A | **Zero stored secrets** (Uses ephemeral OIDC `GITHUB_TOKEN`) | Requires SSH deploy keys or PATs with repo write access |
| **Git Repository Cleanliness** | Clean | Clean | **Clean** (Pages served via API artifact without committing to `gh-pages` branch) | Dirty (Commits generated HTML/CSS blobs to `gh-pages` branch) |
| **Maintenance Overhead** | Minimal | Low | Low (Standard GitHub Actions workflow) | High (Wagon transport bugs, known_hosts, SSH key rot) |

### Rejection of Maven `site-deploy` (Option 4)

Maven's traditional `site-deploy` mechanism was designed in the early 2000s for deployment via FTP, SCP, or WebDAV using Wagon providers. Applying it to GitHub Pages requires either:

* `wagon-scm` or `maven-scm-publish-plugin` pushing commits to a `gh-pages` branch.
* Dedicated SSH keys or Personal Access Tokens stored in GitHub Secrets.

This introduces repository bloat (thousands of generated HTML commits inflating `.git` size) and credential exposure risks. GitHub's modern Pages deployment API (`actions/upload-pages-artifact` and `actions/deploy-pages`) operates purely on uploaded build artifacts without git branch mutation, completely obsoleting `site-deploy`.

---

## 5. Versioning & URL Strategy

Maven plugins must clearly communicate whether documentation corresponds to a released stable version or current development snapshots:

### Versioning Model

1. **Snapshot / Default Branch Mode (`main`)**:
   * On every push to `main` modifying plugin code or documentation, CI generates and publishes to the site root or a `/snapshot/` path.
   * During early development (pre-1.0.0 / `0.1.0-SNAPSHOT`), publishing directly to the root provides immediate visibility, accompanied by an explicit banner indicating snapshot status and latest commit hash.
2. **Release Tag Mode (`v*`)**:
   * When a release tag (e.g. `v0.1.0`) is published, the workflow generates documentation for that exact tag.
   * Artifacts are deployed to a versioned path (`/0.1.0/`) and symlinked or mirrored to `/` (or `/latest/`).
   * A dropdown or version navigation banner allows users to navigate historical versions.

---

## 6. Automated CI/CD Workflow & Quality Gates

To guarantee that broken links or uncompilable descriptors never reach production, the site generation must be guarded by strict verification checks.

### Recommended Workflow Architecture (`.github/workflows/pages.yml`)

```yaml
name: Deploy Plugin Documentation Site

on:
  push:
    branches:
      - main
    paths:
      - 'dependency-elider-maven-plugin/**'
      - 'elider-core/**'
      - 'pom.xml'
      - 'dependency-elider-maven-plugin/src/site/markdown/**'
      - 'scripts/generate-site-index.sh'
      - 'README.md'
      - '.github/workflows/pages.yml'
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  build:
    name: Build & Verify Site
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v7

      - name: Set up Java 21
        uses: actions/setup-java@v6.1.0
        with:
          distribution: temurin
          java-version: '21'
          cache: maven

      - name: Build Plugin & Generate Site
        run: |
          ./mvnw --batch-mode --no-transfer-progress \
            compile \
            org.apache.maven.plugins:maven-site-plugin:3.21.0:site \
            -DskipTests \
            -pl dependency-elider-maven-plugin \
            -am

      - name: Verify Generated Site Assets
        run: |
          SITE_DIR="dependency-elider-maven-plugin/target/site"
          test -f "$SITE_DIR/index.html" || { echo "Missing index.html"; exit 1; }
          test -f "$SITE_DIR/plugin-info.html" || { echo "Missing plugin-info.html"; exit 1; }
          test -f "$SITE_DIR/analyze-mojo.html" || { echo "Missing analyze-mojo.html"; exit 1; }
          test -f "$SITE_DIR/elide-mojo.html" || { echo "Missing elide-mojo.html"; exit 1; }
          echo "All critical goal pages verified."

      - name: Validate Internal Links
        run: |
          # Verify that generated HTML files do not contain dead relative references
          python3 - << 'EOF'
          import os, re, sys
          site_dir = "dependency-elider-maven-plugin/target/site"
          broken = []
          for root, _, files in os.walk(site_dir):
              for f in files:
                  if f.endswith(".html"):
                      p = os.path.join(root, f)
                      with open(p, "r", encoding="utf-8", errors="ignore") as content:
                          links = re.findall(r'href=["\'](?!https?://|mailto:|#)([^"\']+)["\']', content.read())
                          for l in links:
                              clean_link = l.split("#")[0]
                              if clean_link:
                                  target = os.path.normpath(os.path.join(root, clean_link))
                                  if not os.path.exists(target):
                                      broken.append((p, l))
          if broken:
              print(f"Found {len(broken)} broken relative link(s):")
              for src, link in broken[:10]:
                  print(f"  In {src}: href='{link}' not found")
              sys.exit(1)
          print("Internal relative links verified successfully.")
          EOF

      - name: Upload Pages Artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: dependency-elider-maven-plugin/target/site

  deploy:
    name: Deploy to GitHub Pages
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```

---

## 7. Implementation Record

The documentation site implementation answered RQ-0007.1 through RQ-0007.4. This section records what exists rather than proposing the original plan again:

1. Parent `pom.xml` pins Maven Site 3.21.0 and related reporting versions. The plugin module configures Maven Plugin Report and Project Info reports; `src/site/site.xml` selects the Fluido skin and navigation.
2. `dependency-elider-maven-plugin/src/site/markdown/usage.md` is the detailed guide. `scripts/generate-site-index.sh` adapts README links for the generated site, including links to repository-only FAQ, contributor, research, architecture, and handover records.
3. `make site` generates the README-derived index and renders the site. `.github/workflows/pages.yml` builds it, checks required pages, and deploys the artifact through GitHub Pages Actions.
4. The remaining investigations are tagged-release URL/version retention (RQ-0007.5) and comprehensive generated-link validation (RQ-0007.6). The current workflow checks required assets but does not run a general broken-link scan.

---

## 8. Acceptance Criteria

* [x] Parent `pom.xml` pins Maven Site 3.21.0 and reporting plugin versions.
* [x] The plugin site generates goal documentation from Mojo metadata and Javadocs.
* [x] The usage guide is maintained in the plugin site source tree; README links repository-only FAQs and contributor records through the generated index.
* [x] The site uses the configured Fluido skin and Maven Site generation pipeline.
* [ ] Add comprehensive broken-link validation for generated site links (RQ-0007.6).
* [x] GitHub Actions builds required assets and deploys the Pages artifact without `site-deploy`.
* [x] Maven `site-deploy` and Wagon publishing are not used.
* [x] Root `README.md` contains a documentation badge.
* [ ] Decide tagged-release URLs and documentation retention/version navigation (RQ-0007.5).

---

## 9. Related Work & References

* Apache Maven: [Maven Site Plugin Documentation](https://maven.apache.org/plugins/maven-site-plugin/) (version 3.21.0, Doxia 2.0.0).
* Apache Maven: [Maven Plugin Report Plugin Documentation](https://maven.apache.org/plugin-tools/maven-plugin-report-plugin/) (version 3.15.1).
* Apache Maven: [Maven Fluido Skin](https://maven.apache.org/skins/maven-fluido-skin/).
* GitHub Docs: [Publishing with GitHub Pages and GitHub Actions](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
* GitHub Actions: [`actions/deploy-pages`](https://github.com/actions/deploy-pages) and [`actions/upload-pages-artifact`](https://github.com/actions/upload-pages-artifact).
