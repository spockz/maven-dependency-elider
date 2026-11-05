<!-- WHY: Records how advisory-source coverage, package identity, and scanner findings differ, and preserves the evidence needed to evaluate future finding projections without implying vulnerability mitigation. -->
# RQ-0020: Advisory Source Coverage, Maven Identity, and Scanner Finding Projections

## Status

Open; investigation and reporting design. The Spring example has an optional OWASP Dependency-Check profile, and OSV-Scanner was run externally for this study. Adding NVD as a Dependency Elider advisory source was explicitly deferred while investigating. NVD ingestion into Elider, the new finding-projection category, and GitHub release association remain unimplemented proposals.

The agreed reporting direction is to distinguish potential scanner findings projected to disappear, observed baseline findings expected to disappear, and findings observed to disappear in comparable scans. None of those claims alone means a vulnerability was mitigated. More detailed applicability or mitigation evidence takes precedence in the security assessment for the exact CVE and component.

## Record

- Opened: 2026-11-04
- Last updated: 2026-11-05
- Evidence snapshot: 2026-11-04; tool and source behavior below is as checked on that date.
- Related decisions: [ADR-0006](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md), [ADR-0013](../adr/0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md), [RQ-0008](RQ-0008-osv-sbom-comparison-and-vex-evidence.md), [RQ-0011](RQ-0011-persisted-report-scope-and-vulnerability-telemetry.md), [RQ-0013](RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md), [RQ-0015](RQ-0015-actionable-advisory-gap-detection-and-heuristic-elision-candidates.md), and [RQ-0019](RQ-0019-developer-actionable-advisory-workflows-and-ide-quick-fixes.md).

## Research question

How should the project describe advisory coverage and scanner findings when sources use different product identities, package mappings, version scopes, publication clocks, and database update schedules? What evidence would be necessary to estimate or observe findings associated with dependencies removed by elision, while keeping that estimate distinct from a security assessment or VEX mitigation claim?

This RQ is about data-source coverage, package identity, product-to-package association, and finding-count semantics. It does not investigate duplicate-class handling, and it does not document operational troubleshooting. It is not a proposal to make Dependency Elider a general SCA scanner.

## Terms and interpretation

- **CVE record**: a CVE Program record and its identifier, maintained through the CVE Program and its CNAs. NVD is a NIST enrichment and analysis source; NIST is not the central CVE assignment authority.
- **Advisory source**: a database or publisher that supplies a vulnerability record, affected scope, aliases, references, or related metadata. An advisory can exist without a Maven package mapping.
- **Package identity**: an ecosystem-specific identifier, such as Maven `groupId:artifactId`, plus a version or version range. Product names and CPEs are not interchangeable with Maven coordinates.
- **Inventory**: the set of components represented by a particular input, such as a resolved Maven tree, direct JAR directory, executable archive, or CycloneDX SBOM. Inventory construction is separate from advisory matching.
- **Scanner finding**: a scanner's result for a particular inventory under a particular source/database, version, configuration, and matching implementation. It is not by itself a verified exploitability result.
- **Projection**: an estimate based on coarse advisory/component associations or actual baseline scanner findings associated with components later removed. A projection is not a scan of the final artifact and is not a mitigation verdict.
- **Observed delta**: a difference between actual scanner executions over explicitly identified inventories. It remains a scanner result and does not establish vulnerable-code absence.

At least four independent conditions are needed before a record becomes a finding for a deployed component: a vulnerability record exists; the record maps to an identity the tool recognizes; the component/version is in scope under the source's rules; and the component is present in the inventory being assessed. A finding can still be a false positive or have applicability caveats. Record presence alone does not establish a match, and a match does not establish exploitability in a deployment.

## Source model and publication clocks

### CVE, NVD, OSV, and GitHub roles

The CVE Program supplies CVE identifiers and records through participating CNAs. NVD enriches CVE data with fields including CPE applicability and NVD analysis/severity metadata. These are complementary roles: a CNA's CVE publication and NVD's subsequent enrichment are separate events. NVD's documented operational changes in 2026 also make NVD enrichment completeness and timing an active measurement question, not an assumed property.

OSV is an advisory data format and aggregation project with ecosystem-native package identifiers and version ranges. Its dataset includes records from multiple upstream databases and can represent both package-specific affected ranges and Git commit ranges. Aggregation does not guarantee that every upstream CVE has a Maven mapping, that every Maven mapping is complete, or that every scanner interprets every record identically.

GitHub Security Advisories (GHSA) have their own publication and review states. An automatically imported or unreviewed GHSA record is not evidence that the upstream CNA has not disclosed the CVE. A GitHub `github_reviewed_at` value records the latest review time in the advisory database context; it is not necessarily the first time a Maven coordinate was added. `modified` likewise is not a first-mapping timestamp.

### Publication, enrichment, ingestion, and observation clocks

For a CVE that eventually gains a Maven mapping, useful event times include:

1. First publication in the CVE List (`cveMetadata.datePublished`); public disclosure can precede this.
2. First observed Maven mapping in a reviewed advisory export or source snapshot.
3. OSV ingestion and export availability; an API response and an independently generated ZIP need not share one publication watermark.
4. Successful local cache synchronization and the next invocation that consumes it.
5. Time a particular local scan ran against its chosen cache/database.

These clocks answer different questions. A record's modified timestamp, an OSV snapshot date, a GHSA's initial publication, and a local cache's file time are not substitutes for first package mapping. In this project, normal cache readers accept a default 24-hour TTL; that invocation/cache policy can add local staleness after an upstream source changes. It does not define upstream publication latency.

### Why a global OSV record can lack a Maven mapping

OSV's [August 11, 2026 explanation of direct CVEList ingestion](https://osv.dev/blog/posts/faster-cve-data/) describes a deliberate scope boundary. Its automated conversion can derive repository and Git version history when source links and resolvable tags or commits are available. CVE and NVD records do not consistently provide package-manager metadata, so ecosystem databases supply package-specific mappings separately. Direct CVE ingestion also means OSV does not always wait for NVD to attach CPE data.

The [October 2026 zstd-jni discussion](https://github.com/google/osv.dev/issues/6148) describes the same Maven failure mode observed here: CVEs existed in OSV as Git records, but package/version queries and the Maven export omitted them. An OSV contributor explained that CVE conversion attempts Git-range resolution, Maven ecosystem advisories come from GHSA, and GHSA had a review backlog. The contributor also identified a risk of conflicting automated package interpretations and later curated GHSA records. This is direct evidence of the general ingestion boundary; it is not an individual diagnosis of each Tomcat record.

An [open package-metadata discussion](https://github.com/google/osv.dev/issues/6137) considers using `packageURL`, `packageName`, and `collectionURL` from CVE records. Its [associated proposal](https://github.com/google/osv.dev/pull/6143) would add package ranges alongside Git ranges for selected CNAs, including Apache. As checked on November 4, this was proposed work, not coverage to assume in a released scanner or OSV service. The FreeMarker initial-publication example below shows why even explicit CNA package metadata and OSV's Maven coverage can differ.

## Current project boundary

The project uses the OSV Maven `all.zip` snapshot and the modified-ID reconciliation path, with CVEList v5 Git data used for CVE provenance and structured CNA context. The implementation entry point is [`UpdateCveIndexMojo`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/UpdateCveIndexMojo.java); the architecture and data contract are in [ADR-0006](../adr/0006-dual-source-vulnerability-advisory-ingestion-from-cvelist-v5-and-osv-maven.md). Default cache TTL is 24 hours. The currently indexed OSV package identity scope is Maven package identity; this is not an NVD CPE index.

The schema and typed evidence rules keep advisory matching and proof admission separate. Consult the current ADRs, including [ADR-0013](../adr/0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md), for current proof boundaries and portability requirements. Older text in RQ documents may describe superseded proof approaches; this RQ does not reinstate them.

The documented elision example uses a pinned, small advisory cache. That fixture is separate from the live baseline scans in this study and is not a complete representation of upstream coverage. A pinned cache answers “what did this tool return for this database snapshot?” It does not answer “what can all current sources find?” No NVD integration was added to Dependency Elider as part of this investigation.

The plugin reads the Maven-specific OSV snapshot at `https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip` and CVEList v5 at `https://github.com/CVEProject/cvelistV5.git`. OSV-Scanner queries OSV's hosted service for identified Maven packages and versions. These delivery mechanisms share the Maven attribution gap, even though source freshness, locally retained data, and execution settings can differ. A global Git-only record does not become an independent Maven match merely because its CVE appears as an alias elsewhere.

Distributing organization-curated mappings as a versioned Maven dependency is a separate feature investigation in [RQ-0021](RQ-0021-centrally-distributed-vulnerability-mapping-dependencies.md). Its adoption, provenance, and conflict rules must preserve the distinction here between source coverage, mapping assertions, and proof authority.

## Scanner and inventory comparison

The tools below differ along three axes: how they build an inventory, which advisory sources they consult, and how they identify packages. “Supports” here is a source/documentation description checked 2026-11-04, not a claim that a particular finding will be returned for every package or configuration.

| Tool / role | Inventory construction | Advisory source(s) | Identity and matching emphasis |
| --- | --- | --- | --- |
| OWASP Dependency-Check 13.x | Maven dependency/plugin analysis and JAR metadata; can inspect archives | NVD; optional OSS Index with credentials | Extracts evidence from Maven/JAR metadata and heuristically associates products with CPEs; CPE match drives NVD applicability |
| OSV-Scanner 2.7.0 | Maven resolution, supported lock/SBOM inputs, and archive/container analysis | OSV database, which aggregates upstream sources | Ecosystem package plus version where supported; can also match source repository and Git commit information |
| Trivy | POMs, archives, SBOMs, images, and other supported targets | Trivy's aggregated vulnerability database | Language/package identity for Java; its Java database identity hashing is package metadata machinery, not an advisory source |
| Grype with Syft | Syft-generated or supplied SBOMs; archives and images | GHSA for Maven packages; NVD/CPE matching for other package types; OS distribution feeds | Syft inventory identity feeds Grype matching; source choice depends on ecosystem and package type |
| GitHub Dependabot | Dependency graph from manifests, including Maven POMs and supported snapshots | GitHub Advisory Database, including GHSA records | Dependency graph coordinates and versions; findings depend on graph submission and supported ecosystem mapping |
| Snyk | Maven-resolved dependency tree and supported project metadata | Snyk vulnerability database | Maven coordinate/version and Snyk's own affected-version/product mapping |
| Dependency-Track | Supplied CycloneDX SBOM | Configurable NVD, GHSA, OSV, and service-provided analyzers | Component identity already encoded in SBOM, followed by configured analyzers and their source-specific matching |
| CycloneDX Maven plugin | Produces a CycloneDX inventory from a Maven project | None by virtue of inventory generation | Inventory producer, not a vulnerability scanner; downstream tools may analyze the same SBOM differently |

An SBOM can provide a shared inventory to multiple scanners, making the component inputs more comparable. It does not unify advisory source contents, package mappings, version-range interpretation, CPE heuristics, database freshness, or scanner logic. OSV is already an aggregator; adding a second aggregator is not automatically more complete. A defensible comparison records scanner version, source/database identity or timestamp where available, configuration, inventory identity, and the count unit.

Primary references: [Dependency-Check internals](https://dependency-check.github.io/DependencyCheck/general/internals.html), [Dependency-Check report](https://dependency-check.github.io/DependencyCheck/general/thereport.html), [OSV data](https://google.github.io/osv.dev/data/), [OSV query API](https://google.github.io/osv.dev/post-v1-query/), [Trivy Java coverage](https://trivy.dev/docs/latest/coverage/language/java/), [Grype ecosystem matching](https://oss.anchore.com/docs/guides/vulnerability/ecosystems/), [Dependabot dependency graph inputs](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph-data), [Snyk Maven support](https://docs.snyk.io/supported-languages/supported-languages-list/java-and-kotlin/git-repositories-with-maven-and-gradle), [Dependency-Track vulnerability analysis](https://docs.dependencytrack.org/analysis-types/known-vulnerabilities/), [CycloneDX Maven plugin](https://cyclonedx.github.io/cyclonedx-maven-plugin/), and [CycloneDX VEX capabilities](https://cyclonedx.org/capabilities/vex/).

## Dated findings

### 2026-11-04: Spring example scanner measurements

The measured Spring Boot example used Boot 3.3.5, Spring Framework 6.1.14, Tomcat 10.1.31, and Jackson 2.18.2. The findings below are counts from different inventories and tools. All are baseline measurements made before elision; this study did not measure a post-elision delta.

**OWASP Dependency-Check baseline.** The report contained 104 distinct CVE identifiers, associated with seven physical JARs, across nine report entries. The same Angus Mail archive appeared in three rows, including two additional shaded-metadata rows. Severity counts were 25 critical, 40 high, 34 medium, and 5 low. Package/product associations counted as: Tomcat 54; Spring Core 34; Spring Boot 7; Jackson Databind 4; Log4j API 3; Angus Mail 1; FreeMarker 1. These are OWASP product/package scanner associations, not 104 confirmed exploitable defects.

**OSV-Scanner 2.7.0 over runtime SBOM.** The runtime SBOM contained 63 components and returned 15 components with matches: 85 distinct CVE identifiers plus one GHSA-only advisory, or 86 advisory identifiers under that count convention. Tomcat had 36 CVEs. Jackson Core had 4; Jackson Databind had 12 CVEs plus one GHSA-only advisory.

**Executable-JAR inventory.** Scanning the baseline Spring executable JAR detected 65 package identities and returned 38 CVEs. This missed some associations from the runtime scan, including Tomcat, Boot, and FreeMarker, because fallback coordinates were wrong for several nested JARs (for example, `org.apache.tomcat-embed-core:tomcat-embed-core`). This is a substantive identity/cataloging limitation in the tested input path.

The executable JAR scan additionally returned Angus SMTP CVE-2025-7962, which was not in the runtime SBOM scan. The union therefore contains 86 distinct CVEs plus one GHSA-only advisory. A separate POM scan returned 88 CVEs, but includes test dependencies and unresolved/unversioned declarations; it is not a runtime inventory total.

Do not interpret 104 versus 85 as a reduction. They came from different tools, sources, and inventory/matching methods, and both are pre-elision baselines. Likewise, a POM scan, direct-JAR scan, executable JAR scan, and resolved runtime SBOM are different inventory definitions. Counts must name the inventory and advisory identifier unit.

The runtime inventory was generated with CycloneDX Maven Plugin 2.9.1 in CycloneDX 1.6 format and checked against Maven's resolved runtime dependency list, with tests excluded. The scanner used OSV-Scalibr 0.5.3. Both OSV scans completed with findings; an exit indicating findings was not interpreted as an execution failure. The retained [findings snapshot](data/rq-0020/2026-11-04-findings.json) records package identities, CVE/GHSA identifiers, source links, and the precise count units. Large raw reports remain optional local investigation material; the durable summary does not require access to the original workspace.

### 2026-11-04: Tomcat CPE and Maven-source divergence

For Tomcat 10.1.31, the OWASP baseline associated 54 CVEs by CPE/product evidence. The corresponding OSV Maven scan returned 36, all shared with the CPE result; 18 identifiers were NVD/CPE-only in this comparison. All 18 were found globally in OSV, but their primary CVE-derived OSV records used Git ranges without a Maven package affected entry. Thus “present in OSV” did not mean “matchable as this Maven component.”

Review of the 18 records produced two groups: nine had reviewed GHSA records with Maven mappings to other artifacts, also retrievable from OSV by GHSA ID; nine had unreviewed GHSA records with empty package lists and no corresponding GHSA record retrievable from OSV. All 18 primary CVE records were retrievable from OSV. These are source-coverage and identity distinctions, not 18 established false negatives and not 18 confirmed vulnerabilities in `tomcat-embed-core` 10.1.31. The [durable findings dataset](data/rq-0020/2026-11-04-findings.json) preserves each identifier, source record, and classification.

The reviewed package mappings were:

| CVE | Maven artifacts named by the related reviewed GHSA |
| --- | --- |
| CVE-2024-52318 | `org.apache.tomcat:tomcat-jasper`, `org.apache.tomcat:tomcat`, `org.apache.tomcat.embed:tomcat-embed-jasper` |
| CVE-2024-54677 | `org.apache.tomcat:tomcat` |
| CVE-2026-24733 | `org.apache.tomcat:tomcat-coyote` |
| CVE-2026-29145 | `org.apache.tomcat:tomcat-coyote-ffm`, `org.apache.tomcat:tomcat` |
| CVE-2026-29146 | `org.apache.tomcat:tomcat-tribes`, `org.apache.tomcat:tomcat` |
| CVE-2026-34500 | `org.apache.tomcat:tomcat-coyote-ffm` |
| CVE-2026-50229 | `org.apache.tomcat:tomcat` |
| CVE-2026-53434 | `org.apache.tomcat:tomcat-util` |
| CVE-2026-55955 | `org.apache.tomcat:tomcat-tribes`, `org.apache.tomcat:tomcat` |

The nine with unreviewed GHSA records and no package mappings were CVE-2026-59083, CVE-2026-59084, CVE-2026-65183, CVE-2026-65927, CVE-2026-66299, CVE-2026-66422, CVE-2026-68569, CVE-2026-68763, and CVE-2026-73180. “No mapping” is the observed metadata state on the snapshot date, not a prediction about future curation.

Scope examples demonstrate why product-level association needs careful interpretation. CVE-2024-52318 maps to Jasper, including `tomcat-embed-jasper`; CVE-2024-54677 concerns examples; and CVE-2026-24733 maps `org.apache.tomcat:tomcat-coyote`, not the embed-core coordinate. For CVE-2026-68763, the HTTP/2 classes changed by Apache's fix were present in the baseline physical JAR. That corroborates inclusion of the relevant component; class names alone do not prove vulnerable bytecode or deployment exploitability. CVE-2026-29146 has a GHSA version range that excludes 10.1.31 while the Apache product range includes it; preserve that as a source disagreement, not a definitive unaffected result.

### 2026-11-04: Jackson NVD and OSV divergence

For Jackson 2.18.2, OSV returned four Jackson Core CVEs and twelve Jackson Databind CVEs plus one GHSA-only advisory. The OWASP/NVD comparison returned no Core matches and four Databind matches. All 16 CVEs were present in NVD records. The four matched CVEs (CVE-2026-54512 through CVE-2026-54515) had CPE configurations covering 2.18.2. The other twelve had no NVD CPE configuration in the reviewed records; seven were `Awaiting Analysis` and five `Deferred` in the selected record set.

| Package, version 2.18.2 | OWASP/NVD CVEs | OSV Maven CVEs | Additional OSV advisory without CVE |
| --- | ---: | ---: | --- |
| `com.fasterxml.jackson.core:jackson-core` | 0 | 4 | None |
| `com.fasterxml.jackson.core:jackson-databind` | 4 | 12 | GHSA-mhm7-754m-9p8w |

The twelve NVD records without CPE configurations were:

| NVD status | CVE identifiers |
| --- | --- |
| Awaiting Analysis | CVE-2026-18401, CVE-2026-19032, CVE-2026-59888, CVE-2026-59889, CVE-2026-68494, CVE-2026-68497, CVE-2026-83557 |
| Deferred | CVE-2026-77310, CVE-2026-89407, CVE-2026-89425, CVE-2026-91776, CVE-2026-91777 |

The concrete explanation is missing machine-matchable NVD applicability data for these records, rather than absence of their CVE identifiers. The status labels alone do not establish why NVD prioritized or deferred any particular record. The earlier speculative association of CVE-2026-68494 with Databind/ObjectMapper was not supported; the recorded advisory concerns Jackson Core. Product names and familiar class names must not replace exact advisory/package evidence. The dated structured-source follow-up below clarifies the scope of this explanation: the missing data is CPE applicability, while other structured affected data can already be present in the same NVD records.

Representative NVD API checks confirmed the selected status values and absence of configurations. The dataset records a mismatch between a feed-advertised digest and the bytes recorded during the investigation; this limits what can be claimed about that downloaded feed snapshot. It does not erase the spot-check observations, and no claim is made that an archive checksum was independently verified.

The observed direction reverses by package family: the OSV Maven scan returned more Jackson identifiers than the NVD/CPE baseline, while the CPE baseline returned more Tomcat identifiers than the OSV Maven scan. These examples do not establish an overall “more complete” winner. Completeness depends on scope, identity model, source and record state.

### 2026-11-04: Git-only OSV scopes and Tomcat 10.1.31

An OSV `GIT` range describes repository commits or commit boundaries, not inherently a Maven package/version range. A repository may have release tags in its history while the advisory record still has no affected Maven package entry. Git-only scope does not mean that a record is invalid, unreleased, or unreviewed by a CNA. The [OSV schema](https://ossf.github.io/osv-schema/#separating-git-and-strict-ecosystems) recommends separate affected entries for strict package ecosystems and Git details; the latter can omit the `package` field.

| Git event | Meaning for affected history |
| --- | --- |
| `introduced` | First affected commit, included in the affected set; `0` represents an unknown start before all versions |
| `fixed` | Fixing commit, excluded along with its descendants under the applicable range rules |
| `last_affected` | Last known affected commit, included as a hard ceiling |
| `limit` | Exclusive upper bound that constrains reachable history |

Membership depends on the commit graph and all relevant branch/fix events. A fixing commit on one branch does not automatically represent all cherry-picked fixes elsewhere. A successful bounded ancestry test can support a match, while a divergent or unavailable comparison must not become a general unaffected verdict.

For CVE-2026-68763, the [Apache advisory](https://tomcat.apache.org/security-10.html) described Tomcat 10.1.0-M1 through 10.1.57 as affected, including 10.1.31. The fix entered 10.1.58, but that release candidate vote failed; the first released 10.1 version containing this fix was 10.1.59. This identifies the historical fix for this CVE, not a current upgrade recommendation covering later advisories.

The query controls were distinct:

| OSV query identity | Observed result |
| --- | --- |
| Maven `org.apache.tomcat.embed:tomcat-embed-core`, version `10.1.31` | 36 CVEs; CVE-2026-68763 absent |
| `GIT`, repository `https://github.com/apache/tomcat`, tag `10.1.31` | CVE-2024-52318 only |
| Exact release commit `b07cda9f3cc385f6f2d6c0701a050317979745dc` | No returned advisories |
| Direct record lookup for CVE-2026-68763 | Record present with Git ranges |

Both Git query controls succeeded and had no pagination token. Their empty or limited results were therefore observed matching results, not substituted network failures; they did not establish that the release was unaffected. Exact Git requests and returned identifier sets are retained in the findings snapshot.

GitHub's Releases API returned no releases for the repository in the probe. Git tags nevertheless identified commits: 10.1.0-M1 at `f2ab9ac8bc3f40ee9b2cb50b030c99df927f0429`, 10.1.31 at `b07cda9f3cc385f6f2d6c0701a050317979745dc`, and 10.1.57 at `5da21b1c24a6443bca5c10dc80a69a76042ca337`. Git ancestry comparison reported divergence: M1 to 10.1.31 was 2,882 commits ahead and 1 behind; 10.1.31 to 10.1.57 was 1,976 ahead and 1 behind. Tomcat's documented release workflow tags a version, pushes the tag, then resets the release branch to `HEAD~1`, which explains why release tags can sit on offshoots. It does not prove the cause of OSV's query omission. Do not infer affected package applicability by stripping a parent heuristic or by lexical version comparison.

The evidence supports investigating explicit upstream release-to-commit association, but not silently changing Git-range matching semantics. Original CNA product/version ranges remain the preferred applicability evidence when available.

### 2026-11-04: First observed Maven mapping timeline

The mapping-latency sample contains 34 other CVEs currently matched in the runtime SBOM and executable-JAR scans (excluding the Tomcat and Jackson comparisons, and including the Angus SMTP JAR-only case). It compares CVE `datePublished` with the first observed GitHub reviewed-advisory export commit in the examined history containing an exact Maven package coordinate. It does not establish that this was the first coordinate mapping anywhere: an earlier source, export, or unexamined record could already have contained it. For every entry, the immediate parent commit retained an unreviewed GHSA file with an empty `affected` array; the reviewed-export commit added the Maven coordinate.

In the sample, the minimum interval was 6 hours 12 minutes, maximum 71.592 days, median 27.229 days, and mean 27.692 days. Nine mappings appeared within 24 hours, eight after one day and within 30 days, and 17 after 30 days. Eleven Spring-associated CVEs published on June 9 appeared in reviewed Maven mappings on July 30, about 51.5 days later. This is a selected sample and is subject to survivorship and selection bias; it is not a general service-level target or a claim about all Maven advisories.

FreeMarker CVE-2026-84939 is a useful counterexample: the initial CVE already had Maven PURL data at its September 10 publication. The GHSA was initially published that same day, about 1 hour 24 minutes later, while its reviewed export gained the Maven coordinate on September 24, about 14 days 14 hours after CVE publication. An apparent delay in one feed may therefore be enrichment latency, not delay before any package mapping existed. The initial CVE commit and both package URLs are preserved in the findings snapshot.

The [timeline JSON](data/rq-0020/2026-11-04-maven-mapping-timelines.json) records all 34 CVEs, exact UTC timestamps, mapping commits, pre-mapping snapshots, and source links. The [CSV](data/rq-0020/2026-11-04-maven-mapping-timelines.csv) provides the same rows for inspection. Dates must be compared using the same event definition and timezone normalization. GitHub's [`github_reviewed_at` definition](https://github.com/github/advisory-database/blob/main/README.md) is the last curator review; the study did not substitute it for a coordinate-addition commit or infer an exact subsequent OSV ingestion time.

Representative transitions span the measured range:

| Component family | CVE | CVE publication date | Reviewed mapping date | Elapsed time, rounded |
| --- | --- | --- | --- | --- |
| Logback | CVE-2024-12801 | 2024-12-19 | 2024-12-19 | 6h 12m |
| FreeMarker | CVE-2026-84939 | 2026-09-10 | 2026-09-24 | 14d 14h 5m |
| Angus SMTP | CVE-2025-7962 | 2025-07-21 | 2025-08-06 | 16d 3h 24m |
| Log4j API | CVE-2026-49844 | 2026-07-10 | 2026-08-13 | 33d 21h 15m |
| Spring Core | CVE-2026-41848 | 2026-06-09 | 2026-07-30 | 51d 14h 39m |
| Micrometer | CVE-2026-40984 | 2026-06-09 | 2026-08-06 | 58d 15h 24m |
| Spring Boot Autoconfigure | CVE-2026-41001 | 2026-06-11 | 2026-08-21 | 71d 14h 12m |

### 2026-11-04: Structured affected-source data and observed population

Several sources can carry more precise source locations than product names, package coordinates, or Git boundaries. Three separate questions matter: does the format support source details, does a particular record populate them, and are those details sufficient to attribute the complete relevant code in the actual installed artifact? The first two do not establish the third.

| Source | Structured source information | Evidence checked and limits |
| --- | --- | --- |
| CVE List / CNA records | An affected entry can contain `repo`, `modules`, `programFiles`, and `programRoutines[].name`, alongside package identity and affected versions | The [CVE schema](https://cveproject.github.io/cve-schema/schema/docs/) defines source files and routines explicitly. Fields are optional; `modules` can identify a feature or API rather than a source file. Names need not be fully qualified or include method descriptors. |
| NVD API | `cve.affected[].affectedData[]` can retain the CVE contributor's package, repository, file, routine, and version declarations | [NIST's June 17, 2026 deployment notice](https://www.nist.gov/itl/nvd) and [affected-data schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_affected_1.0.json) document this addition. It is separate from `cve.configurations` CPE analysis; copied CNA declarations are not independent NVD verification. |
| GitHub Security Advisories | `vulnerabilities[].vulnerable_functions`, plus affected package and version information | The [global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories) supports the field. Two actual Maven advisory responses checked below returned empty function lists. The generic documentation example does not establish Java coverage. |
| OSV core and Git-derived records | Repository and Git ranges; ecosystem-specific extensions can add symbols | The [OSV schema](https://ossf.github.io/osv-schema/) has no universal affected-Java-class or affected-method field. A fixing commit is a boundary/reference, not a complete enumeration of vulnerable code. |
| Go Vulnerability Database, distributed as OSV | `affected[].ecosystem_specific.imports[]` contains package `path`, affected `symbols`, and optional OS/architecture restrictions | [Go's database contract](https://go.dev/doc/security/vuln/database) documents the fields and review states. [GO-2024-2609](https://vuln.go.dev/ID/GO-2024-2609.json) names `net/mail` routines, including `Address.String` and `ParseAddress`. These are Go-specific mappings. |
| RustSec's OSV export | The checked record has `affected[].ecosystem_specific.affects.functions` | [RUSTSEC-2026-0334](https://github.com/rustsec/advisory-db/blob/osv/crates/RUSTSEC-2026-0334.json) lists four `bip322` verification functions. Its adjacent `affected_functions` value is null: the populated field path matters. This does not establish equivalent Maven coverage. |

For the commercial sources previously discussed, the bounded public-primary-documentation check did not establish a stable, publicly documented Java source/method mapping contract for Snyk or Sonatype OSS Index. That is an unestablished capability in this investigation, not a finding that those providers lack such data. Scanner-specific reachability, symbol extraction, or patch analysis must also be distinguished from structured affected-symbol declarations supplied by an advisory publisher.

The strongest concrete Java example checked was [CVE-2026-18401](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/18xxx/CVE-2026-18401.json). Its Jackson Core affected entry supplies:

- Maven package `com.fasterxml.jackson.core:jackson-core` and Maven Central collection URL.
- Repository `https://github.com/FasterXML/jackson-core`.
- Source path `src/main/java/com/fasterxml/jackson/core/json/async/NonBlockingUtf8JsonParserBase.java`.
- Routines `NonBlockingUtf8JsonParserBase._finishNumberIntegralPart` and `NonBlockingUtf8JsonParserBase._valueComplete`.
- Maven affected/unaffected ranges, including an affected range containing the example's 2.18.2. A separate entry describes the `tools.jackson.core` package and source namespace; the entries must not be merged across major-version namespaces.

A successful current [NVD API lookup for that CVE](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-18401) returned those declarations while the record remained `Awaiting Analysis` with no `configurations` field. This clarifies the earlier sentence “missing machine-matchable NVD applicability data”: it was too broad if read as describing every NVD field. **Missing CPE applicability does not mean missing Maven/version/source metadata.** The missing configurations are consistent with the earlier CPE-based matching gap; the current lookup does not independently establish the historical scanner inputs or the cause of that result. Another consumer could potentially use the structured CNA data already carried by NVD. NIST's later August update changed the history feed's treatment of affected data; its notice says the CVE detail endpoint still returns the latest affected JSON.

The existing selected Jackson NVD records contain source-file declarations for five of 16 CVEs and routine declarations for nine; nine have at least one of those fields, all without CPE configurations. These are observations from the retained record set, whose previously recorded feed digest discrepancy remains a limitation. The current independent API lookup confirms the concrete CVE-2026-18401 example; it does not independently revalidate all 16 records or make the selected sample a coverage census.

For the same 34 other CVEs used in the Maven mapping-latency study, the retained current CVE records contain `programFiles` in two records and `programRoutines` in none; six name `modules`. The two file-bearing records, [CVE-2026-10532](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/10xxx/CVE-2026-10532.json) and [CVE-2026-9828](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/9xxx/CVE-2026-9828.json), name only `HardenedObjectInputStream.java`, with package name `logback-core` and the Logback repository. A basename and a short package name are useful review leads but do not uniquely identify a Maven artifact, source revision, or binary class. These counts concern current records, not the fields present at initial CVE publication, and this selected set cannot estimate ecosystem-wide coverage.

The successful live GitHub API responses for [GHSA-jhq6-gfmj-v8fx](https://api.github.com/advisories/GHSA-jhq6-gfmj-v8fx) (Logback) and [GHSA-27j2-h3m2-8237](https://api.github.com/advisories/GHSA-27j2-h3m2-8237) (FreeMarker) contain exact Maven coordinates and version ranges but `vulnerable_functions: []`. This establishes the content of those two responses, not that every Maven GHSA lacks function data or that an empty list means no vulnerable functions.

The project already retains CNA `programFiles` and `programRoutines` in [`OsvSnapshotIndexer`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/OsvSnapshotIndexer.java). The next research opportunity is to measure and improve the use of populated claims within the existing scope and proof boundaries, rather than treat NVD copies of those claims as a new independent authority. A source path or routine name still needs exact affected-entry/version binding and attribution to the installed binary; a declared list must not silently become an exhaustive affected-class set. The current ADRs govern any proof admission. A patch diff, cached declaration, or repository release association alone cannot produce a VEX conclusion.

The [structured-source evidence snapshot](data/rq-0020/2026-11-04-structured-source-evidence.json) preserves selected payload fields, count scope, source URLs, raw-input digests, and the distinction between retained-feed observations and current successful API probes.

### 2026-11-04: Whether additional sources justify index integration

The underlying product question is whether another source adds usable evidence to the index. Schema support alone is insufficient. The research direction is to evaluate additional sources selectively and keep any account-dependent source optional. Snyk is now a concrete candidate for package-mapping enrichment; reusable Java class/method enrichment remains unestablished.

A public [Snyk advisory for CVE-2026-68763](https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHETOMCATEMBED-20304748), identified as `SNYK-JAVA-ORGAPACHETOMCATEMBED-20304748`, explicitly associates the CVE with `org.apache.tomcat.embed:tomcat-embed-core` and an affected interval containing 10.1.31. The earlier OSV Maven query omitted that CVE for the same package/version while the global Git record existed. This is one observed usable package association outside that OSV result, not an additional globally unknown CVE, a complete Snyk scan, or evidence that Snyk covers all 18 Tomcat gaps. The page also distinguishes the failed 10.1.58 candidate from a released fixed version; its headline range and prose exception need reconciliation before general range ingestion.

The checked [Snyk Jackson advisory](https://security.snyk.io/vuln/SNYK-JAVA-TOOLSJACKSONCORE-15365915) includes a code demonstration and technical explanation. That can aid investigation, but prose or demonstration code does not establish an exported, exhaustive affected-class/method mapping. In particular, that record describes `tools.jackson.core:jackson-core` 3.x and cannot be applied directly to the example's different 2.x Maven coordinate.

Snyk's [package-issues API documentation](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/issues-list-issues-for-a-package) confirms authenticated package/version queries using Maven PURLs, aliases, affected-version representations, fixes, and references. The documented package query returns issues in the named package, not its dependency tree; a comparison must submit every resolved runtime package. The [API overview](https://docs.snyk.io/developer-tools/snyk-api/snyk-api) says most APIs require Enterprise access. The documentation check did not establish a generally accessible complete bulk feed, reusable Java method mappings, or permission to retain and redistribute provider data. Those remain separate access and data-use questions, not findings that the capabilities or rights are absent. No authenticated Snyk API request or account-specific entitlement check was performed.

Evaluate a source against the following distinct benefits:

| Incremental benefit | Measurement needed before adoption |
| --- | --- |
| More applicable package mappings | Additional supported CVE/component/version associations after alias deduplication, with false/ambiguous associations retained separately |
| Earlier usable mappings | First observed package-mapping availability under comparable observation clocks, rather than a provider's disclosure date alone |
| More precise code locations | Populated, attributable file/class/method claims absent from current sources; distinguish machine-readable fields, prose extraction, and application-specific reachability |
| Sustainable consumption | Suitable API/export access, caching and distribution terms, rate/cost limits, update/deletion semantics, and reproducible offline use |

The next bounded experiment should reuse the resolved Spring runtime inventory and the saved Tomcat gap set, recording the provider and API version, query time, response completeness, exact package versions, source record identifiers, and any failures. Compare additional CVE/component pairs, independently useful mappings for existing CVEs, code-location detail, and conflicting scopes. Do not compare unmatched inventory totals or count aliases as new vulnerabilities. Current public-page observations justify this experiment but do not substitute for authenticated API payloads or a complete measured result.

If the incremental value and consumption conditions hold, an optional enrichment path would be justified. Keep provider records and their applicability assertions separate, with source identity, version ranges, timestamps and provenance. Do not silently union conflicting ranges, treat repeated copies of one upstream declaration as independent corroboration, or promote a provider's severity, confidence or reachability label into proof authority. ADR-0006 currently selects OSV for Maven package scope; admitting another package authority into production assessment would require an explicit architectural decision and tests of those semantics. This research does not change that authority or implement a connector.

The recommendation is therefore to benchmark Snyk for optional enrichment, with one concrete package-coverage benefit already observed, while retaining the current default sources during the investigation. Making any new source mandatory or implementing a general provider framework is not justified by this evidence. The [additional-source evaluation snapshot](data/rq-0020/2026-11-04-additional-source-evaluation.json) retains the exact package/advisory identities, displayed interval and exception, public-documentation checks, and unverified API/access conditions.

### 2026-11-04: Current use of CVE List v5 for vulnerable-code identification

Code inspection at revision `9ccf50eaa857c5cbcfa993b7e910f33765eb827f` confirms that CVE List v5 is already a configured download and a source of code-location claims. This is an implementation observation, not a fresh scan, a successful-download measurement, or a claim that every populated upstream field resolves automatically.

The updater defaults to `https://github.com/CVEProject/cvelistV5.git`. On an online advisory-cache refresh, the cache manager attempts to create a shallow Git checkout or pull an existing checkout in the cache's `cvelistV5` directory. The existing checkout supports offline reads. Git synchronization is currently best-effort and does not check the process exit code, so configuration or an attempted refresh alone does not establish a successful fresh checkout. See [`UpdateCveIndexMojo`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/UpdateCveIndexMojo.java) and [`VulnerabilityCacheManager`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityCacheManager.java).

[`OsvSnapshotIndexer`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/OsvSnapshotIndexer.java) starts from OSV records and their Maven affected scopes, locates the associated CVE record, and reads `containers.cna.affected`. It retains affected-entry identity, package/version claims, `programFiles`, and `programRoutines`, and attaches structured evidence only when the CVE metadata and machine-readable Maven identity match authorize that association. It also extracts possible class names from descriptions and Java paths present in reference URLs as heuristic review evidence; this path does not fetch and analyze arbitrary fix-commit diffs.

There is an active structured attribution/omission path beyond merely storing those fields. [`MavenStructuredProofAssessment`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenStructuredProofAssessment.java) dispatches unambiguous candidates through [`MavenSourceCorrespondenceAssessment`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenSourceCorrespondenceAssessment.java). Core revalidates the current index and CVE entry, requires matching OSV and CNA applicability, attributes claims against the original JAR, and verifies that the selected classes are absent from the final artifact. [`StructuredClaimClassResolver`](../../elider-core/src/main/java/io/github/spockz/elider/model/StructuredClaimClassResolver.java) uses source-file metadata and package paths for file claims and attempts unique method-owner matching for routine claims. [`StructuredOmittedCodeProof`](../../elider-core/src/main/java/io/github/spockz/elider/model/StructuredOmittedCodeProof.java) keeps the result limited to the verified declared classes; it does not validate the CNA declaration's correctness or completeness. This describes the current bytecode-based implementation and does not reinstate the superseded source-compilation design.

Two gaps materially qualify “we already use CVE List to identify vulnerable code”:

1. **CVE List is an enrichment source, not an independent Maven discovery index.** A record in the downloaded checkout does not create its own Maven finding when no corresponding OSV Maven scope exists. The Tomcat package-mapping gap therefore persists despite downloading the CVE repository.
2. **Routine retention is broader than routine resolution.** `readRoutineNames` retains the declared string unchanged. [`JarSourceFileIndex`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/JarSourceFileIndex.java) collects bare JVM method names, while the resolver tests exact string membership. Qualified claims such as `NonBlockingUtf8JsonParserBase._valueComplete` or `com.fasterxml.jackson.databind.ext.NioPathDeserializer.deserialize` cannot match those bare names through this path. The resulting failure abstains from automatic structured proof; parsing the claim does not establish that its code was successfully identified. This is a code-inspection finding, with no corrective implementation or regression test added during the investigation.

Additional-source evaluation should therefore measure both genuinely added upstream evidence and gaps in consuming data already downloaded. More providers may improve package associations, while fuller use of current CNA claims is a separate implementation question. Neither improvement can be assumed from the number of CVE records in the local checkout.

### 2026-11-04: OSV's source set and indirect Snyk references

Snyk is absent from OSV's checked [published data-source list](https://google.github.io/osv.dev/data/) and [importer configuration](https://github.com/google/osv.dev/blob/master/source.yaml). The complete retrieved configuration contained no case-insensitive `snyk` occurrence; it did contain the `ghsa` source importing GitHub's reviewed advisory directory. These public sources support the conclusion that OSV does not directly ingest the Snyk database as a configured feed. They are not an independent inspection of the running service's private configuration, and they do not establish a reason for Snyk's absence.

There is nevertheless overlap through other sources. [GHSA-m7j4-fhg6-xf5v](https://osv.dev/vulnerability/GHSA-m7j4-fhg6-xf5v), alias CVE-2020-28458, names GitHub's advisory database as its import source and includes four Snyk URLs in its references. Its actual affected package is npm `datatables.net`, even though two reference URLs identify Snyk Java advisories. A Snyk link in an OSV record therefore does not establish direct Snyk ingestion, complete Snyk data retention, or a Maven affected entry for that record.

The distinction for the additional-source investigation is **partial overlap versus direct database coverage**. Some information also published by Snyk can already be available through OSV's other sources; this does not make a Snyk integration automatically redundant. Conversely, the absence of a direct feed does not quantify how much new useful data Snyk would add. That still requires comparing exact package/version associations and code-location claims after alias deduplication. The earlier Tomcat package-association comparison remains a dated observation; this source-list check did not rerun the live Tomcat Maven query.

The [OSV/Snyk source-check snapshot](data/rq-0020/2026-11-04-osv-snyk-source-check.json) preserves the checked URLs, configuration observation, exact indirect example, Snyk references, and limits of the conclusion. No provider integration was implemented.

### 2026-11-04: Source-independent findings requirement and implementation plan

The user requested that OSV, CVE List v5, and manual vulnerability mappings all ingest independently into a common finding set, with source retained for reporting rather than assessment policy. This replaces the proposed future direction in which OSV remains the mandatory package authority and other sources merely enrich its owners. The existing implementation and historical observations above remain unchanged; the requested replacement has not been implemented.

The [source-independent findings plan](../handovers/2026-11-04-source-independent-vulnerability-findings-plan.md) defines the common data boundary, independent ingestion/cache work, shared applicability and code attribution, removal of implicit source precedence, retained physical verification constraints, report/schema integration, and acceptance tests that compare equivalent claims across all three inputs. The follow-up instruction explicitly requires planning before implementation. Common confidence/review-only semantics and alias ambiguity must be settled with the architectural contract; source identity cannot be hidden in a different field and continue to determine proof authority.

The user clarified the merge contract after an initial proposal to leave differing source claims unresolved: complementary code information should enrich a common finding; code paths must be normalized before deduplication and treated as sets; severity is irrelevant to this tool; and differing affected-version coverage should be widened to include both. For disjoint ranges, the user explicitly selected set union that preserves the gap. The revised plan incorporates these requirements instead of the earlier conflict default: different code sets and supported version ranges are merged, not treated as conflicts. It retains version-specific attribution so widening package coverage does not invent code mappings for versions lacking such data. No implementation was added.

The user then confirmed an explicit exception to equal merge precedence: manual mappings have higher priority while receiving the same handling. For the same CVE, artifact and applicable version, explicitly supplied manual fields override automatic fields; missing fields are enriched. The plan now keeps this priority at the common merge boundary and removes only the separate source-specific assessment/proof route, not manual correction priority. Code mapping overrides cover class/file/routine representations together so automatic paths cannot reintroduce a superseded mapping. Priority does not bypass validation or physical verification. The earlier proposal to remove manual precedence is superseded by this requirement.

### 2026-11-05: Accepted common model and independent ingestion implementation

The user approved the full plan for implementation. [ADR-0014](../adr/0014-source-independent-vulnerability-findings.md) now records the common semantic model, gap-preserving version union, scoped manual priority, and source-independent physical verification. This supersedes the proposed status in the preceding dated snapshot; it does not change the historical scanner measurements.

The first implemented slice is the [generic merge model](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java). Its [behavioral tests](../../elider-core/src/test/java/io/github/spockz/elider/model/GenericFindingMergeTest.java) exercise automatic enrichment, manual whole-code-group replacement, version-scoped code and review intent, and provenance invariance. Version status is explicit: supported affected coverage can establish applicability, unsupported coverage remains unresolved, and code from a contribution applies only within that contribution's supported affected scope. These model tests do not establish production Maven integration.

Independent [CVE ingestion](../../elider-core/src/main/java/io/github/spockz/elider/scanner/CveVulnerabilityFindingAdapter.java) now has focused fixtures for Maven identities in CNA and ADP entries, optional product names, version changes/default status, unsupported range types and wildcards, PURL identity/version constraints, and record lifecycle/identity validation. [OSV ingestion tests](../../elider-core/src/test/java/io/github/spockz/elider/scanner/OsvVulnerabilityFindingAdapterTest.java) preserve advisory-only identities and disjoint Maven coverage. These fixtures demonstrate the intended adapter boundary; they are not new live coverage counts or evidence that previously unmapped Tomcat records have acquired Maven coordinates.

Production cache, Maven assessment and report integration remain in progress at this checkpoint. Independent ingestion still requires machine-readable component/version evidence: a Git-only record without a supported Maven identity does not become a Maven finding by product-name similarity. Additional providers, Git release association, scanner finding projections and central mapping dependencies remain open research topics.

## Finding projection and assessment semantics

Several measurement designs are possible. They have different costs and answer different questions.

| Method | What it measures | Strength | Main limitation |
| --- | --- | --- | --- |
| Replicate each scanner's attribution logic | Recompute baseline matches against the final inventory | Could estimate source-specific candidate disappearance without a second scan | Expensive, fragile, and risks duplicating scanner logic; not a trustworthy scanner result |
| Same scanner and database, two inventories | Run scanner on original and final actual inventories | Produces an observed scanner-specific delta | Requires comparable scanner/source/database state and two executions; findings can remain on retained packages |
| One baseline scan plus final component absence | Associate each baseline finding with its component; count if that exact component is absent from final SBOM | Lower cost; makes the inference rule explicit | Expected inventory disappearance, not a final scan; same-GAV trimmed artifacts can remain flagged |
| Broad NVD/CPE candidates plus removed component | Count candidate associations with components absent from the final inventory | May explore product coverage outside Maven-native mappings | Heuristic product association can be noisy; candidate finding projection only |
| Existing class/CVE evidence and physical absence | Assess mapped vulnerable symbols against final bytes under existing proof gates | Can support a separate security assessment when all current requirements pass | Requires specific verified evidence; cannot be inferred from package finding disappearance |

If implemented in the future, a report should use explicit labels such as **potential projected findings**, **baseline findings associated with removed components**, or **observed two-scan finding delta**. Avoid a generic “CVEs mitigated” count. A projected value and a vulnerability assessment are two facts; a sufficiently strong existing security assessment may take precedence over a scanner's package-level alert, but the scanner may still report a finding because the package identity and version remain.

The preferred umbrella term from the discussion is **projected scanner finding reduction**. Its wording changes with evidence:

| Evidence available | Suitable claim |
| --- | --- |
| NVD/CPE association and whole-component removal | Potential finding projected to disappear |
| Finding observed in an actual baseline scan and component removed | Existing finding expected to disappear |
| Comparable actual before/after scans | Finding observed to disappear |

For example, “12 potential scanner findings projected to disappear following component removal, based on NVD CPE/version associations” describes an estimate. Without a baseline scan, do not say that twelve previously observed findings were removed. Without comparable final scanning, do not imply that a specific scanner has already stopped reporting them. Explicit detailed evidence may establish a stronger security assessment, but it does not retroactively change an observed scanner result.

Count dimensions must remain explicit:

- Count distinct CVE identifiers separately from finding instances and CVE/component pairs.
- Deduplicate CVE/GHSA aliases within the stated context so one underlying CVE is not double-counted merely because it has aliases. Preserve record ownership and provenance; deduplication is not a claim that records have identical affected scope.
- If several packages or versions are associated with one CVE, report the pair count and distinct-CVE count separately.
- A component removed from the final inventory can support an expected finding-disappearance projection for that component. If another component, shaded implementation, or different package remains, do not infer that the vulnerability disappeared globally.
- If metadata, identity, source records, or required scan results are missing, report unknown/unresolved. Do not convert missing data, network failure, or an unmatchable finding into zero.
- A retained GAV whose classes have been trimmed can still trigger a package scanner. Package scans do not prove class-level absence or presence.

The discussion accepted these distinctions as research/reporting concepts. This record documents that direction and does not implement a new report category, release parameter, NVD integration, or VEX claim.

## Proposal under investigation: opt-in Git release association

One possible future aid is an opt-in setting, illustrated as `elide.resolveGitAdvisoryReleases=true`. This is an unimplemented proposal and defaults off in the proposal. It must not be described as existing project behavior.

The proposal would associate an upstream Git advisory's affected/fixed commit ranges with installed product releases by resolving actual repository tags to commits and evaluating ancestry/range membership. A GitHub Release object is not required for a version tag to exist. Annotated tags must be peeled to their target commit. Git ancestry, source tag metadata, and explicit release boundaries matter; commit date, SHA lexical order, and Maven version string comparison are not substitutes.

The reportable result would be an **upstream release associated with an advisory**, with the original advisory, repository, tag, resolved commit, range events, comparison result, and observation date. It would not silently add an authoritative Maven package mapping to an OSV record. A later explicit package mapping or more detailed assessment can supersede the inferred association for the corresponding component while its historical provenance remains available.

Open constraints include offshoot tags, branch points, cherry-picks, shallow or incomplete histories, tag naming, repository identity, multiple installed versions, and failure/unknown outcomes. If release metadata is absent or ancestry is ambiguous, the result must remain unknown. A positive upstream release association is not proof that a Maven artifact was built from that commit, that a Maven component is affected, or that the deployment is exploitable. CNA package/version ranges should take precedence when available, with the source and rationale preserved independently.

No implementation decision is made here about cache format or repository retrieval. A bounded experiment should prefer the installed version's relevant tags, reuse repository/commit results across advisories, and retain explicit unresolved outcomes for API errors or rate limits. Acceptance criteria and any required architecture decisions remain follow-up work; this discussion does not introduce an additional approval procedure.

### 2026-11-04: Shared observations for watched repositories

The follow-up direction is to centralize reusable repository observations for an explicit set of **watched repositories**, rather than repeatedly discover tags and compare the same commits for every CVE or consuming project. The shared unit should be the repository and an identified observation snapshot. Advisory-specific range evaluation consumes that snapshot; application-specific Maven applicability remains a separate step. This is a research proposal, with no watcher, service, flag, or source integration implemented.

A small shared workstation/CI cache is the simplest experiment. An organization could later publish immutable snapshots for multiple projects, using existing artifact distribution if suitable. Centralizing the observations does not require choosing a hosting provider or building a new HTTP service. The proposed [RQ-0021](RQ-0021-centrally-distributed-vulnerability-mapping-dependencies.md) Maven distribution mechanism might carry such data, but release-index observations and adopted vulnerability-mapping assertions need separate data contracts and authority rules.

The index should keep distinct relations with their own sources and observation times:

| Relation or observation | What it establishes | What it leaves unresolved |
| --- | --- | --- |
| Repository identity, tag ref/object, and peeled target commit | Which source commit a particular tag resolved to when observed | Whether the tag was a successful published release, or which Maven artifacts it produced |
| Relevant parent/ancestry facts or comparisons keyed by immutable commit IDs | The observed Git relationship needed for an advisory range test | Unfetched history, other branches, and whether a cherry-pick is semantically the same fix |
| Project version-to-tag convention and upstream release statement | A sourced association between an upstream version and source tag/commit | Whether every module uses that version or publishes the same artifacts |
| GitHub Release object, if present | Metadata that the hosting service exposes for that release object | Completeness of releases, tag identity by itself, or publication to Maven Central |
| Maven artifact/source provenance | A separately supported association between a GAV/type/classifier and source revision | Complete affected-code attribution or deployment exploitability |
| Advisory source/version declaration | The publisher's affected or fixed scope for that record | Agreement with every other source or a complete method/class enumeration |

A bounded refresh would resolve the watched repository's relevant refs once, peel annotated tags, retain the required graph facts or comparison results, and record retrieval coverage and errors. Reuse immutable commit relationships across CVEs and projects. Start with requested versions and affected/fix boundaries; do not require complete Git histories or eagerly compute every tag pair. Expand history only when an unresolved query needs it. A partial graph can support established positive ancestry facts, while a negative conclusion needs sufficient history/comparison coverage; an API failure, shallow-history gap, or unresolved relationship remains unknown.

Raw observations and interpretations should stay separate. Preserve a changed tag's previous and new observed targets rather than silently rewriting historical analyses. Keep failed release candidates, prereleases, withdrawn releases, and branch-specific fixes visible when the source supplies them. Observation time and snapshot identity describe freshness; commit timestamps, tag names, and lexical SHA/version ordering do not establish Git-range membership. Snapshot retention and freshness policy remain open design questions.

Tomcat provides two concrete acceptance cases for this separation. Its Releases API returned no objects even though version tags existed. Its documented release procedure creates offshoot tag commits, so a naive ancestry comparison can diverge; any interpretation using the release procedure must be an explicit sourced project convention, never a universal rule that replaces a tag commit with its parent. Likewise, the failed 10.1.58 release vote means that finding a tag containing a fix does not establish that an actual released artifact contained the fix. Repository discovery can be shared, but those relationships cannot be collapsed into a single “version is affected” Boolean.

Reports should retain the repository observation snapshot, advisory source/version, tag and immutable commit IDs, range/comparison inputs, provenance of any release or Maven association, unresolved conditions, and observation date. Saved-report rendering should use the saved result without network access. Assess explicit upstream Maven/version claims and component-specific evidence in context, generally giving more weight to directly applicable, well-supported claims than a weaker inferred association. Preserve disagreement and avoid a definitive assessment where it cannot be resolved. A shared index accelerates repeated research and makes results reproducible, without making inferred mappings authoritative by distribution alone.

## Evidence inventory and sources

Durable evidence is stored under `docs/research/data/rq-0020/`:

- [2026-11-04-findings.json](data/rq-0020/2026-11-04-findings.json): scanner counts and identifiers, inventory definitions, source-divergence classifications, Git query controls, GitHub release/tag evidence, and the original FreeMarker Maven metadata.
- [2026-11-04-maven-mapping-timelines.json](data/rq-0020/2026-11-04-maven-mapping-timelines.json) and [CSV](data/rq-0020/2026-11-04-maven-mapping-timelines.csv): all 34 publication-to-first-observed-Maven-mapping timelines, exact UTC timestamps, and public source snapshots.
- [2026-11-04-structured-source-evidence.json](data/rq-0020/2026-11-04-structured-source-evidence.json): selected CNA/NVD source-file and routine declarations, actual Maven GHSA function-list responses, Go/RustSec symbol examples, bounded sample counts, and source/digest limitations.
- [2026-11-04-additional-source-evaluation.json](data/rq-0020/2026-11-04-additional-source-evaluation.json): Snyk's concrete Tomcat package association outside the earlier OSV Maven result, bounded Java-detail observations, API documentation, and still-unverified consumption conditions.
- [2026-11-04-osv-snyk-source-check.json](data/rq-0020/2026-11-04-osv-snyk-source-check.json): OSV's published/configured source check and a GitHub-imported record containing Snyk references, preserving the distinction between indirect overlap and direct database ingestion.

The current raw measurement workspaces are `.scratch/verification/osv-spring-scan/`, `.scratch/verification/nvd-divergence/`, `.scratch/verification/tomcat-osv-global/`, `.scratch/verification/tomcat-git-range-investigation/`, and `.scratch/verification/maven-advisory-timelines/`. These workspaces are not durable reader-facing evidence; the checked-in datasets above are the reproducible summary boundary. Keep source snapshots, tool versions, input identities, timestamps, count units, and classification rationale with future evidence.

Primary references checked 2026-11-04:

- [CVE JSON 5 schema documentation](https://cveproject.github.io/cve-schema/schema/docs/) and [NIST on NVD operational changes](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth).
- [NVD vulnerability status definitions](https://nvd.nist.gov/vuln/vulnerability-status) and [OSV FAQ](https://google.github.io/osv.dev/faq/).
- [OSV faster CVE data article](https://osv.dev/blog/posts/faster-cve-data/), [OSV issue 6148](https://github.com/google/osv.dev/issues/6148), [OSV issue 6137](https://github.com/google/osv.dev/issues/6137), and [OSV PR 6143](https://github.com/google/osv.dev/pull/6143). Issues and proposals are evidence of discussion, not deployed behavior.
- [OSV schema](https://ossf.github.io/osv-schema/) and [GitHub Advisory Database review documentation](https://github.com/github/advisory-database/blob/main/README.md).
- [Tomcat 10 security page](https://tomcat.apache.org/security-10.html), [CVE-2026-68763 disclosure](https://www.openwall.com/lists/oss-security/2026/08/26/9), [GHSA-82jr-6mfr-9vq5](https://github.com/advisories/GHSA-82jr-6mfr-9vq5), and [Tomcat BUILDING release instructions](https://github.com/apache/tomcat/blob/main/BUILDING.txt).
- [GitHub Releases API](https://docs.github.com/en/rest/releases/releases), [GitHub Commits API](https://docs.github.com/en/rest/commits/commits), and [GitHub global security advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories).

These sources support source roles, schemas, and tool behavior; empirical counts and latency statistics come from the identified local evidence snapshots, not from these documentation pages. Source URLs and status may change. Future updates should preserve the checked date and exact evidence snapshot rather than silently refreshing historical claims.

## Unresolved questions

1. How often do CVEs affecting Maven software have exact Maven PURLs or coordinates in CNA, GHSA, and OSV records, and how does coverage vary by publisher, project, and time?
2. Can NVD/CPE associations be translated into Maven candidate identities at a useful precision and recall, with provenance and ambiguity preserved? Which classifications must remain advisory-only?
3. What is the quality of repository/tag/release association for Git-only records, especially projects that tag off release branches or use backports and cherry-picks?
4. Which user question matters most: potential findings associated with removed components, observed scanner delta across two inventories, or findings still present on retained but class-trimmed components? What minimal presentation avoids conflating them?
5. How should finding-instance, CVE/component-pair, and distinct-CVE counts be presented together without alias duplication or implying global disappearance?
6. How can a before/after experiment pin or otherwise characterize the same scanner database? What should be reported when a scanner does not expose a stable database revision?
7. Which direct-JAR identity/cataloging failures are systemic, and should inventory identity be improved or should the project simply prefer a resolved Maven SBOM for those measurements?
8. How do local cache TTL, upstream snapshot cadence, advisory ingestion timing, and selected-sample survivorship bias affect any claimed mapping-latency distribution?
9. What report wording and precedence should apply when package scanner findings persist but stronger, independently gated assessment evidence exists? Which sources and scope should remain visible to avoid presenting either result as a universal truth?
10. What evidence threshold would justify an opt-in Git release association feature, and what explicit unknown state should it emit for ambiguous or unavailable history?
11. How often are source-file/routine declarations populated, precise enough, and complete enough for current artifact attribution? How should this be measured separately for CNA publishers, NVD copies, GHSA APIs, and ecosystem-specific OSV exports?
12. Which repositories should be watched, who maintains their release conventions, and what minimum graph coverage, refresh cadence, snapshot retention, and artifact-provenance evidence make shared release association useful and reproducible?
13. Which optional additional sources supply enough unique package associations, earlier mappings, or attributable code locations to justify their access, maintenance and consumption costs? For Snyk, what do authenticated responses and applicable data-use terms permit beyond the public-page example recorded here?

## Future update protocol

Future chats investigating this topic should update this same RQ rather than create a parallel record. Append a dated finding section and update `Last updated`; do not overwrite prior snapshots or silently revise their counts. If a previous statement proves wrong or is superseded, identify the exact earlier statement, state the correction and reason, and preserve the historical observation where useful.

Every new empirical claim should record, as applicable: source URLs and access date; scanner/tool version; database/cache snapshot identity and freshness; exact input inventory and its generation method; scope and inclusion/exclusion rules; query shape; timestamps; units and alias-deduplication rule; uncertainty; durable evidence path; and whether the result is observation, interpretation, or proposal. Keep unresolved and missing values explicit rather than replacing them with zero.

Proposals remain proposals until adopted. Before implementation, define acceptance criteria and identify affected schemas, reports, source contracts, and tests. Any persisted-format or compatibility decision must follow repository policy and have an ADR before promising migration or compatibility behavior. Keep this RQ linked from the research register and related investigations; a new chat on the same topic should continue this record rather than assign another RQ number.
