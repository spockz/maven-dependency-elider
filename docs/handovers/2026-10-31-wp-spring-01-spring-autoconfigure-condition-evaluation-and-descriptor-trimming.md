<!-- WHY: Defines staged Spring AOT evidence integration and scoped registration-root replacement without duplicating Spring condition evaluation (Subsumed by WP-PLATFORM-01). -->
# Work Package Handover: WP-SPRING-01 Spring AOT Evidence and Descriptor Coherence

> [!NOTE]
> **Subsumed**: This work package has been unified with compiler decoupling, multi-JDK portability, JPMS module awareness, and post-packaging acceleration into a single all-encompassing work package: **[WP-PLATFORM-01: Multi-JDK Decoupling, Spring AOT Coherence, and Live Proof Pivot](2026-11-02-wp-platform-01-compiler-decoupling-and-live-proof-pivot.md)**. All technical specifications, findings, and slices from this document are fully preserved and coordinated under WP-PLATFORM-01.

* **Status**: Subsumed by [WP-PLATFORM-01](2026-11-02-wp-platform-01-compiler-decoupling-and-live-proof-pivot.md)
* **Date**: 2026-10-31
* **Last Reviewed**: 2026-11-02
* **Scope**: Production/generated input handling, Spring root provenance, report guidance, and descriptor coherence.
* **Related Work Packages**:
  * [WP-POLICY-01: Dependency Banishment and Explicit Retention](2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md)
* **Related Research**:
  * [RQ-0002: Runtime Sensor Fidelity](../research/RQ-0002-runtime-sensor-fidelity-and-framework-autoconfiguration-quiescence.md)
  * [RQ-0005: Bean Request Evidence and Recommendations](../research/RQ-0005-spring-bean-request-evidence-and-autoconfiguration-recommendations.md)
  * [RQ-0016: Native Image Metadata Ingestion](../research/RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md)
  * [RQ-0018: Spring AOT, JPMS, and JVM Packaging](../research/RQ-0018-jpms-module-awareness-and-assisted-modularization.md)
* **Related Decisions**:
  * [ADR-0008: Evidence-Bounded VEX](../adr/0008-precondition-gated-vex-attestations.md)
  * [ADR-0010: Post-Compile Lifecycle and Bytecode Completeness](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)

## 1. Revised Scope and Findings

Use Spring's own AOT processing to obtain its selected bean model. Do not implement `OnClassCondition`, `AutoConfigurationSorter`, or an enclosing-class condition evaluator inside Elider. The former archive-only class inventory and `$`-prefix algorithm are withdrawn, including their unconditional removal tests. This specification replaces that algorithm rather than leaving two conflicting implementations to choose from.

The following findings remain useful:

* [`SpringMetadataRoots`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SpringMetadataRoots.java) roots imports, metadata owners, class-valued conditions, and ordering targets conservatively. That can retain dormant capabilities, but some class-presence checks preserve observable behavior. It is not sound to remove every conditional target.
* The current production scanner can read generated classes copied into `target/classes`, but adjacent AOT resources are not automatically ingested by that scan. Directory-aware hint/resource handling is a concrete integration gap.
* Generated AOT registrations are stronger evidence than a startup trace, but do not express application demand. Ordinary lazy and prototype beans generally remain. AOT preparation can instantiate infrastructure and exclude processor beans from generated registrations.
* Registration omission does not remove original methods or their bytecode references. The local Spring 6.1.14 probe in [RQ-0018](../research/RQ-0018-jpms-module-awareness-and-assisted-modularization.md#local-feasibility-probe-2026-11-01) demonstrated this limit. Class-level trimming may therefore retain an optional dependency even after its bean registration disappears.
* A runtime listener, environment processor, initializer, service provider, or resource lookup can remain necessary outside the generated bean model. An AOT evidence directory cannot authorize disabling all Spring metadata roots.

WP-POLICY-01 is needed only to execute its new dependency ban. Evidence ingestion, retention reporting, and an explicit `spring.autoconfigure.exclude` experiment can proceed without it. No savings or CVE-removal count is an acceptance prerequisite.

Preserve the intended two-step workflow: AOT first selects and represents the configured application, including lazy or unrequested application beans; workload-informed user choices then select features/dependencies for removal, followed by regeneration and validation. The second step addresses application demand that static analysis cannot establish. Record intended feature removals and required remaining behavior so expected bean-model changes are accepted while unexplained changes fail.

## 2. Runtime and Evidence Contracts

| Supported use | Treatment of AOT evidence | Spring roots |
| :--- | :--- | :--- |
| No AOT evidence | Existing production/trace/metadata inputs. | Preserve conservative defaults. |
| Ordinary JVM with AOT evidence | Add generated references and supported hints. | Preserve conservative defaults; no negative inference from the AOT model. |
| Validated AOT-enabled JVM or native deployment | Generated assets are executable inputs tied to a specific environment/classpath. | Investigate replacement of proven-superseded discovery contributions only; retain other obligations. |

AOT generation must run against the application's actual chosen inputs, including intentional feature-selection changes. An earlier trace or AOT run describes its earlier classpath, not a later ban. Regenerate and revalidate after a policy change; do not discard contradictory evidence merely to make a ban pass.

Spring Boot's [AOT JVM restrictions](https://docs.spring.io/spring-boot/3.3/reference/packaging/aot.html) include a fixed build-time classpath. Generated assets from before trimming cannot certify the new classpath. Validate a final generation against the proposed deployment; reject missing roots or unstable generation, and bound any reconciliation loop.

`process-aot` at `prepare-package` is too late for Elider's pre-test production analysis. For the same-phase `process-classes` arrangement, [`EliderLifecycleParticipant.afterProjectsRead`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java#L30-L33) can deterministically guarantee that `dependency-elider:elide` runs **last** in `process-classes` (regardless of POM `<plugin>` order) by setting `execution.setPriority(Integer.MAX_VALUE)` on the `elide` `PluginExecution` (`DefaultLifecycleMappingDelegate` sorts phase executions by `PluginExecution.getPriority()` ascending, where user POM executions default to `0`) and moving `dependency-elider-maven-plugin` / `elide` to the tail of `project.getBuild().getPlugins()` and `plugin.getExecutions()`. [`MavenPreconditionGenerationGuard`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java) can then accept verified pre-`elide` `process-classes` writers (`priority < elide.getPriority()`) whose outputs are captured before `elide` runs. Prior-build evidence still needs freshness checking and storage that survives the consuming build's `clean`.

## 3. Implementation Slices

### Slice 1: Additive AOT Inputs and Provenance

Extend the existing input pipeline rather than introducing another bytecode or native-image parser:

* [`ProductionBytecodeAnalysis`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ProductionBytecodeAnalysis.java) for ordinary and generated compiled classes.
* [`MavenAnalysisEvidence`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenAnalysisEvidence.java), [`DynamicRootOrchestrator`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DynamicRootOrchestrator.java), and [`NativeImageScanContext`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/NativeImageScanContext.java) for artifact/resource ownership and existing metadata readers.
* [`ProductionOutputFingerprint`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ProductionOutputFingerprint.java) and consumed-input verification for freshness, including changes during analysis and publication.

Required behavior:

1. Merge ordinary production bytecode, generated classes, and the source-attribution supplement. Never replace all production inputs with only `target/spring-aot/main/classes`; never filter generated inputs by class-name suffix.
2. Import generated reflection, proxy, serialization, resource/bundle, and other descriptors within RQ-0016's supported schemas. Resolve resources across production/generated directories and dependency JARs, including classless resource JARs. Unsupported formats and unreadable/malformed files fail explicitly.
3. Deduplicate copied generated assets by validated identity. Preserve the declaring input, target/provider, root category, and runtime/generation role. A conflicting duplicate class cannot be treated as an interchangeable provider merely because its name matches.
4. Validate bundle inputs: application/source/resource hashes, ordered dependency identities/hashes, generated-output hashes, main class, versions, profiles, condition-relevant configuration identity, and context/runtime mode. Do not persist secret values. Model missing/unverifiable environment inputs explicitly.
5. Detect stale classes after renames/deletions, absent outputs, mixed generation runs, test-AOT contamination, and post-capture changes. Distinguish an explicitly configured empty/missing evidence source from no source configured.
6. Keep current Spring roots intact. New positive roots can increase retention; this slice proves completeness of ingestion, not reduction.

Any new persisted evidence format stays at version 1 while unreleased. Implement its writer, reader, validator, fixtures, and documentation together.

### Slice 2: Retention Explanations and Feature-Selection Guidance

Use typed root contributions rather than one undifferentiated set. Proposed fields include origin input/artifact, evidence category, referenced class or resource, provider identity, and applicable generation/runtime context. These are design fields, not existing API names.

Report separately:

* retained by conservative discovery metadata;
* referenced by generated registration, proxy, or hint;
* not observed in a specified workload;
* required through another class, resource, source constraint, or graph promotion;
* explicitly requested for removal by policy, including the blocking obligation if rejected.

A bean-origin sidecar from supported AOT extension points could connect registrations to exact artifacts and improve recommendations. Its capture point must account for later processors/contributions. Treat unresolved origins as unknown, and do not mutate definitions to collect evidence. Bean-request instrumentation remains RQ-0005 work; class loading is not bean demand.

Offer an explicit feature-selection experiment: disable a supported feature or exclude an auto-configuration, regenerate AOT, test representative behavior, then consider removing dependencies. `spring.autoconfigure.exclude` names auto-configuration classes, not arbitrary application beans. Policy bans must honor surviving generated references and retained metadata obligations. No automatic POM edits, exclusion replacements, or population of `banishedDependencies` is authorized by an advisory.

Keep baseline evidence and evidence for the selected variant distinct. A baseline observation can motivate or contextualize an intentional removal; it must not be rewritten as non-use or mistaken for current-variant evidence. If generated references block the requested ban, identify the contributing feature and regenerate after its explicit removal. Test the intended removal and the remaining features, rather than requiring equality with the entire baseline bean model.

For vulnerability reporting, retained mapped code prevents the corresponding code-absence justification; it does not alone establish applicability or exploitability. An AOT-generated reference is not merely a conservative guess. Only claim that a conservative contribution is the sole blocker after accounting for transitive retention and graph rules. Verify physical final output before emitting any absence claim under ADR-0008.

### Slice 3: Scoped AOT Registration-Root Replacement Experiment

This slice requires a decision record and a fixture proving the exact boundary before changing defaults.

1. Identify discovery contributions superseded by the generated production bean model. Do not disable `SpringMetadataRoots` wholesale or drop an entire artifact's dynamic roots because it contains auto-configuration metadata.
2. Preserve runtime `spring.factories` registrations such as listeners, environment processors, and initializers; keep ordinary application references, SPI, native-image hints, and resources independent. `aot.factories` describes AOT processing services and must remain available where regeneration needs them.
3. Retain conservatively for unmodeled contexts, programmatic discovery, incomplete provenance, or unsupported versions. Independently imported nested configurations are not governed by a name-prefix rule. The discovery-root exemption applies only to its proved context and environment.
4. Generate against a clean candidate classpath, re-ingest all outputs, and verify no required root was lost. A failed or unstable result rejects the plan before output publication. If extra generation-only tools are required, document that distinct inventory; do not silently use dependencies absent from the claimed inputs.
5. Launch the final packaged application in its supported AOT mode, exercise required paths, and check incompatible non-AOT launch handling. A build-time setting is not sufficient to force all later JVM invocations into AOT mode. Test native execution separately when claimed.

The first successful fixture should remove one structurally separate inactive configuration while retaining an active lazy bean, reflective DTO, and resource-only dependency. Also include an inactive method inside a retained class; explain why its hard reference remains rather than weakening class closure to improve counts.

### Slice 4: Descriptor Coherence and Real Fixture Evaluation

Only rewrite descriptors after final retained classes and registration policy are known:

* Filter `AutoConfiguration.imports` entries whose archive-owned classes were actually removed; preserve external registrations and independent roots.
* Parse autoconfigure metadata using Java properties semantics, including escaped keys, continuations, and supported empty values. Preserve metadata needed by any remaining sorting/lookup consumer. Do not implement a simplistic `key=value` line filter.
* Treat `spring.factories` by key/version and preserve live infrastructure registrations. Keep `aot.factories` generation requirements distinct from runtime initializer discovery.
* Apply equivalent ownership rules in [`SingleReleaseArchiveWriter`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/SingleReleaseArchiveWriter.java) and [`MultiReleaseArchiveWriter`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/MultiReleaseArchiveWriter.java). Verify target-JDK inventory and independent descriptor/resource consumers.

Then revisit [`example-spring-boot-app`](../../examples/example-spring-boot-app/pom.xml). Remove workaround dependencies individually only when the changed fixture's actual closure and runtime checks permit it. Remaining hard references, modular-JAR pass-through, graph promotion, or broad hints are findings to report, not reasons to force a desired artifact/CVE count. Root-module-descriptor work and JDK cache training remain separate RQ-0018 experiments.

## 4. Acceptance Criteria and Verification

* [ ] Additive ingestion retains generated/proxy/reflection references and resource-only dependencies without changing the no-AOT retention policy.
* [ ] Freshness checks reject mixed/stale/changed evidence and test-AOT contamination; complete input identity reaches both analysis and cached-output validation.
* [ ] Shared fixtures demonstrate a false condition, an independently imported nested configuration, a lazy bean exercised only later, an AOT processor excluded from runtime registration, and an original conditional method whose bytecode reference remains.
* [ ] Positive/missing-class condition changes are evaluated by Spring across deliberate feature/classpath changes. No custom condition evaluator or absence-based workload pruning is introduced.
* [ ] Runtime listeners, initializers, environment processors, SPI, and resources survive scoped root replacement. Unknown contexts retain conservatively.
* [ ] Clean and incremental lifecycle runs validate execution order, capture guards, final regeneration, and actual packaged AOT behavior. Missing/conflicting roots fail before publication and preserve the prior successful outputs.
* [ ] Descriptor tests preserve external registrations, key semantics, continued/escaped properties, entry-order independence, and both writer paths.
* [ ] Ban recommendations identify conflicts from retained code/metadata and graph policy. The combined WP-POLICY-01 fixture proves successful removal or explicit failure, never silent re-retention or evidence erasure.
* [ ] A two-step fixture first retains a lazy/unrequested bean, then explicitly disables its feature, regenerates evidence, and verifies the selected removal plus remaining application behavior. Baseline and selected-variant identities remain distinct.
* [ ] Reports distinguish conservative roots, generated references, workload coverage, policy changes, and verified code presence; no unsupported vulnerability applicability or non-reachability claim is emitted.

Use shared immutable fixtures and `assertAll` for independent observations. Keep separate executions for materially different classpaths, modes, profiles, or lifecycle states. After implementation, apply repository formatting and use `make check`; when fixtures or documented commands/output change, run `make update-transcripts` before the final check. Generated README and [plugin usage](../../dependency-elider-maven-plugin/src/site/markdown/usage.md) transcript blocks must not be hand-edited.
