<!-- WHY: Defines evidence and lifecycle boundaries for Spring AOT integration, condition-aware trimming, and post-elision JVM packaging experiments. -->
# RQ-0018: JPMS Mechanics, Spring AOT & CDS Integration, and `jlink` JRE Reduction

## Status

Open; revised proposals reviewed on 2026-11-01, including a local Spring 6.1.14 AOT probe. The integration designs below are proposals, not implemented capabilities or measured size/performance benefits.

## Date

2026-10-31

## Category

Bytecode Slicing, Framework AOT/CDS Integration & Modular Packaging

## Related Documents

* [ADR-0007: Proven ServiceLoader SPI Roots and Conservative Vulnerability Exclusions](../adr/0007-proven-serviceloader-spi-roots-and-conservative-cve-exclusions.md)
* [ADR-0008: Evidence-Bounded Precondition-Gated VEX Attestations](../adr/0008-precondition-gated-vex-attestations.md)
* [ADR-0010: Post-Compile Lifecycle and Production Bytecode Completeness](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)
* [RQ-0002: Runtime Sensor Fidelity and Framework Auto-Configuration Quiescence](RQ-0002-runtime-sensor-fidelity-and-framework-autoconfiguration-quiescence.md)
* [RQ-0005: Spring Bean Request Evidence and Auto-Configuration Recommendations](RQ-0005-spring-bean-request-evidence-and-autoconfiguration-recommendations.md)
* [RQ-0014: Multi-Release JAR Trimming and Vertical Shading](RQ-0014-multi-release-jar-trimming-and-vertical-shading.md)
* [RQ-0016: Native Image Metadata Ingestion](RQ-0016-graalvm-native-image-metadata-ingestion-and-permissive-argument-taxonomy.md)
* [RQ-0017: Source-Generation Lifecycle Integration](RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md)
* [WP-POLICY-01: `banishedDependencies` and `retainedArtifacts`](../handovers/2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md) *(Required for executing the proposed ban policy, not for AOT ingestion or advisory reporting)*
* [WP-SPRING-01: Spring Condition Evaluation and Descriptor Trimming](../handovers/2026-10-31-wp-spring-01-spring-autoconfigure-condition-evaluation-and-descriptor-trimming.md)

## 1. Review Findings and Evidence Boundary

The strongest opportunity is to combine Spring's generated bean-registration code and runtime hints with Elider's existing bytecode and dynamic-root analysis. Condition-aware metadata handling can reduce unnecessary retention; CDS and JDK AOT caches can then accelerate the final trimmed deployment. These are complementary improvements with different correctness requirements.

The repository fixture pins Spring Boot **3.3.5**. Source checks below use that release and Spring Framework **6.1.14**; newer Boot/JDK capabilities are separate experiments. Repository observations describe the working tree at review time, including ongoing refactoring.

| Original finding | Review result |
| :--- | :--- |
| Spring metadata over-retains dormant configurations. | Confirmed: `SpringMetadataRoots` roots imports, metadata owners, class-valued conditions, and ordering targets. Keep the ordinary-JVM policy conservative; investigate replacing specific registration roots only for a validated AOT deployment. Merely supplying an AOT directory cannot switch off Spring metadata roots. |
| `process-aot` can supply useful evidence before Elider runs. | Confirmed as the preferred source of Spring's condition decisions. Lazy/unrequested application beans generally remain represented. AOT processor beans can be excluded from generated registrations, and AOT preparation can instantiate infrastructure. |
| Generated AOT files identify everything needed at runtime. | Too strong. They describe one build-time bean model and registered dynamic access. Missing hints or an unobserved path do not prove absence of runtime use. |
| `onRefresh` provides a clean, complete application startup. | Incorrect. It halts before lifecycle startup; it is a bounded training run. Recorder completion must be checked separately. |
| A sanitized class list makes a pre-trimming CDS archive reusable. | Incorrect. Archives/caches must be trained for the final deployment. Reading a class list as evidence is different from writing a valid HotSpot archive input. |
| JPMS metadata enables automatic SPI/VEX proofs and 30–50 MiB JRE savings. | Unproven. Module descriptors constrain some discovery paths; bytecode analysis misses dynamic requirements. Size and vulnerability effects need separate measurements. |
| A global ban replaces repeated Maven exclusions. | Confirmed when combined with `EliderLifecycleParticipant.afterProjectsRead` injecting a Maven `Exclusion` onto every first-level `<dependency>` before dependency collection, backed by post-resolution link-closure verification in `elide`/`analyze`. Repeated POM `<exclusions>` (`>= 2`) can therefore be surfaced as review candidates for `<banishedDependency>`. |

### 1.1 Existing Integration Points

[`ProductionBytecodeAnalysis`](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ProductionBytecodeAnalysis.java) scans compiled classes under a production output directory. [`DynamicRootOrchestrator`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DynamicRootOrchestrator.java) and [`DependencyDynamicRoots`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DependencyDynamicRoots.java) collect dependency-JAR metadata and supported external configuration references. They do **not** automatically discover an application AOT directory or its generated resources.

A copied AOT class in `target/classes` can therefore contribute bytecode references today, while adjacent generated reflection/resource metadata is not automatically ingested through that production-output scan. Setting `elide.productionOutput` to only an AOT directory would also omit the application's ordinary compiled output; it is not a substitute for a combined input model.

## 2. Spring AOT Integration

### 2.1 Separate Runtime Contracts

Spring AOT prepares a bean model for the build-time environment and emits Java sources, generated bytecode, and `RuntimeHints`. Conditions and profiles affect that model; AOT does not exercise every bean's business behavior. See [Spring's AOT engine overview](https://docs.spring.io/spring-framework/reference/core/aot.html).

| Deployment | Useful evidence | Required boundary |
| :--- | :--- | :--- |
| Ordinary JVM, AOT disabled | Generated references and hints supplement production roots and workload traces. | Additive evidence only. A bean absent from the AOT model may exist under another runtime profile or property setting. |
| JVM with `spring.aot.enabled=true` | Generated initializer/bean code is part of the executable application. | Bind evidence to the selected environment and validate the actual AOT-enabled artifact after pruning. |
| Native image | Generated code and supported reachability metadata feed both Elider and native-image analysis. | Run native-image build and representative native workloads; JVM success does not validate native reflection, resources, JNI, or initialization. |

Spring Boot's [AOT JVM contract](https://docs.spring.io/spring-boot/3.3/reference/packaging/aot.html) requires a fixed build-time classpath and restricts runtime changes to bean selection. Consequently, generating AOT against the original classpath and then pruning it is **not an established supported integration**. It must be investigated with regeneration and validation against the final classpath. Hints may increase retention while preventing breakage; a successful integration need not always make a smaller JAR.

### 2.2 Import Generated Assets Through Existing Analysis

In Boot 3.3.5, [`ProcessAotMojo`](https://github.com/spring-projects/spring-boot/blob/v3.3.5/spring-boot-project/spring-boot-tools/spring-boot-maven-plugin/src/main/java/org/springframework/boot/maven/ProcessAotMojo.java) defaults to `prepare-package`. It generates into `target/spring-aot/main/{sources,classes,resources}`, compiles the sources, and copies generated classes and resources into `classesDirectory`, normally `target/classes`. Calling `SpringApplicationAotProcessor` alone does not perform that entire Maven workflow.

Proposed integration:

1. Scan **all generated class files**, including proxies and initializers, through the existing bytecode scanner. Do not depend on `*__BeanDefinitions` naming conventions. Merge their references with ordinary production bytecode and the source-attribution supplement required by ADR-0010.
2. Feed generated `META-INF/native-image/**` descriptors through the parsers established by RQ-0016. Include reflection, proxies, serialization, resources/bundles, and other supported descriptors, not just `reflect-config.json`. Preserve conditional-hint semantics: the current parser conservatively roots condition types; it does not implement GraalVM's reachability evaluator.
3. Extend resource resolution to production/generated directories as well as dependency archives. A resource hint may retain a resource-only dependency or a provider in another JAR. Preserve generated runtime resources and validate discovery of the generated application initializer in the final AOT launch. Separately, `META-INF/spring/aot.factories` registers build-time AOT processors and hint registrars; preserve what regeneration requires without confusing those registrations with runtime initializer discovery. See [Spring's AOT contribution interfaces](https://docs.spring.io/spring-framework/reference/core/aot.html) and [Boot's initializer loading](https://github.com/spring-projects/spring-boot/blob/v3.3.5/spring-boot-project/spring-boot/src/main/java/org/springframework/boot/SpringApplication.java).
4. Retain origin and reason for each contribution: production bytecode, AOT-generated reference, runtime hint, resource provider, startup trace, or workload trace. Deduplicate overlapping copies without losing provenance. Detect conflicting duplicate classes/resources according to the effective classpath, rather than silently unioning incompatible contents.
5. Keep the adapter optional and version-scoped. Reuse scanners and validators without making the core library boot a Spring context or depend on Spring. Verify emitted formats for each supported Boot/Framework/native-image combination; reject unsupported or malformed inputs explicitly.

A future evidence bundle should include application/source/resource digests, ordered dependency identities and hashes, generated-output hashes, main class, Boot/Framework/plugin/JDK versions, AOT mode, profiles, and condition-relevant configuration identity. Do not persist secret property values. Treat unmodeled custom-condition inputs, external configuration, and runtime classpath additions as incomplete evidence. Freshness checks must also cover deletion, stale generated classes after a source rename, and changes during analysis/publication.

Keep production and `process-test-aot` outputs separate. Test contexts and slice-test hints must not masquerade as the production AOT model. If multiple deployment configurations are supported, preserve positive evidence from each and require any exclusion claim to hold across the explicitly supported set. Any new persisted bundle remains schema version **1** while unreleased, with writer, reader, validator, fixtures, and documentation changed together.

### 2.3 Lifecycle Ordering and the Final Classpath

Keep `elide` before `test-compile`/`test` as required by ADR-0010. Moving it to `prepare-package` would leave ordinary unit tests running against the original dependencies.

| Mode | Proposed sequence | Qualification |
| :--- | :--- | :--- |
| External evidence | Baseline build with elision disabled → export compiled AOT evidence → validate bundle in the consuming build → elide → test/package. | `initialize` cannot generate current AOT evidence before compilation. Preserve the bundle outside a directory deleted by the consuming `clean`; never silently reuse stale `target` output. |
| Same-build positive evidence | Compile → Boot `process-aot` → Elider scan/elision at `process-classes` → test/package. | Verify effective execution order, generated-source compilation, copies, and Maven artifact views. This sequence alone does not certify AOT-enabled deployment on the changed classpath. |
| AOT-enabled final deployment | Initial evidence → proposed pruning → clean AOT regeneration against the resulting runtime classpath → reconcile new roots/conditions → tests of final AOT artifact. | If regeneration requires restored dependencies or changes the bean model, recompute or reject the plan. Bound iterations and fail explicitly on instability. |

There is a current integration blocker for precondition proofs: [`MavenPreconditionGenerationGuard`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java) rejects other writers bound at the `process-classes` capture phase when complete precondition capture is requested, and relying on manual POM `<plugin>` declaration order is fragile. However, in Maven's `DefaultLifecycleMappingDelegate.calculateLifecycleMappings`, executions within a phase are ordered via a `TreeMap<Integer, List<MojoExecution>>` keyed by `PluginExecution.getPriority()` (default `< 0` for lifecycle bindings, `0` for user POM executions) and then by `project.getBuild().getPlugins()` list order. Therefore, [`EliderLifecycleParticipant.afterProjectsRead`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java#L30-L33) can deterministically force `dependency-elider:elide` to run **last** in `process-classes`—independent of POM declaration order—by setting `execution.setPriority(Integer.MAX_VALUE)` and moving `dependency-elider-maven-plugin` (and its `elide` execution) to the tail of `project.getBuild().getPlugins()` / `plugin.getExecutions()`. With that deterministic ordering guaranteed by the core extension, `MavenPreconditionGenerationGuard` can model verified pre-`elide` `process-classes` writers (with `priority < elide.getPriority()`) whose outputs are captured and hashed by `elide`, while unknown later writers remain rejected.

A final regeneration experiment must use isolated, clean outputs and the actual proposed dependency files, not dependencies silently restored by Maven resolution. Final generated references must be included in link closure and cache identity. Tests should launch the packaged application with `spring.aot.enabled=true` and assert its intended features; ordinary `@SpringBootTest` success can validate a different context. The [Boot Maven AOT documentation](https://docs.spring.io/spring-boot/3.3/maven-plugin/aot.html) describes application and test processing separately.

### 2.4 Explainable Configuration Recommendations

The intended workflow has two steps. First, Spring AOT selects registrations from configuration and classpath inputs; ordinary lazy and unrequested beans may remain. Second, workload evidence and retention explanations identify candidates for an explicit user-directed feature/dependency removal experiment. That second step is necessary because neither AOT registration nor static reachability establishes whether a capability is wanted. Keeping those beans in step one is expected behavior.

Combine AOT bean origins with the condition outcomes and bean-request evidence proposed in RQ-0005. Report why a dependency remains: an active bean, a generated proxy, reflection, a resource, or a condition whose truth must be preserved. Distinguish framework probing from application demand without subtracting either from roots automatically.

For an apparently unnecessary capability, recommend an explicit auto-configuration exclusion, then regenerate AOT and rerun workloads. Only then evaluate removing its starter/dependencies via [`WP-POLICY-01`](../handovers/2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md)'s `<banishedDependencies><banishedDependency>groupId:artifactId</banishedDependency></banishedDependencies>` (`-Delide.banishedDependencies`) and rerun again, since classpath removal can activate fallback configurations. This can reduce the bean graph before trimming and is easier to review than speculative deletion of framework classes. Do not automatically modify the POM or populate `banishedDependencies` / `retainedArtifacts` without user review.

`spring.autoconfigure.exclude` selects auto-configuration classes; it is not an arbitrary bean-removal API. For user configurations or third-party registrations outside that mechanism, use their supported feature settings or change application configuration. A ban is an explicit feature/classpath policy change, not proof of non-use. If generated code, retained metadata, resources, or graph constraints still require the banned artifact, the policy must fail with the blocking reason. Removing metadata contributed by the banned artifact does not remove references to it from `spring-boot-autoconfigure` or other retained artifacts.

Record the second step's intended feature removals and required remaining behavior before regeneration. Expected bean/condition changes are allowed; validate against that selected configuration, not a requirement that every baseline bean survive. Preserve the original trace/model as baseline evidence, generate fresh evidence for the selected variant, and reject unexplained changes or incompatible current inputs. A generated-reference conflict can direct the user to disable the contributing feature and regenerate before enforcing the dependency ban. It is a diagnostic for completing the second step.

### 2.5 Opportunities That Do Not Require Global Banishment

* **Additive evidence ingestion can proceed independently.** Consume generated bytecode/hints with conservative Spring roots intact first. This establishes directory/resource handling and avoids coupling the first integration to root removal or a new policy surface.
* **Explain retention before changing it.** Capture a sidecar from the AOT fork containing bean names, factory/definition origins, scope/lazy flags, configuration inputs, and generated-asset attribution. Use supported AOT extension points without changing the bean model. Define when capture is complete relative to all contributors; a callback before later contributions is not a complete manifest. Keep unresolved provenance explicit and avoid deriving bean demand from class-load absence.
* **Measure a scoped replacement of registration roots.** In a separately validated AOT deployment, generated registrations can replace some discovery roots that ordinary startup requires. Keep runtime listeners, environment processors, direct code references, hints, and service/resource obligations independent. The replacement is per contribution, not per JAR or all of `SpringMetadataRoots`.
* **Separate generation inputs from deployment outputs.** AOT processors may be needed to regenerate an artifact without being needed in its final runtime. Record both inventories, including any explicitly supported build-only tooling. A runtime-only ban must not be described as removing a library from the entire build. The first policy slice has no general build-only/deploy-only split; do not invent one by retaining hidden dependencies during validation.

These steps can expose useful improvements even when no artifact is removed. Removing an inactive configuration class is most promising when its implementation is structurally separate from retained classes; method-level optional code inside a retained class remains a different problem.

## 3. Relying on Spring AOT Instead of Custom `@ConditionalOnClass` Re-Implementation

### 3.1 Selected Direction: Spring Evaluates Conditions; Elider Validates Evidence Scope

[`SpringMetadataRoots`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SpringMetadataRoots.java) currently treats `AutoConfiguration.imports`, `spring.factories`, and `spring-autoconfigure-metadata.properties` (including `.ConditionalOn*` and `.AutoConfigureBefore`/`.AutoConfigureAfter` entries) as unconditional roots. `Owner.ConditionalOnClass=ClassA,ClassB` is a guard on `Owner`, not an unconditional retention directive. For an ordinary startup that must still evaluate and match that condition, its required types must remain available; retaining the owner alone does not preserve the outcome.

Furthermore, attempting to re-implement Spring Boot's [`OnClassCondition`](https://github.com/spring-projects/spring-boot/blob/v3.3.5/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/condition/OnClassCondition.java) and [`AutoConfigurationSorter`](https://github.com/spring-projects/spring-boot/blob/v3.3.5/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/AutoConfigurationSorter.java) statically inside Elider's scanner is fragile and undesirable:

* `NativeImageScanContext.logicalClasses(Optional.empty())` only covers candidate Maven dependency JARs, omitting JDK platform types (such as `javax.sql.DataSource` in `BatchAutoConfiguration.ConditionalOnClass`), application/generated classes, and target-JDK MRJAR views.
* `META-INF/spring-autoconfigure-metadata.properties` is a point-lookup table (`AutoConfigurationMetadata.wasProcessed`), not a class registration mechanism; top-level `@Import` targets like `FreeMarkerServletWebConfiguration` have no `$` prefix yet depend on `FreeMarkerAutoConfiguration`'s outer guard, while other `$` nested classes are imported independently.
* Pruning a class named only in a string-valued `@ConditionalOnClass` or `@ConditionalOnMissingClass` annotation can silently disable an active configuration or activate a dormant fallback configuration.

**Preferred design: use Spring's evaluated bean model without recreating its condition engine.** `GenericApplicationContext.refreshForAotProcessing()` invokes bean-factory post-processors, including configuration processing. Their results describe the selected application/environment, not every possible context or runtime discovery path.

| Contribution | Ordinary JVM, including optional AOT evidence | Validated AOT deployment experiment |
| :--- | :--- | :--- |
| `AutoConfiguration.imports` and configuration-discovery roots | Preserve current conservative behavior; generated evidence is additive. | Consider replacing only discovery contributions proven superseded by the generated model. |
| Autoconfigure condition/ordering metadata | Retain conservatively under the current policy; it is a lookup table rather than a complete registration list. | Classify separately from actual registrations; preserve any remaining runtime/build-time consumer requirements. |
| `spring.factories` listeners, initializers, environment processors | Preserve applicable registrations. | Preserve applicable registrations: AOT does not replace the entire Boot startup sequence. |
| Generated references, runtime hints, application roots, SPI/resource evidence | Positive obligations. | Positive obligations; replacing Spring discovery roots does not subtract them. |
| `aot.factories` processors and hint registrars | Needed where AOT generation is performed. | Generation inputs remain available for regeneration; any runtime exclusion needs separate evidence. |

Before replacing a contribution, require a recognized complete AOT run, matching production inputs and supported launch mode, explicit environment/context scope, final-classpath regeneration, and no unresolved provenance for the affected registration. An ordinary-mode launch, extra child/management context, or programmatic scan may still need discovery metadata. Unknown/custom behavior retains conservatively. Test the actual packaged AOT launch and define how an incompatible non-AOT launch is detected; a POM setting alone cannot enforce a later JVM flag.

This is a research direction, not an accepted compatibility promise. Record an ADR before turning AOT evidence into a subtractive policy. The former archive-only condition evaluator and `$`-prefix enclosing-condition algorithm remain out of scope.

### 3.2 What Spring AOT Drops vs. Retains (`BeanRegistrationsAotProcessor`) and CVE Exclusion Guidance

The pinned source gives a more precise boundary than “all matched beans, no instantiation”:

* [`GenericApplicationContext.refreshForAotProcessing()`](https://github.com/spring-projects/spring-framework/blob/v6.1.14/spring-context/src/main/java/org/springframework/context/support/GenericApplicationContext.java) continues after `freezeConfiguration()` to merged-definition processing and bean-type determination. Infrastructure/post-processor creation can occur; this is not a normal eager-singleton startup or a bean-demand trace.
* [`BeanRegistrationsAotProcessor`](https://github.com/spring-projects/spring-framework/blob/v6.1.14/spring-beans/src/main/java/org/springframework/beans/factory/aot/BeanRegistrationsAotProcessor.java) considers registered definitions, but only records those with a non-null method generator. [`BeanDefinitionMethodGeneratorFactory`](https://github.com/spring-projects/spring-framework/blob/v6.1.14/spring-beans/src/main/java/org/springframework/beans/factory/aot/BeanDefinitionMethodGeneratorFactory.java) applies processor and `BeanRegistrationExcludeFilter` exclusions. Ordinary lazy/prototype beans are not removed merely because a workload never requested them.
* An unmatched registration is omitted from the bean model. That does **not** prove its type disappears from generated hints, another bean's references, or the original configuration class. The original class can still contain a conditional factory method and its hard dependency references.

Report distinct states: conservative metadata retention, generated registration/reference, not observed in a named workload, policy-requested removal, and verified final code presence. A generated bean reference is stronger than a conservative metadata guess; do not label both as “potentially conservative” without distinguishing their reasons. Retained mapped code prevents an absence justification for that code, but does not by itself prove vulnerability applicability or exploitability. Conversely, a requested ban does not establish `vulnerable_code_not_present` until final artifact contents and mapping identity have been verified.

Offer feature-selection/regeneration guidance first, then a ban only as an explicit policy experiment that may fail. “Solely retained by Spring metadata” requires complete root provenance and transitive closure, not just one direct-root label. If removing that contribution still leaves a generated reference, resource, source constraint, or graph promotion, show that blocker.

#### Local Feasibility Probe (2026-11-01)

An isolated Java probe ran against the cached Spring Framework **6.1.14** JARs on **GraalVM JDK 21.0.12+7.1**, without changing production code. It registered a `@Configuration(proxyBeanMethods=false)` with a lazy bean, an always-false conditional factory method, and a static `BeanFactoryInitializationAotProcessor` bean. It invoked `ApplicationContextAotGenerator.processAheadOfTime`, wrote generated sources through `DefaultGenerationContext`, and inspected the original configuration with `javap -p -c`.

| Observation | Result | Consequence |
| :--- | :--- | :--- |
| Lazy application bean | Definition and generated registration present; constructor count 0. | No workload-demand pruning. |
| False conditional factory method | Definition and generated registration absent. | Spring can select the registration set. |
| Infrastructure processor | Constructor count 1; no generated registration for that processor. | AOT can instantiate infrastructure and deliberately omit its runtime registration. |
| Original configuration bytecode | Conditional method and its `new RejectedBean` reference remain. | Class-level link closure may retain the rejected bean's dependency even after AOT registration removal. |

This verifies Spring registration behavior, not end-to-end Elider pruning, native-image compatibility, or savings. Promote these scenarios into shared integration fixtures before implementing subtractive AOT roots; retain separate runtime assertions for the lazy and conditional paths.

### 3.3 Descriptor Coherence and Link Closure

When trimming a Spring JAR (such as `spring-boot-autoconfigure.jar` in an AOT-backed build where unreferenced `*AutoConfiguration.class` entries are omitted), filter `AutoConfiguration.imports` and autoconfigure metadata only after final retained classes are known. Remove an entry only when its owner belonged to the input archive and was actually removed; preserve external registrations, `wasProcessed` lookup integrity for active `.AutoConfigureBefore`/`.AutoConfigureAfter` targets, and Java `Properties` escaping/continuations. Treat `spring.factories` registrations by key so non-auto-configuration listeners, initializers, and environment processors are preserved.

A separate limitation remains: removing a metadata root does not subtract hard references discovered from a retained class, method, or annotation (for example, `spring-webmvc`'s hard bytecode references from `InternalResourceViewResolver` or `RequestMappingHandlerAdapter`). Measure this effect separately.

## 4. Startup Evidence and JVM Acceleration

### 4.1 A Bounded Trace Goal

A proposed `dependency-elider:trace` goal could orchestrate a compiled baseline application and record class-load or execution evidence. It does not exist yet. Keep AOT generation and runtime recording as distinct operations with separate outputs and success criteria; use Boot's supported Maven workflow for generation before considering a direct processor wrapper.

In [Framework 6.1.14 `DefaultLifecycleProcessor`](https://github.com/spring-projects/spring-framework/blob/v6.1.14/spring-context/src/main/java/org/springframework/context/support/DefaultLifecycleProcessor.java), `spring.context.exit=onRefresh` calls `Runtime.halt(0)` before lifecycle beans start. Eager initialization may already perform I/O; lazy beans, runners, lifecycle startup, request handling, and normal shutdown are not covered. Do not promise an entirely side-effect-free or port-free run for arbitrary application code.

The recorder needs a timeout, exit-status handling, output validation, and a documented coverage marker. Test flushing for each recorder, particularly JFR or agents relying on shutdown hooks; a zero exit code is insufficient. Test the actual HotSpot class-list syntax against [`CdsClassListReader`](../../elider-core/src/main/java/io/github/spockz/elider/trace/CdsClassListReader.java), whose current normalized-name parser does not support every extended class-list entry.

Union startup observations with representative HTTP/message workloads, lazy beans, scheduled tasks, error/retry paths, health/metrics, and shutdown where relevant. Preserve workload labels and coverage gaps. A short startup run can also load optional classes merely while probing conditions; neither presence nor absence in that trace establishes application demand.

### 4.2 Train Caches After Packaging

Preferred order: **final elision and AOT validation → package/repackage → extract deployment → train → verify cache use**. Boot's [3.3 CDS workflow](https://docs.spring.io/spring-boot/3.3/reference/packaging/class-data-sharing.html) trains an extracted application and permits reuse while that application remains unchanged. Record the final dependency bytes, classpath order/layout, JDK, and launch options; do not reuse pre-trimming archives.

Static CDS (`-Xshare:dump` with `SharedClassListFile`) and dynamic CDS (`ArchiveClassesAtExit`) are separate workflows in the [JDK CDS documentation](https://docs.oracle.com/en/java/javase/21/vm/class-data-sharing.html). Filtering names from a trace does not recreate extended class-list IDs, loader/source information, or regenerate a `.jsa`. Prefer retraining; a sanitized-list exporter is a lower-priority feature requiring its own HotSpot round-trip tests.

Distinguish **Spring AOT** bean-code generation from the **JDK AOT cache**. [Current Boot AOT-cache documentation](https://docs.spring.io/spring-boot/reference/packaging/aot-cache.html) describes the Java 25+ `AOTCacheOutput`/`AOTCache` workflow. Evaluate that in a separately pinned Boot/JDK matrix; it is not a demonstrated capability of the Boot 3.3.5 fixture. Measure cache acceptance and contribution separately from Elider and Spring AOT.

## 5. JPMS and `jlink`: Useful Follow-ups, Separate Contracts

### 5.1 Execution Modes

A descriptor inside a JAR does not make ordinary classpath loading modular. Spring Boot's normal nested-JAR launch uses classloaders; explicit module-path deployments impose readability, exports, opens, and service rules. Hybrid launches need the intended modules resolved, often with `--add-modules`; compiler/test-plugin settings also matter. Spring documents its automatic module names and module-path considerations in the [Framework overview](https://docs.spring.io/spring-framework/reference/overview.html).

These facts justify prioritizing Boot AOT/classpath integration. They do not establish the original draft's claims about individual maintainers' motives, JPMS being designed only for one vendor, or custom module layers necessarily harming startup. Those claims are not needed for this design.

### 5.2 Descriptor-Aware Trimming (Including Classpath / Spring Boot Deployments)

Even when a Spring Boot application runs on the classpath in the unnamed module and never activates JPMS at runtime, `module-info.class` descriptors inside third-party dependencies directly affect trimming:

* **Root vs. Versioned `module-info.class` Asymmetry**:
  [`MultiReleaseArchiveWriter`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/MultiReleaseArchiveWriter.java) omits versioned module descriptors under `vertical-shade`. Root descriptors instead trigger pass-through or rejection in [`TrimPassThroughPlanner`](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimPassThroughPlanner.java) and [`ArchiveSnapshot`](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSnapshot.java). This is an independent trimming limit; AOT integration or dependency bans do not remove it.
* **Bounded Signals from `uses`/`provides`, Qualified `exports ... to ...`, and `requires static`**:
  * **`uses` and `provides`**: For modular dependencies, `uses` and `provides` record the library's declared `ServiceLoader` consumers and providers. Combined with scanning retained dependency bytecode for `ServiceLoader.load(...)` call sites, they help distinguish active SPI chains from dormant `META-INF/services/` descriptors (such as Jackson's `ObjectCodec` SPI in `CVE-2026-68494`). However, `uses`/`provides` are positive evidence, not a closed-world proof by themselves: [ServiceLoader](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/ServiceLoader.html) supports classloader and module-layer discovery, so unnamed callers, dynamically added `uses`/layers, and direct provider references must still be accounted for before removing providers or claiming `vulnerable_code_not_present`.
  * **Qualified `exports <pkg> to <target>`**: Restricts access for named-module consumers and may help explain a dependency relationship. It does not establish that the package is dead when the target is absent, and those access restrictions do not apply to the same JAR loaded on the ordinary classpath.
  * **`requires static`**: Identifies dependencies that the library author declared optional at runtime in the module system, helping classify optional companion links during link-closure analysis. Do **not** remove `requires` merely because no surviving bytecode names a target package (runtime discovery, resources, reflection, and readability can still depend on that module), and do not treat `requires static` alone as proof that an executed code path is safe without the target class.

A sanitizer for root `module-info.class` must preserve package, export/open, main-class, service/provider, and module-readability invariants across supported releases. `ModuleFinder` parsing alone is insufficient: resolve the graph and run actual module-path/service tests.

Local `jar tf` inspection on 2026-11-01 confirmed the following cached artifacts; this is an inventory observation, not a trimming benchmark:

| Artifact/version inspected | Descriptor location |
| :--- | :--- |
| `tomcat-embed-core:10.1.31` | Root `module-info.class` |
| `logback-core:1.5.11` | Root `module-info.class` |
| `jackson-annotations:2.17.2` | Root `module-info.class` |
| `slf4j-api:2.0.16` | `META-INF/versions/9/module-info.class` |

Two bounded designs are worth comparing:

| Design | Benefit | Contract/cost |
| :--- | :--- | :--- |
| Explicit classpath-only derivative | Remove descriptors from the derived runtime artifact and apply existing class-level trimming, avoiding a full JPMS sanitizer initially. | Opt-in deployment contract; never silently alter originals or publish the derivative as a general-purpose modular replacement. Reject unsupported module-path/layer consumers, preserve classpath services/resources, bind output/cache identity to this mode, and test consumers that inspect descriptor resources. |
| Descriptor-preserving derivative | Keep a named module with a descriptor consistent with the retained inventory. | Validate descriptor attributes and semantic resolution/service behavior, not just syntax. Preserve `requires` unless independently justified; do not promise original public API or `jlink` compatibility from `ModuleFinder` success alone. |

The classpath-only option is a proposal, not a current flag. It may yield more immediate Boot benefit than full modular support, but a Boot launch alone does not establish that no library creates a module layer. Both designs retain strict bytecode/resource checks and need a dedicated fixture before any size claim.

Current post-compile scanning reads module service declarations, but `PostCompileSourceAttribution` still rejects `module-info.java` and falls back conservatively. Therefore `productionClassesComplete=true` is not a claim of full modular attribution support. Preserve versioned descriptors for module-path consumers; keep source/module attribution and MRJAR descriptor rewriting as separate work under RQ-0017/RQ-0014.

### 5.3 JDK Module Suggestions

A classpath application can use a custom JDK image without linking its Spring dependency JARs as application modules. Analyze the final application classes, generated AOT classes, and retained dependencies with target-aware [`jdeps`](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jdeps.html); it can produce module dependencies for [`jlink`](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jlink.html).

Treat the result as a static candidate set. Add requirements discovered through reflection, service providers, resource bundles, security/crypto providers, JDBC/JNDI, agents, and deployment configuration; validate representative workloads on the linked runtime. Never hide unresolved links with `--ignore-missing-deps` and call the result complete. Generate CDS/AOT caches with that final runtime.

The proposed `target/dependency-elider-jdk-modules.txt` is not an existing output. Measure image bytes and startup/RSS changes before claiming savings. Smaller images and fewer scanner findings do not independently prove fewer exploitable vulnerabilities; use the evidence boundaries in ADR-0008.

## 6. Priorities, Experiments, and Acceptance Criteria

| Priority | Research question | Deliverable and benefit |
| :--- | :--- | :--- |
| Independent | **[WP-POLICY-01](../handovers/2026-10-31-wp-policy-01-global-dependency-exclusions-and-retained-artifacts-flip.md):** Rename retention and introduce a dual-layer dependency ban (`<banishedDependency>`). | Inject first-level Maven `Exclusion`s in `afterProjectsRead` before collection/mediation and enforce post-resolution link-closure/absence verification. Needed for executing bans, not for AOT ingestion or recommendations. |
| P0 | **RQ-0018.1:** How should AOT assets and startup/workload evidence enter Elider? | Directory-aware generated bytecode/resource ingestion, provenance, freshness, and lifecycle validation using existing parsers. |
| P0 | **RQ-0018.2:** Which Spring retention reasons can be explained and later replaced? | First distinguish conservative registrations, generated references, and workload coverage. Investigate scoped discovery-root replacement only after final AOT validation; retain other runtime infrastructure. |
| P1 | **RQ-0018.5:** Can pruning and final AOT generation agree on one deployment? | A bounded regeneration experiment, final-artifact AOT JVM tests, and independently verified native support. |
| P1 experiment | **RQ-0018.3a:** Can a classpath-only derivative remove root-descriptor pass-through safely? | Independent Boot trimming opportunity with an explicit non-modular output contract; compare against descriptor-preserving rewriting. |
| P2 | **RQ-0018.6:** Which explicit feature exclusions reduce the bean graph? | RQ-0005 recommendations explaining retained dependencies, followed by exclude/regenerate/test experiments. |
| P2 | **RQ-0018.4:** What do final-package CDS/AOT training and JDK module suggestions save? | Reproducible measurements and runtime validation; defer class-list rewriting until it has demonstrated value. |
| P3 | **RQ-0018.3:** What additional proofs permit modular trimming? | Module-path attribution, descriptor validation, resolution/service tests, and preserved JPMS contracts. |

### 6.1 Semantic Verification

* [ ] A generated bean/proxy reference, reflective DTO, resource bundle, and resource-only dependency survive trimming; an unrelated class is physically removed. Run the behavior that consumes each retained input.
* [ ] Positive-class and missing-class conditions retain their required outcomes, including string-valued checks and a fallback activated only after dependency removal. Include application/JDK/late-generated types, MRJAR visibility, and duplicate providers.
* [ ] An independently imported nested configuration survives an unsatisfied outer configuration. Missing metadata and incomplete visibility retain conservatively; malformed input fails explicitly. No archive-only or name-prefix condition evaluator is introduced.
* [ ] Reproduce the local probe's lazy-bean, infrastructure-creation, processor-exclusion, and surviving-method-reference observations in shared fixtures. A generated bean reference is not reported as merely conservative metadata or eliminated because a trace missed it.
* [ ] Successful bans satisfy both effective graph policy and class/resource/provider closure, including trim-disabled operation. Repeated Maven exclusions remain advisory candidates; no consumer-POM or mediation equivalence is claimed.
* [ ] Descriptor filtering preserves external registrations, non-auto-configuration factories, properties escaping/continuations, and both archive-writer paths. Report remaining hard-bytecode retention separately.
* [ ] Changed source/resource/profile/property/dependency/JDK inputs, stale generated outputs, and changes during consumption cannot reuse a prior bundle/cache as current evidence. Verify unsupported format handling and deterministic identities.
* [ ] Clean and incremental builds prove AOT execution order, no unmodeled later writer, and no resolver restoration of original dependencies. Test the ordinary and AOT-enabled packaged applications through relevant endpoint, lazy, operational, failure, and shutdown paths.
* [ ] Recorder timeout/nonzero exit/truncated output is rejected. Validate real `onRefresh` recording and cache acceptance on the pinned JDK; successful training is not substituted for full application tests.
* [ ] Native-image and linked-JRE claims each have their own build/runtime checks. VEX claims require their independent code-presence/reachability evidence.
* [ ] A classpath-only descriptor-removal experiment preserves classpath services/resources, keeps original dependency bytes intact, rejects unsupported modular use, and records its output contract in identity and provenance. Descriptor-preserving experiments additionally validate module resolution and services.

Share immutable fixtures and expensive runs across compatible assertions, using `assertAll` to preserve independent failures. Keep runs separate when runtime mode, classpath, profile, or lifecycle changes.

### 6.2 Measure the Combined Benefit

Use a controlled **Elider on/off × Spring AOT on/off × JVM cache on/off** comparison on one pinned JVM, with the same workload and deployment layout. Run native-image and linked-JRE comparisons separately. Record whole artifacts dropped, retained classes/resources and their reasons, packaged bytes, AOT/trimming/training build cost, cold and warm startup distributions, RSS, cache acceptance, and representative throughput/latency. Include no-op build overhead and cache invalidation cost.

Count package-level vulnerability finding changes separately from validated VEX conclusions. The existing Spring fixture and generated transcripts are baselines, not evidence for the proposed gains. When implementation changes the fixture or its commands/output, regenerate with `make update-transcripts` and verify with `make check-transcripts`; do not hand-edit transcript blocks.
