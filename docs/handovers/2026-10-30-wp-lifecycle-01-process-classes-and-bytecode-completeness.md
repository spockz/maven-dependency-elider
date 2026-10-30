<!-- WHY: Defines the work package specification, track decomposition, and step-by-step implementation guide for post-compile process-classes elision and production bytecode completeness (RQ-0017, ADR-0010). -->
# Work Package Handover: WP-LIFECYCLE-01 Post-Compile `process-classes` Execution & Production Bytecode Completeness

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-30
* **Target Branch / Base**: `main`
* **Related Research Questions**:
  * [RQ-0017: Source-Generation Lifecycle Integration and Post-Compile Bytecode Completeness](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md)
* **Related Architecture Decisions**:
  * [ADR-0010: Post-Compile `process-classes` Lifecycle Execution and Production Bytecode Completeness](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md)
  * [ADR-0001: Runtime Telemetry-Driven Dependency Elision at Maven INITIALIZE Phase](../adr/0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md)
  * [ADR-0008: Evidence-Bounded Precondition-Gated VEX Attestations](../adr/0008-precondition-gated-vex-attestations.md)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective

Enable full compile-scope dependency elision, intra-JAR trimming, and CVE/VEX reporting for Maven projects that use source generators (`generate-sources`) or annotation processors (`maven-compiler-plugin` `annotationProcessorPaths`, MapStruct, Lombok, OpenAPI, Protobuf, Avro, ANTLR) without failing closed or conservatively pinning 100% of compile-scoped dependencies.

Specifically:

1. **Production Bytecode Completeness (`elide.productionClassesComplete`)**:
   Add `@Parameter(property = "elide.productionClassesComplete", defaultValue = "false")` to `ElideMojo` and `AnalyzeMojo` (and auto-enable it when `ElideMojo` runs in the `process-classes` phase with `sourceRootsComplete=false`). When active, `MavenElisionService.compilerInputs` uses the `BytecodeReferenceScan` of `target/classes` (`ProductionBytecodeReferenceScanner`) instead of scanning raw `.java` sources or pinning all compile-visible JARs.
2. **Decouple Trimmer Platform Release Resolution from Source-Attribution Restrictions (`MavenCompilerSettings`)**:
   `MavenDependencyTrimmer` currently calls `MavenCompilerSettings.options(...)` solely to determine the target Java release (`--release` / `-target`) for `JdkPlatformContext`, which causes `MavenDependencyTrimmer` to crash whenever a project configures `annotationProcessorPaths`, `generatedSourcesDirectory`, `compilerArgs`, or a classpath annotation processor without `proc=none`. Introduce `MavenCompilerSettings.platformReleaseOptions(project, session)` for `MavenDependencyTrimmer` so bytecode trimming works on projects with annotation processors.
3. **Dynamic Phase Rebinding (`EliderLifecycleParticipant`) & `mvn dependency:tree` Support (`EliderTreePreparation`)**:
   Keep `ElideMojo` default phase at `LifecyclePhase.INITIALIZE` in `plugin.xml` for backwards compatibility, allow explicit `<phase>process-classes</phase>` in POM executions, and dynamically rebind `elide` executions from `null`/`initialize` to `process-classes` in `EliderLifecycleParticipant.afterProjectsRead(session)` when `elide.productionClassesComplete=true`. Update `EliderPluginConfiguration`, `EliderGoalOrder`, and `EliderTreePreparation` to support `process-classes`-bound executions (injecting `process-classes` before standalone `dependency:tree` requests).
4. **Phase-Relative Precondition Guards (`MavenPreconditionGenerationGuard` & `MavenCompilerGenerationGuard`)**:
   When `productionClassesComplete=true` at `process-classes`, phases `generate-sources` through `compile` have already completed and emitted `.class` files into `target/classes`. Update `MavenPreconditionInventory`, `MavenPreconditionProviderRoots`, `MavenPreconditionGenerationGuard`, and `MavenCompilerGenerationGuard` to allow pre-capture `generate-sources`..`compile` executions and `compile`-goal annotation processors when `productionClassesComplete=true`, while tightening `MavenElisionService.hasUnknownSourceGeneration` at `initialize` (`sourceRootsComplete=true`) to reject `annotationProcessorPaths`/`annotationProcessors`.

### 1.2 Non-Negotiable Invariants

1. **100% Backwards Compatibility for `initialize` Mode**: Existing tests (`DependencyContextLifecycleIntegrationTest`, `ADR0008MavenPreconditionInventoryTest`, `ADR0008MavenPreconditionPublicationTest`, `ElideMojoTest`, `AnalyzeMojoTest`, `examples/run-elision-cycle.sh`, and `make check-transcripts`) must continue to pass without regression.
2. **Mutual Exclusion & Fail-Closed Validation**:
   * Setting both `elide.sourceRootsComplete=true` and `elide.productionClassesComplete=true` must fail closed with an explicit `IOException`.
   * When `elide.productionClassesComplete=true`, `productionOutput` (defaulting to `${project.build.outputDirectory}`) must exist as a directory and contain at least one `.class` file (`scannedClassFileCount() > 0`), or analysis fails closed with an actionable message instructing the user to run `mvn compile` first or bind `elide` to `process-classes`.
3. **Static Link-Closure Soundness**: Static references in `target/classes` (including classes generated by MapStruct, Lombok, OpenAPI, etc.) must retain their owning compile-visible JARs in `compilerInputs` and transitively promote any reachable dependency in `MavenElisionService.finishAnalysis`.
4. **Persisted Format Policy (`AGENTS.md` / `ADR-0005`)**: Keep unreleased persisted schemas (such as `.trim-analysis-cache.json`) at their current schema version without adding legacy migration aliases.
5. **Tooling & Quality Gates (`AGENTS.md`)**: Strictly Java, shell, or Go. No Python or Node.js. All code must pass `make check` (Spotless, Checkstyle, PMD, SpotBugs, Markdownlint).

---

## 2. Track Decomposition & Execution Order

```text
┌──────────────────────────────────────────────────────────────────────┐
│ Track 1: Bytecode-Complete Attribution & Compiler Platform Options   │
│ (MavenCompilerSettings, MavenElisionService, MavenDependencyTrimmer, │
│  AnalyzeMojo, ElideMojo)                                             │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
┌──────────────────────────────────┐┌──────────────────────────────────┐
│ Track 2: Lifecycle Rebinding &   ││ Track 3: Phase-Relative          │
│ dependency:tree Preparation      ││ Precondition Proof Guards        │
│ (EliderLifecycleParticipant,     ││ (MavenPreconditionInventory,     │
│  EliderPluginConfiguration,      ││  MavenPreconditionProviderRoots, │
│  EliderGoalOrder,                ││  MavenPreconditionGenerationGuard│
│  EliderTreePreparation)          ││  MavenCompilerGenerationGuard)   │
└────────────────┬─────────────────┘└────────────────┬─────────────────┘
                 │                                   │
                 └─────────────────┬─────────────────┘
                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Track 4: Unit & Integration Tests and Quality Gate Verification      │
└──────────────────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> Because all four tracks modify package-private classes inside `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/`, a single worker can execute Tracks 1 $\rightarrow$ 2 $\rightarrow$ 3 $\rightarrow$ 4 sequentially in one branch/worktree, committing after each slice once `mvn test-compile` / `mvn test` passes.

---

## 3. Detailed Step-by-Step Implementation Guide

### Track 1: Bytecode-Complete Attribution & Compiler Platform Options

#### Slice 1.1: Decouple Platform Release Options in `MavenCompilerSettings.java`

**File**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenCompilerSettings.java`

* **Why**: `MavenDependencyTrimmer` calls `MavenCompilerSettings.options(...)` at lines 585, 606, and 729 only to extract `--release` or `-source`/`-target` via `releaseFromOptions(...)`. Calling `options(...)` invokes `rejectUnsupportedSettings` and `rejectAnnotationProcessors`, which throws an `IOException` if the project uses `annotationProcessorPaths`, `generatedSourcesDirectory`, `compilerArgs`, or classpath processors without `proc=none`.
* **What to change**:
  1. Keep `static List<String> options(MavenProject project, MavenSession session, List<String> compileClasspath)` unchanged for `JavaSourceReferenceScanner` (when `sourceRootsComplete=true`).
  2. Add a new package-private method `static List<String> platformReleaseOptions(final MavenProject project, final MavenSession session) throws IOException`:
     * Call `rejectSelectedToolchain(session);`
     * Resolve `final List<Xpp3Dom> configurations = compilerConfigurations(project);`
     * Call a helper `rejectUnsupportedPlatformSettings(configurations, project.getProperties(), session == null ? new Properties() : session.getUserProperties());` that rejects only settings that alter the compiling JDK or bytecode version (`executable`, `jdkToolchain`, `fork`, `enablePreview`, and non-`javac` `compilerId`, plus their `maven.compiler.*` property equivalents), **without** rejecting `annotationProcessorPaths`, `annotationProcessors`, `annotationProcessorPath`, `processorpath`, `generatedSourcesDirectory`, `compileSourceRoots`, `compilerArgs`, `compilerArgument`, `compilerArguments`, `includes`, `excludes`, `sourcepath`, `modulePath`, `modulepath`, `useModulePath`, or `proc`.
     * Resolve `release`, `source`, and `target` using the existing `value(...)` helper:
       * If `release != null && (source != null || target != null)`, throw `new IOException("Cannot attribute source with both compiler release and source/target")`.
       * If `release != null`, return `List.of("--release", release)`.
       * Else if `source != null && target != null`, return `List.of("-source", source, "-target", target)`.
       * Else throw `new IOException("Source attribution requires effective compiler release or source/target settings")`.
  3. Also add a package-private helper `static boolean hasConfiguredAnnotationProcessing(final MavenProject project)` to `MavenCompilerSettings` so `MavenElisionService.hasUnknownSourceGeneration(project)` can detect annotation processors configured on `maven-compiler-plugin`:
     * Inspect `compilerConfigurations(project)` and `project.getProperties()`:
       * Return `true` if any configuration child `annotationProcessorPaths`, `annotationProcessors`, `annotationProcessorPath`, `processorpath`, or `generatedSourcesDirectory` `hasValue(...)`.
       * Return `true` if `project.getProperties()` contains a non-blank value for `maven.compiler.annotationProcessorPaths`, `maven.compiler.annotationProcessors`, `maven.compiler.annotationProcessorPath`, `maven.compiler.processorpath`, or `maven.compiler. processorPath`.
       * Return `true` if `proc` (or `maven.compiler.proc` in `project.getProperties()`) is non-null, non-blank, and not equal (ignoring case) to `"none"`.
       * Otherwise return `false`.

#### Slice 1.2: Wire `productionClassesComplete` into `MavenElisionService.java`, `MavenElisionGraphBinding.java`, and `MavenDependencyTrimmer.java`

**File 1**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java`

1. **`AnalysisOptions` record** (around line 64):
   * Add `boolean productionClassesComplete` as the last component of `record AnalysisOptions`:

     ```java
     record AnalysisOptions(
         List<File> traceFiles,
         List<String> excludedArtifacts,
         File productionOutput,
         MavenSession session,
         boolean sourceRootsComplete,
         boolean trimJars,
         List<String> explicitTrimRoots,
         boolean failOnUnsupportedMultiRelease,
         List<String> explicitPassThroughArtifacts,
         boolean failOnUnsupportedModuleInfo,
         boolean testResolutionContext,
         boolean conservativeServiceLoaderRoots,
         int trimWorkers,
         boolean productionClassesComplete) {
     ```

   * Keep existing 13-argument, 12-argument, and 11-argument overloading constructors on `AnalysisOptions`, chaining to `this(..., false)` so all existing callers and test fixtures compile without modification.
2. **`MavenElisionService.prepare(...)`** (around lines 230–295):
   * Read `final boolean productionClassesComplete = options.productionClassesComplete();`
   * Validate mutual exclusion right at the start of `prepare`:

     ```java
     if (sourceRootsComplete && productionClassesComplete) {
       throw new IOException(
           "elide.sourceRootsComplete=true and elide.productionClassesComplete=true are mutually exclusive");
     }
     ```

   * Move `final ProductionBytecodeInputs productionInputs = productionBytecodeInputs(productionOutput, productionClassesComplete);` **before** `compilerInputs(...)`.
   * Update `productionBytecodeInputs(final File output, final boolean productionClassesComplete)`:
     * If `output == null`:
       * If `productionClassesComplete` is `true`, throw `new IOException("elide.productionClassesComplete=true requires a production class output directory")`.
       * Otherwise return `new ProductionBytecodeInputs("none", Optional.empty())`.
     * Scan `output` as before into `BytecodeReferenceScan scan`.
     * If `productionClassesComplete && scan.scannedClassFileCount() == 0`:
       throw `new IOException("elide.productionClassesComplete=true requires compiled production class files in " + output.toPath().toAbsolutePath().normalize() + "; run 'mvn compile' first or bind to process-classes")`.
   * Pass `productionClassesComplete` and `productionInputs.scan()` into `compilerInputs(...)`:

     ```java
     final CompilerInputs compilerInputs =
         compilerInputs(
             project,
             session,
             scanCandidates,
             index,
             sourceRootsComplete,
             productionClassesComplete,
             productionInputs.scan());
     ```

3. **`MavenElisionService.compilerInputs(...)`** (around lines 913–965):
   * Add parameters `final boolean productionClassesComplete` and `final Optional<BytecodeReferenceScan> bytecodeScan`.
   * When `sourceRootsComplete` is `true`:
     * Keep existing `JavaSourceReferenceScanner` logic.
   * Else when `productionClassesComplete` is `true`:
     * Obtain `final BytecodeReferenceScan scan = bytecodeScan.orElseThrow(() -> new IOException("elide.productionClassesComplete=true requires a production bytecode scan"));`
     * `requiredClasses.addAll(scan.referencedClasses());`
     * `compileVisibleArtifacts.removeIf(artifact -> !sourceClassesByArtifact(artifact, requiredClasses, indexedClasses));`
     * `final Set<String> declaredClasses = classNamesInOutput(scan.scope());`
     * Return `new CompilerInputs(compileVisibleArtifacts.stream().map(ArtifactFileRef::coordinate).collect(java.util.stream.Collectors.toSet()), requiredClasses, declaredClasses);`
   * Else (`!sourceRootsComplete && !productionClassesComplete`):
     * Keep existing conservative fallback (`compileVisibleArtifacts.forEach(artifact -> requiredClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));`).
4. **Tighten `hasUnknownSourceGeneration(MavenProject)` and `verifySourceRootsComplete(...)`** (around lines 980–1014):
   * In `hasUnknownSourceGeneration(final MavenProject project)`:
     * After checking `build == null || ...`, also check:

       ```java
       if (MavenCompilerSettings.hasConfiguredAnnotationProcessing(project)) {
         return true;
       }
       ```

   * In `verifySourceRootsComplete`:
     * Update the error message when `hasUnknownSourceGeneration(project)` is `true` so it still contains the substring `"elide.sourceRootsComplete=true conflicts with a source-generation lifecycle execution"` (required by `MavenElisionServiceTest.completeSourceRootsRejectUnknownSourceGenerationExecution`) while appending actionable guidance:

       ```java
       throw new IOException(
           "elide.sourceRootsComplete=true conflicts with a source-generation lifecycle execution; "
               + "use -Delide.productionClassesComplete=true (or bind dependency-elider:elide to "
               + "process-classes) to analyze compiled bytecode");
       ```

5. **Expose `productionClassesComplete` on `MavenElisionService.Analysis`**:
   * Add `boolean productionClassesComplete` as a component on `record Analysis` (defaulting to `false` in legacy convenience constructors, and populated from `prepared.options().productionClassesComplete()` in `finish(PreparedAnalysis)` and `finishEffectiveOutputs(EffectiveAnalysis)`).

**File 2**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionGraphBinding.java`

* In `operationFingerprint(...)` (around line 163), add `fields.add(Boolean.toString(options.productionClassesComplete()));` right after `fields.add(Boolean.toString(options.sourceRootsComplete()));`.

**File 3**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenDependencyTrimmer.java`

1. In `stageEffectiveOutputs` (line 585), `trim` (line 606), and `analyzeInMemory` (line 729):
   * Replace `MavenCompilerSettings.options(project, session, compileClasspath)` with `MavenCompilerSettings.platformReleaseOptions(project, session)`!
2. In `EffectiveOutputPlan` (line 179), `EffectiveCacheIdentity` (line 308), `stageEffectiveOutputs` (line 572), and `effectiveCacheKey` (line 1978):
   * Include `boolean productionClassesComplete` alongside `boolean sourceRootsComplete` so cache entries distinguish `productionClassesComplete` runs. (Per `ADR-0005`, keep `EffectiveCacheIdentity` schema integer at `2`, do not increment).

#### Slice 1.3: Add `productionClassesComplete` to `AnalyzeMojo.java` and `ElideMojo.java`

**File 1**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java`

1. Add field:

   ```java
   /** Uses compiled production bytecode in target/classes to attribute compile dependencies. */
   @Parameter(property = "elide.productionClassesComplete", defaultValue = DEFAULT_FALSE)
   private boolean productionClassesComplete;
   ```

2. Add helper method `private File effectiveProductionOutput()`:
   * If `productionOutput != null`, return `productionOutput`.
   * If `productionClassesComplete && project != null && project.getBuild() != null && project.getBuild().getOutputDirectory() != null && !project.getBuild().getOutputDirectory().isBlank()`:
     return `new File(project.getBuild().getOutputDirectory())`.
   * Return `null`.
3. In `execute()`, pass `effectiveProductionOutput()` and `productionClassesComplete` into `new MavenElisionService.AnalysisOptions(...)`.

**File 2**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java`

1. Add constant `private static final String PROCESS_CLASSES_PHASE = "process-classes";` and field:

   ```java
   /** Uses compiled production bytecode in target/classes to attribute compile dependencies. */
   @Parameter(property = "elide.productionClassesComplete", defaultValue = DEFAULT_FALSE)
   private boolean productionClassesComplete;
   ```

2. Add helper `private boolean effectiveProductionClassesComplete()`:
   * Return `productionClassesComplete || (!sourceRootsComplete && mojoExecution != null && PROCESS_CLASSES_PHASE.equals(mojoExecution.getLifecyclePhase()))`.
3. Add helper `private File effectiveProductionOutput(final boolean bytecodeComplete)`:
   * If `productionOutput != null`, return `productionOutput`.
   * If `bytecodeComplete && project != null && project.getBuild() != null && project.getBuild().getOutputDirectory() != null && !project.getBuild().getOutputDirectory().isBlank()`:
     return `new File(project.getBuild().getOutputDirectory())`.
   * Return `null`.
4. In `analysisOptions()`, compute `final boolean bytecodeComplete = effectiveProductionClassesComplete();` and pass `effectiveProductionOutput(bytecodeComplete)` and `bytecodeComplete` into `new MavenElisionService.AnalysisOptions(...)`.

---

### Track 2: Lifecycle Rebinding & `dependency:tree` Preparation

#### Slice 2.1: Support `process-classes` in `EliderPluginConfiguration.java`, `EliderLifecycleParticipant.java`, `EliderGoalOrder.java`, and `EliderTreePreparation.java`

**File 1**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderPluginConfiguration.java`

1. Add constants:

   ```java
   static final String INITIALIZE_PHASE = "initialize";
   static final String PROCESS_CLASSES_PHASE = "process-classes";
   private static final String PRODUCTION_CLASSES_COMPLETE_PROP = "elide.productionClassesComplete";
   ```

2. Add a package-private method `static void rebindProcessClassesIfConfigured(final MavenSession session) throws MavenExecutionException`:
   * Iterate over `active(session)`. For each `ElideConfiguration`:
     * For each `PluginExecution execution` in `configuration.executions()`:
       * Check if `isProductionClassesCompleteConfigured(session, configuration.project(), configuration.plugin(), execution)` is `true` and `!isSourceRootsCompleteConfigured(session, configuration.project(), configuration.plugin(), execution)`:
         * If `execution.getPhase() == null || execution.getPhase().isBlank() || INITIALIZE_PHASE.equals(execution.getPhase())`:
           call `execution.setPhase(PROCESS_CLASSES_PHASE);`
   * How `isProductionClassesCompleteConfigured` checks configuration (in priority order):
     1. Execution `<configuration>` child `<productionClassesComplete>` (`Xpp3Dom`).
     2. Plugin `<configuration>` child `<productionClassesComplete>` (`Xpp3Dom`).
     3. `session.getUserProperties().getProperty("elide.productionClassesComplete")`.
     4. `session.getSystemProperties().getProperty("elide.productionClassesComplete")`.
     5. `project.getProperties().getProperty("elide.productionClassesComplete")`.
     * Resolve simple `${property}` interpolation if present, and check `"true".equalsIgnoreCase(value.trim())`.
3. Update `requireInitializeBinding(final PluginExecution execution, final MavenProject project)` (keep method name or add `requireSupportedBinding` and delegate from `requireInitializeBinding` so callers compile):
   * Resolve effective phase: `final String phase = effectivePhase(execution);` where `effectivePhase` returns `INITIALIZE_PHASE` if `execution.getPhase() == null || execution.getPhase().isBlank()`, otherwise `execution.getPhase().trim()`.
   * Allow both `INITIALIZE_PHASE` (`"initialize"`) and `PROCESS_CLASSES_PHASE` (`"process-classes"`).
   * If neither matches, throw:

     ```java
     throw failure(
         project,
         "Automatic dependency:tree preparation requires dependency-elider:elide bound to "
             + INITIALIZE_PHASE
             + " or "
             + PROCESS_CLASSES_PHASE
             + " (found "
             + phase
             + ")");
     ```

**File 2**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java`

* In `afterProjectsRead(final MavenSession session)`:

  ```java
  @Override
  public void afterProjectsRead(final MavenSession session) throws MavenExecutionException {
    EliderPluginConfiguration.rebindProcessClassesIfConfigured(session);
    EliderTreePreparation.schedule(session);
  }
  ```

**File 3**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderGoalOrder.java`

* Currently `PREPARED_PHASES` lists all phases from `"initialize"` to `"deploy"`.
* Add a phase-ordered list `LIFECYCLE_PHASES`:

  ```java
  private static final List<String> LIFECYCLE_PHASES =
      List.of(
          "initialize",
          "generate-sources",
          "process-sources",
          "generate-resources",
          "process-resources",
          "compile",
          "process-classes",
          "generate-test-sources",
          "process-test-sources",
          "generate-test-resources",
          "process-test-resources",
          "test-compile",
          "process-test-classes",
          "test",
          "prepare-package",
          "package",
          "pre-integration-test",
          "integration-test",
          "post-integration-test",
          "verify",
          "install",
          "deploy");
  ```

* Overload `hasPreparedLifecycleAfter(final List<String> goals, final int lastCleanIndex, final int treeIndex, final String requiredPhase)`:
  * A goal in `goals.subList(lastCleanIndex + 1, treeIndex)` satisfies `requiredPhase` iff `LIFECYCLE_PHASES.indexOf(goal) >= LIFECYCLE_PHASES.indexOf(requiredPhase)`.
  * Keep the 3-argument `hasPreparedLifecycleAfter(goals, lastCleanIndex, treeIndex)` delegating with `"initialize"` for backwards compatibility.
* Update `validateCleanOrdering(final List<String> goals, final int treeIndex, final MavenProject project, final String requiredPhase)` (with 3-arg overload delegating with `"initialize"`).

**File 4**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderTreePreparation.java`

* In `scheduleTreePreparation`:
  * Determine `final PluginExecution execution` from `configuration.executions()` first (validating `ONE_CONFIGURED_EXECUTION` and `requireInitializeBinding` / `requireExecutionIdentity`).
  * Determine `final String boundPhase = EliderPluginConfiguration.effectivePhase(execution);` (`"initialize"` or `"process-classes"`).
  * Validate clean ordering and check `EliderGoalOrder.hasPreparedLifecycleAfter(goals, lastCleanIndex, treeIndex, boundPhase)`.
  * When injecting before `treeIndex`:
    * If `EliderPluginConfiguration.PROCESS_CLASSES_PHASE.equals(boundPhase)`:
      inject `EliderPluginConfiguration.PROCESS_CLASSES_PHASE` (`"process-classes"`) before `treeIndex` so Maven runs the lifecycle up to `process-classes` (including `generate-sources`, `compile`, and the `process-classes`-bound `elide` execution), and do **not** set `EliderPreparationState.PREPARATION_STATE_KEY` (because `process-classes` is a lifecycle phase, not a synthetic duplicate CLI Mojo invocation!).
    * Else (`"initialize"`):
      keep the exact existing behavior (inject `EliderGoalMatcher.configuredElideGoal(configuration.plugin(), execution)` and record `EliderPreparationState.pending(...)`).

---

### Track 3: Phase-Relative Precondition Proof Guards

#### Slice 3.1: Update `MavenPreconditionInventory.java`, `MavenPreconditionProviderRoots.java`, `MavenPreconditionGenerationGuard.java`, and `MavenCompilerGenerationGuard.java`

**File 1**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionInventory.java`

* In `captureInternal(...)` (around line 185):
  * Pass `analysis.productionClassesComplete()` to `MavenCompilerGenerationGuard`:

    ```java
    MavenCompilerGenerationGuard.requireSafeCompilerConfiguration(
        project, session, analysis.productionClassesComplete());
    ```

**File 2**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionProviderRoots.java`

* In `capture(...)` (around lines 66–69):
  * Pass `analysis.productionClassesComplete()` to `MavenPreconditionGenerationGuard`:

    ```java
    MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
        project, session, analysis.productionClassesComplete());
    if (!analysis.productionClassesComplete()
        && MavenElisionService.hasUnknownSourceGeneration(project)) {
      throw new IOException(MAVEN_PREFIX + "build has an unsupported or unknown source generator");
    }
    ```

* In `declaredRoots(...)` (around lines 96–108):
  * When `analysis.productionClassesComplete()` is `true`, generators in `generate-sources` may have emitted non-Java marker files (e.g., `.openapi-generator/VERSION`, `.proto` metadata, or properties) under `target/generated-sources/*` or registered custom compile source roots under `target/generated-sources/*`.
  * Keep scanning all existing `.java` files in `project.getCompileSourceRoots()`, or in `scanRoot(...)` when `analysis.productionClassesComplete()` is `true` and `source == true`, filter `members` to `.java` files or only scan declared source roots when `!analysis.productionClassesComplete()` while always scanning `production-output` (`target/classes`), `test-source`, `test-output`, `production-resource`, and `test-resource`!
  * Wait: let's check what `ADR0008MavenPreconditionInventoryTest` expects for `MavenPreconditionProviderRoots`!
    In `ADR0008MavenPreconditionInventoryTest`, all existing tests run with `analysis.productionClassesComplete() == false`. So keeping `declaredRoots` identical when `!analysis.productionClassesComplete()`, and when `analysis.productionClassesComplete()` is `true`, still scanning `declaredRoots` (while allowing pre-`process-classes` source generator executions in `MavenPreconditionGenerationGuard`) preserves 100% of `ADR0008` provider inventory semantics!

**File 3**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java`

1. Add constant `private static final String PHASE_PROCESS_CLASSES = "process-classes";`.
2. Overload `requireKnownProviderGeneration(final MavenProject project, final MavenSession session)` to delegate to `requireKnownProviderGeneration(project, session, false)`.
3. In `requireKnownProviderGeneration(final MavenProject project, final MavenSession session, final boolean productionClassesComplete)`:
   * Pass `productionClassesComplete` to `requireSafeGoalOrder(session, productionClassesComplete)` and `inspectConfiguredPlugins(project, session, build, requestedPhaseIndex, productionClassesComplete)`.
4. In `requireSafeGoalOrder(final MavenSession session, final boolean productionClassesComplete)`:
   * The minimum required lifecycle phase is `productionClassesComplete ? PHASE_PROCESS_CLASSES : PHASE_INITIALIZE`.
   * If `phaseIndex < LIFECYCLE_PHASES.indexOf(minimumPhase) || UNMODELED_CLEAN_SITE_PHASES.contains(defaultPhase)`, throw `unsupported("Maven goal sequence is not a safe default lifecycle invocation")`.
5. In `inspectPluginExecution(...)` (around lines 1206–1211):
   * When `productionClassesComplete` is `true`, any non-Shade, non-Surefire, non-Clean/Site plugin execution whose resolved `phaseIndex` is strictly after `validate` and strictly before `process-classes` (`phaseIndex >= LIFECYCLE_PHASES.indexOf(PHASE_INITIALIZE) && phaseIndex <= LIFECYCLE_PHASES.indexOf(PHASE_COMPILE)`) has **already completed** before `process-classes` inventory capture!
   * Specifically, if `productionClassesComplete && phaseIndex >= LIFECYCLE_PHASES.indexOf(PHASE_INITIALIZE) && phaseIndex <= LIFECYCLE_PHASES.indexOf(PHASE_COMPILE)` and the plugin is not `maven-enforcer-plugin`, `maven-surefire-plugin`, `maven-shade-plugin`, `maven-jar-plugin`, or `maven-clean-plugin`, return safely (because its generated sources and compiled `.class` files in `target/classes` are already present and hashed at `process-classes`).
6. In `requireSupportedExecution(...)` (around lines 1322–1327):
   * Allow `dependency-elider-maven-plugin` execution when `PHASE_INITIALIZE.equals(execution.getPhase()) || (productionClassesComplete && PHASE_PROCESS_CLASSES.equals(execution.getPhase()))`.

**File 4**: `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenCompilerGenerationGuard.java`

1. Overload `requireSafeCompilerConfiguration(final MavenProject project, final MavenSession session)` to delegate to `requireSafeCompilerConfiguration(project, session, false)`.
2. In `requireSafeCompilerConfiguration(final MavenProject project, final MavenSession session, final boolean productionClassesComplete)`:
   * When `productionClassesComplete` is `false`: run the exact existing checks unchanged.
   * When `productionClassesComplete` is `true`:
     * `CompileGoal.COMPILE` has already completed prior to `process-classes`, and all resulting `.class` files in `target/classes` are directly inventoried and hashed by `MavenPreconditionProviderRoots`.
     * Require supported compiler plugin version (`requireSupportedCompilerPluginVersion`) and target levels (`requireSupportedTargetLevels`), and if `testCompile` will run (`!isTestsSkipped(project, session)`), still require safe `TEST_COMPILE` configuration; for `COMPILE`, permit `annotationProcessorPaths`, `annotationProcessors`, `generatedSourcesDirectory`, `compilerArgs`, and processor discovery (`proc` not required to be `none`).

---

### Track 4: Unit & Integration Tests and Quality Gate Verification

#### Slice 4.1: Unit Tests for Track 1, Track 2, and Track 3

Add focused unit tests covering all new behaviors:

1. **`MavenElisionServiceTest.java`**:
   * `productionClassesCompleteRetainsOnlyBytecodeReferencedCompileDependenciesAndAllowsSourceGenerators()`:
     * Configure a `MavenProject` with two `compile`-scoped JARs (`compile-used.jar` containing `library.Used`, `compile-unused.jar` containing `library.Unused`), a `generate-sources` plugin execution (e.g., `org.openapitools:openapi-generator-maven-plugin` or `org.codehaus.mojo:build-helper-maven-plugin`), and `maven-compiler-plugin` with `<annotationProcessorPaths>`.
     * Write a compiled `.class` file in `target/classes` (`app/GeneratedMapperImpl.class`) that references `library.Used`.
     * Run `MavenElisionService.analyze` with `productionClassesComplete=true` and `sourceRootsComplete=false`.
     * Assert `compile-used` is retained and `compile-unused` is **elided**!
   * `productionClassesCompleteFailsClosedWhenOutputDirectoryHasNoClassFiles()`:
     * Pass an empty `target/classes` directory with `productionClassesComplete=true`; assert `IOException` with message containing `"requires compiled production class files"`.
   * `productionClassesCompleteAndSourceRootsCompleteAreMutuallyExclusive()`:
     * Pass both `sourceRootsComplete=true` and `productionClassesComplete=true`; assert `IOException` with message containing `"mutually exclusive"`.
   * `completeSourceRootsRejectCompilerAnnotationProcessorPaths()`:
     * Configure `maven-compiler-plugin` with `<annotationProcessorPaths>` and `sourceRootsComplete=true`; assert `IOException` with message containing `"source-generation lifecycle execution"`.

2. **`AnalyzeMojoTest.java` & `ElideMojoTest.java`**:
   * In `AnalyzeMojoTest`: verify that setting `productionClassesComplete=true` with `project.getBuild().setOutputDirectory(...)` automatically uses `target/classes` without needing explicit `productionOutput`, and reports elided `compile`-scoped JARs and avoided CVEs.
   * In `ElideMojoTest`: verify that when `mojoExecution.getLifecyclePhase()` is `"process-classes"` (and `sourceRootsComplete=false`), `ElideMojo` automatically activates `productionClassesComplete`, trims/elides `compile`-scoped dependencies even when `annotationProcessorPaths` is configured on `maven-compiler-plugin`, and does not fail in `MavenDependencyTrimmer`.

3. **`EliderLifecycleParticipant` & `EliderTreePreparation` Tests**:
   * Verify that `EliderLifecycleParticipant.afterProjectsRead` rebinds an `elide` execution from `null`/`initialize` to `process-classes` when `-Delide.productionClassesComplete=true` is set.
   * Verify that `EliderTreePreparation.schedule` accepts a `process-classes`-bound `elide` execution and injects `"process-classes"` before `"dependency:tree"`.

4. **`ADR0008MavenPreconditionInventoryTest.java`**:
   * Verify that when `productionClassesComplete=true` and session goal is `"process-classes"` (or `"package"` with `clean` prelude), a project with a `generate-sources` plugin execution and `annotationProcessorPaths` produces a `COMPLETE` `PreconditionClassInventory` snapshot.

---

## 4. Verification Matrix & Acceptance Criteria

Run the following commands in order:

```bash
# 1. Run plugin unit tests
./mvnw test -pl dependency-elider-maven-plugin

# 2. Run full static analysis and formatting gate
make check

# 3. Verify command transcripts have not drifted
make check-transcripts
```

### Acceptance Criteria

1. **Post-Compile Bytecode Attribution**: Projects with `generate-sources` plugins or `maven-compiler-plugin` `annotationProcessorPaths` elide unused `compile`-scoped dependencies and trim retained JARs when `elide.productionClassesComplete=true` or when `elide` executes in `process-classes`.
2. **Trimmer Compatibility with Annotation Processors**: `MavenDependencyTrimmer` resolves `--release` / `-target` via `MavenCompilerSettings.platformReleaseOptions` without failing on `annotationProcessorPaths`, `compilerArgs`, or processor services on the compile classpath.
3. **Dynamic Phase Rebinding & Tree Preparation**: Setting `-Delide.productionClassesComplete=true` dynamically rebinds `elide` to `process-classes` in `EliderLifecycleParticipant`, and `EliderTreePreparation` injects `process-classes` before standalone `dependency:tree` requests.
4. **Phase-Relative Precondition VEX**: `MavenPreconditionInventory` produces a `COMPLETE` snapshot at `process-classes` for projects using `generate-sources` and `compile` annotation processors, while `sourceRootsComplete=true` at `initialize` rejects `annotationProcessorPaths`.
5. **Zero Regressions**: All existing unit tests, lifecycle integration tests, precondition tests, and `make check` pass with 0 errors.
