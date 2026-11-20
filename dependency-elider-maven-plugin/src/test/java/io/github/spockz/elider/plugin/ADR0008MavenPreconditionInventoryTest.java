// WHY: Verifies Maven inventory capture includes declared providers and rejects membership drift.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.applicability.PreconditionClassInventory;
import io.github.spockz.elider.applicability.PreconditionClassInventory.Provider;
import io.github.spockz.elider.applicability.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.applicability.PreconditionProof;
import io.github.spockz.elider.applicability.PrerequisiteProofResult;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.PrerequisiteAbsenceAttribution;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.model.PluginManagement;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** WHY: Groups provider inventory cases around one shared fixture. */
@DisplayName("ADR-0008: Maven precondition inventory completeness and freshness")
@Isolated("The javac plugin fixture communicates with a compiler through a JVM system property")
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "checkstyle:AbbreviationAsWordInName"
})
final class ADR0008MavenPreconditionInventoryTest {
  /** WHY: These names identify Maven lifecycle goals and plugin configuration. */
  private static final String TEST = "test";

  /** WHY: Test compiler goal entries are matched by their exact Maven name. */
  private static final String GOAL_TEST_COMPILE = "testCompile";

  /** WHY: Maven plugin configuration uses this exact skip key. */
  private static final String SKIP = "skip";

  /** WHY: Test resources execute in this Maven lifecycle phase. */
  private static final String PROCESS_TEST_RESOURCES = "process-test-resources";

  /** Maven artifact type used by all provider fixtures. */
  private static final String JAR_TYPE = "jar";

  /** Lifecycle phase used to prove trusted production capture boundaries. */
  private static final String PROCESS_CLASSES_PHASE = "process-classes";

  /** Shared failure text for stale provider snapshots. */
  private static final String INVENTORY_CHANGED = "provider inventory changed";

  /** WHY: Maven model fixtures use one stable example coordinate namespace. */
  private static final String EXAMPLE_GROUP = "com.example";

  /** WHY: Legacy provider fixtures use this Maven group identity. */
  private static final String ORG_EXAMPLE_GROUP = "org.example";

  /** WHY: Repeated version fixtures represent the same Maven artifact version. */
  private static final String TEST_VERSION = "1.0";

  /** WHY: The javac provider fixture uses one stable vulnerability identity. */
  private static final String TEST_CVE = "CVE-2026-12345";

  /** WHY: The vulnerable mapping fixtures all target the same single version. */
  private static final String TEST_RANGE = "[1.0]";

  /** WHY: The exact prerequisite identity is shared by proof scenarios. */
  private static final String PREREQUISITE_COORDINATE = "org.example:missing-prerequisite";

  /** WHY: Maven names the test compiler lifecycle execution with this ID. */
  private static final String DEFAULT_TEST_COMPILE = "default-testCompile";

  @SuppressWarnings("PMD.CommentRequired")
  private static final String MAVEN_TEST_SKIP = "maven.test.skip";

  /** WHY: Maven lifecycle fixture goals are asserted by exact names. */
  private static final String GOAL_CLEAN = "clean";

  /** WHY: Maven plugin fixtures use the canonical plugin group ID. */
  private static final String MAVEN_PLUGIN_GROUP = "org.apache.maven.plugins";

  /** Maven's standard resources plugin key used by phase guard fixtures. */
  private static final String MAVEN_RESOURCES_PLUGIN = "maven-resources-plugin";

  /** WHY: Maven lifecycle fixture goals are asserted by exact names. */
  private static final String GOAL_VERIFY = "verify";

  /** WHY: Maven property fixtures distinguish exact boolean values. */
  private static final String TRUE = "true";

  /** WHY: Maven lifecycle fixture goals are asserted by exact names. */
  private static final String GOAL_SITE = "site";

  /** WHY: Maven lifecycle fixture goals are asserted by exact names. */
  private static final String GOAL_PACKAGE = "package";

  /** WHY: Surefire property fixtures use the canonical skip option. */
  private static final String SKIP_TESTS = "skipTests";

  /** WHY: Maven property fixtures distinguish exact boolean values. */
  private static final String FALSE = "false";

  /** WHY: Compiler guard fixtures set the shared processor mode property. */
  private static final String PROCESSING_PROPERTY = "maven.compiler.proc";

  /** WHY: Javac writes the generated class through this key. */
  private static final String JAVAC_PLUGIN_OUTPUT_PROPERTY = "elider.test.javacPluginOutput";

  /** WHY: Compiler guard fixtures distinguish processor modes. */
  private static final String PROCESSING_FULL = "full";

  /** WHY: Compiler config fixtures use the Maven compiler option name. */
  private static final String PROCESSING_SETTING = "proc";

  /** WHY: Compiler guard fixtures distinguish processor modes. */
  private static final String PROCESSING_NONE = "none";

  /** WHY: Maven names the default compiler lifecycle execution with this ID. */
  private static final String DEFAULT_COMPILE = "default-compile";

  /** WHY: Maven lifecycle fixture goals are asserted by exact names. */
  private static final String GOAL_COMPILE = "compile";

  /** WHY: Maven Xpp3Dom fixtures use this canonical element name. */
  private static final String CONFIGURATION_ELEMENT = "configuration";

  /** WHY: Compiler processor paths must remain scoped to default compile. */
  private static final String ANNOTATION_PROCESSOR_PATHS = "annotationProcessorPaths";

  /** WHY: This compiler flag must be rejected as an argument channel. */
  private static final String PROCESSOR_FLAG = "-proc:full";

  /** WHY: Enforcer fixtures target Maven's built-in plugin coordinates. */
  private static final String ENFORCER_PLUGIN = "maven-enforcer-plugin";

  /** WHY: Shade config fixtures identify the transformer container. */
  private static final String SHADE_TRANSFORMERS = "transformers";

  /** WHY: Shade config fixtures identify the filter container. */
  private static final String SHADE_FILTERS = "filters";

  /** WHY: Clean property fixtures test stale package input safety. */
  private static final String CLEAN_SKIP_PROPERTY = "maven.clean.skip";

  /** WHY: Shade source generation is outside the scanned provider model. */
  private static final String SHADE_SOURCE_CONTENT_PROPERTY = "shadeSourcesContent";

  /** Temporary project and archive files for provider inventory scenarios. */
  @TempDir Path temporaryDirectory;

  @Test
  void capturesRuntimeOutputAndProductionResourcesWithoutTestRootsOrSourceRoots()
      throws IOException {
    final Fixture fixture = fixture();
    final Path productionSource =
        writeSource(
            fixture.productionSources(),
            "Main.java",
            "package app; public final class Main { static final class Nested {} }\n");
    final Path testSource =
        writeSource(
            fixture.testSources(), "TestOnly.java", "package test; public class TestOnly {}\n");
    final Path outputClass = fixture.productionOutput().resolve("compiled/Output.class");
    writeClass(outputClass, "compiled/Output");
    final Path testClass = fixture.testOutput().resolve("compiled/TestOutput.class");
    writeClass(testClass, "compiled/TestOutput");
    final Path resource = fixture.productionResources().resolve("renamed.bin");
    Files.createDirectories(resource.getParent());
    Files.write(resource, classBytes("resources/Hidden"));
    final Path testResource = fixture.testResources().resolve("test.data");
    Files.createDirectories(testResource.getParent());
    Files.writeString(testResource, "ordinary test resource");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .noneMatch(
            provider ->
                provider.path().equals(productionSource)
                    || provider.path().equals(testSource)
                    || provider.path().equals(testClass)
                    || provider.path().equals(testResource));
    final Path realOutputClass = outputClass.toRealPath();
    final Path realResource = resource.toRealPath();
    assertThat(snapshot.classProviders().providers())
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(realOutputClass);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_CLASS_FILE);
            })
        .anySatisfy(
            provider -> {
              assertThat(provider.path()).isEqualTo(realResource);
              assertThat(provider.kind()).isEqualTo(ProviderKind.APPLICATION_RESOURCE_FILE);
            });
  }

  @Test
  void testScopedDependencyArchivesAreExcludedFromRuntimeProviderInventory() throws IOException {
    final Fixture fixture = fixture("test-scoped-dependency");
    final Path testDependencyJar = temporaryDirectory.resolve("test-scoped-provider.jar");
    ImmutableTestJar.write(
        testDependencyJar,
        Map.of(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            "org/example/TestOnlyProvider.class",
            classBytes("org/example/TestOnlyProvider")));
    final Artifact testDependency =
        new DefaultArtifact(
            ORG_EXAMPLE_GROUP,
            "test-support",
            TEST_VERSION,
            Artifact.SCOPE_TEST,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    testDependency.setFile(testDependencyJar.toFile());
    final Set<Artifact> resolvedArtifacts = new LinkedHashSet<>(fixture.plan().resolvedArtifacts());
    resolvedArtifacts.add(testDependency);
    fixture.project().setArtifacts(resolvedArtifacts);
    final ElisionAnalysisModel.ApplyPlan plan =
        new ElisionAnalysisModel.ApplyPlan(
            resolvedArtifacts,
            fixture.plan().directArtifactsPresent(),
            fixture.plan().directArtifacts());

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(),
            sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY),
            plan,
            trustedProcessClassesAnalysis(fixture.analysis()),
            true);

    assertAll(
        "test-scoped dependency classes do not enter runtime proof inventory",
        () ->
            Assertions.assertTrue(
                snapshot.complete(), "snapshot must be complete when no violations occur"),
        () ->
            Assertions.assertTrue(
                snapshot.classProviders().providers().stream()
                    .noneMatch(provider -> provider.path().equals(testDependencyJar)),
                "test-scoped archive must not contribute runtime class providers"),
        () ->
            Assertions.assertTrue(
                snapshot.artifactFiles().stream()
                    .anyMatch(file -> Artifact.SCOPE_TEST.equals(file.coordinate().scope())),
                "publication inventory retains resolved test-scope rows for the SBOM"));
  }

  @Test
  void attributionUsesOriginalResolvedProvidersAndSelectedTrimOutput() throws IOException {
    final Fixture fixture = fixture("attribution-selected-trim");
    final String requiredClass = "org.example.Required";
    final String classEntry = requiredClass.replace('.', '/') + ".class";
    ImmutableTestJar.write(
        fixture.dependency(), Map.of(classEntry, classBytes("org/example/Required")));
    final Path trimmedPath = temporaryDirectory.resolve("selected-trim.jar");
    writeJar(trimmedPath);
    final ArtifactDigests originalDigests = ArtifactDigests.read(fixture.dependency());
    final ArtifactDigests trimmedDigests = ArtifactDigests.read(trimmedPath);
    final ArtifactTrimRecord trimRecord =
        new ArtifactTrimRecord(
            fixture.coordinate(),
            fixture.dependency(),
            originalDigests.sha256(),
            originalDigests.sha1(),
            trimmedPath,
            trimmedDigests.sha256(),
            trimmedDigests.sha1(),
            1,
            0,
            0L);
    final ElisionAnalysisModel.Analysis originalAnalysis = fixture.analysis();
    final TrimResult originalTrimResult = originalAnalysis.trimResult();
    final TrimResult stagedTrimResult =
        new TrimResult(
            List.of(trimRecord),
            originalTrimResult.multiReleasePassthroughArtifacts(),
            originalTrimResult.moduleInfoPassthroughArtifacts(),
            originalTrimResult.configuredPassThroughArtifacts(),
            originalTrimResult.cacheHits(),
            originalTrimResult.maximumCacheHitNanos(),
            originalTrimResult.analysisRuns(),
            originalTrimResult.executionEnvironment(),
            originalTrimResult.toleratedDuplicates());
    final ElisionAnalysisModel.Analysis stagedAnalysis =
        new ElisionAnalysisModel.Analysis(
            originalAnalysis.artifacts(),
            originalAnalysis.decision(),
            originalAnalysis.effectiveDecision(),
            originalAnalysis.evidence(),
            stagedTrimResult,
            originalAnalysis.graphProjection(),
            originalAnalysis.mediatedGraph(),
            originalAnalysis.policyIdentity(),
            originalAnalysis.traceDecision(),
            originalAnalysis.banPlan());

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(),
            sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY),
            fixture.plan(),
            stagedAnalysis,
            true);
    final PreconditionProof.InventoryPair pair = snapshot.proofInventoryPair().orElseThrow();
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            TEST_CVE,
            fixture.coordinate(),
            TEST_RANGE,
            Set.of(),
            null,
            ConfidenceLevel.HIGH,
            fixture.coordinate().groupId() + ":" + fixture.coordinate().artifactId(),
            requiredClass);
    final PrerequisiteProofResult result =
        PreconditionProof.proveWithAttribution(
            ExplicitEvidenceTestSupport.genericPrerequisiteFinding(mapping),
            fixture.coordinate(),
            pair);
    final boolean finalInventoryComplete = snapshot.complete();

    final Path realTrimmedPath = trimmedPath.toRealPath();
    assertAll(
        "proof attribution uses original Maven input and selected staged bytes",
        () -> Assertions.assertTrue(finalInventoryComplete, "final inventory is complete"),
        () ->
            assertThat(snapshot.classProviders().providers())
                .anySatisfy(
                    provider -> {
                      assertThat(provider.coordinate()).isEqualTo(fixture.coordinate());
                      assertThat(provider.path()).isEqualTo(realTrimmedPath);
                    }),
        () ->
            assertThat(result.groups())
                .singleElement()
                .satisfies(
                    group ->
                        assertThat(group.attribution())
                            .isEqualTo(PrerequisiteAbsenceAttribution.TRIMMED_CLASS)),
        () ->
            assertThat(result.groups().getFirst().members().getFirst().providers())
                .singleElement()
                .satisfies(
                    provider ->
                        assertAll(
                            () ->
                                assertThat(provider.baselinePath())
                                    .isEqualTo(fixture.dependency().toRealPath()),
                            () -> assertThat(provider.finalPath()).isEqualTo(realTrimmedPath),
                            () ->
                                assertThat(provider.attribution())
                                    .isEqualTo(PrerequisiteAbsenceAttribution.TRIMMED_CLASS))));
  }

  @Test
  void droppedDependencyClassIsPresentInBaselineAndAbsentFromFinal() throws IOException {
    final Fixture fixture = fixture("dropped-provider-baseline");
    final String requiredClass = "org.example.DroppedProvider";
    final Path droppedJar = temporaryDirectory.resolve("dropped-provider.jar");
    ImmutableTestJar.write(
        droppedJar,
        Map.of(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n\n".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            "org/example/DroppedProvider.class",
            classBytes("org/example/DroppedProvider")));
    final Artifact droppedArtifact =
        new DefaultArtifact(
            ORG_EXAMPLE_GROUP,
            "dropped-provider",
            TEST_VERSION,
            GOAL_COMPILE,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    droppedArtifact.setFile(droppedJar.toFile());
    final Set<Artifact> resolvedArtifacts =
        new LinkedHashSet<>(
            List.of(fixture.project().getArtifacts().iterator().next(), droppedArtifact));
    fixture.project().setArtifacts(resolvedArtifacts);
    final ArtifactCoordinate droppedCoordinate =
        MavenArtifactInventory.toCoordinate(droppedArtifact);
    final ElisionAnalysisModel.Analysis sourceAnalysis = fixture.analysis();
    final ElisionAnalysisModel.ArtifactViews artifactViews =
        new ElisionAnalysisModel.ArtifactViews(
            MavenArtifactInventory.snapshots(resolvedArtifacts), false, List.of());
    final io.github.spockz.elider.model.ElisionDecision decision =
        new io.github.spockz.elider.model.ElisionDecision(
            Set.of(fixture.coordinate()), Set.of(droppedCoordinate), Map.of(), Map.of(), 0L);
    final ElisionAnalysisModel.Analysis analysis =
        new ElisionAnalysisModel.Analysis(
            artifactViews,
            decision,
            decision,
            sourceAnalysis.evidence(),
            sourceAnalysis.trimResult(),
            sourceAnalysis.graphProjection(),
            sourceAnalysis.mediatedGraph(),
            sourceAnalysis.policyIdentity(),
            sourceAnalysis.traceDecision(),
            sourceAnalysis.banPlan());
    final ElisionAnalysisModel.ApplyPlan retainedPlan =
        MavenArtifactPlan.prepare(fixture.project(), analysis);

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(),
            sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY),
            retainedPlan,
            analysis,
            true);
    final PreconditionProof.InventoryPair pair = snapshot.proofInventoryPair().orElseThrow();
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            TEST_CVE,
            fixture.coordinate(),
            TEST_RANGE,
            Set.of(),
            null,
            ConfidenceLevel.HIGH,
            fixture.coordinate().groupId() + ":" + fixture.coordinate().artifactId(),
            requiredClass);
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(
            ExplicitEvidenceTestSupport.genericPrerequisiteFinding(mapping),
            fixture.coordinate(),
            pair);
    final boolean finalInventoryComplete = snapshot.complete();

    final Path realDroppedJar = droppedJar.toRealPath();
    assertAll(
        "whole-artifact removal is attributed from original resolved providers",
        () -> assertThat(retainedPlan.resolvedArtifacts()).hasSize(1),
        () -> Assertions.assertTrue(finalInventoryComplete, "final inventory is complete"),
        () ->
            assertThat(snapshot.classProviders().providers())
                .noneMatch(provider -> provider.path().equals(realDroppedJar)),
        () ->
            assertThat(proof.groups())
                .singleElement()
                .satisfies(
                    group ->
                        assertAll(
                            () ->
                                assertThat(group.attribution())
                                    .isEqualTo(PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY),
                            () ->
                                assertThat(group.members().getFirst().providers())
                                    .singleElement()
                                    .satisfies(
                                        provider ->
                                            assertAll(
                                                () ->
                                                    assertThat(provider.baselinePath())
                                                        .isEqualTo(realDroppedJar),
                                                () -> assertThat(provider.finalPath()).isNull(),
                                                () ->
                                                    assertThat(provider.attribution())
                                                        .isEqualTo(
                                                            PrerequisiteAbsenceAttribution
                                                                .ELIDED_DEPENDENCY))))));
  }

  @Test
  void unreadableOriginalProviderKeepsCompleteFinalProofWithUnknownAttribution()
      throws IOException {
    final Fixture fixture = fixture("unreadable-provider-baseline");
    final Path malformedJar = temporaryDirectory.resolve("malformed-dropped-provider.jar");
    Files.writeString(malformedJar, "not a jar");
    final Artifact droppedArtifact =
        new DefaultArtifact(
            ORG_EXAMPLE_GROUP,
            "malformed-provider",
            TEST_VERSION,
            GOAL_COMPILE,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    droppedArtifact.setFile(malformedJar.toFile());
    final Artifact affectedArtifact = fixture.project().getArtifacts().iterator().next();
    final Set<Artifact> resolvedArtifacts =
        new LinkedHashSet<>(List.of(affectedArtifact, droppedArtifact));
    fixture.project().setArtifacts(resolvedArtifacts);
    final ArtifactCoordinate droppedCoordinate =
        MavenArtifactInventory.toCoordinate(droppedArtifact);
    final ElisionAnalysisModel.Analysis sourceAnalysis = fixture.analysis();
    final ElisionAnalysisModel.Analysis analysis =
        new ElisionAnalysisModel.Analysis(
            new ElisionAnalysisModel.ArtifactViews(
                MavenArtifactInventory.snapshots(resolvedArtifacts), false, List.of()),
            new io.github.spockz.elider.model.ElisionDecision(
                Set.of(fixture.coordinate()), Set.of(droppedCoordinate), Map.of(), Map.of(), 0L),
            new io.github.spockz.elider.model.ElisionDecision(
                Set.of(fixture.coordinate()), Set.of(droppedCoordinate), Map.of(), Map.of(), 0L),
            sourceAnalysis.evidence(),
            sourceAnalysis.trimResult(),
            sourceAnalysis.graphProjection(),
            sourceAnalysis.mediatedGraph(),
            sourceAnalysis.policyIdentity(),
            sourceAnalysis.traceDecision(),
            sourceAnalysis.banPlan());
    final ElisionAnalysisModel.ApplyPlan retainedPlan =
        MavenArtifactPlan.prepare(fixture.project(), analysis);
    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(),
            sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY),
            retainedPlan,
            analysis,
            true);
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            TEST_CVE,
            fixture.coordinate(),
            TEST_RANGE,
            Set.of(),
            null,
            ConfidenceLevel.HIGH,
            fixture.coordinate().groupId() + ":" + fixture.coordinate().artifactId(),
            "org.example.AbsentPrerequisite");
    final PreconditionProof.InventoryPair pair = snapshot.proofInventoryPair().orElseThrow();
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(
            ExplicitEvidenceTestSupport.genericPrerequisiteFinding(mapping),
            fixture.coordinate(),
            pair);
    final boolean finalInventoryComplete = snapshot.complete();
    final String baselineDetail = pair.baselineDetail();

    assertAll(
        "baseline archive failure limits attribution but not complete final proof",
        () -> Assertions.assertTrue(finalInventoryComplete, "final inventory is complete"),
        () -> Assertions.assertFalse(baselineDetail.isBlank(), "baseline failure includes detail"),
        () ->
            assertThat(proof.groups().getFirst().members().getFirst().attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN));
  }

  /** WHY: Groups compiler-generated provider cases under the ADR proof boundary. */
  @Nested
  @DisplayName("Javac provider discovery")
  class JavacProviderTests {
    @Test
    void javacPluginServiceDescriptorBlocksProofAfterGeneratingAClass() throws Exception {
      final Fixture fixture = fixture("javac-plugin-service-provider");
      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
      assertThat(snapshot.complete()).isTrue();

      final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
      assertThat(compiler).isNotNull();
      final Path pluginSource =
          writeSource(
              temporaryDirectory.resolve("javac-plugin-source"),
              "ProviderPlugin.java",
              javacPluginSource(
                  Base64.getEncoder().encodeToString(classBytes("generated/FromPlugin"))));
      final Path pluginClasses = temporaryDirectory.resolve("javac-plugin-classes");
      Files.createDirectories(pluginClasses);
      assertThat(
              compiler.run(
                  null,
                  null,
                  null,
                  "-proc:none",
                  "-d",
                  pluginClasses.toString(),
                  pluginSource.toString()))
          .isZero();

      final Path pluginArchive = temporaryDirectory.resolve("javac-plugin.jar");
      final Map<String, byte[]> pluginEntries;
      try (java.util.stream.Stream<Path> pluginClassFiles = Files.walk(pluginClasses)) {
        pluginEntries =
            java.util.stream.Stream.concat(
                    pluginClassFiles
                        .filter(Files::isRegularFile)
                        .map(pluginClass -> pluginClassEntry(pluginClasses, pluginClass)),
                    java.util.stream.Stream.of(
                        Map.entry(
                            "META-INF/services/com.sun.source.util.Plugin",
                            "plugin.ProviderPlugin\n"
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8))))
                .collect(
                    java.util.stream.Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, Map.Entry::getValue));
      }
      ImmutableTestJar.write(pluginArchive, pluginEntries);

      final Path consumerSource =
          writeSource(
              fixture.productionSources(),
              "CompileTrigger.java",
              "package app; public final class CompileTrigger {}\n");
      final Path generatedClass = fixture.productionOutput().resolve("generated/FromPlugin.class");
      final String previousPluginOutput = System.getProperty(JAVAC_PLUGIN_OUTPUT_PROPERTY);
      System.setProperty(JAVAC_PLUGIN_OUTPUT_PROPERTY, generatedClass.toString());
      try {
        assertThat(
                compiler.run(
                    null,
                    null,
                    null,
                    "-classpath",
                    pluginArchive.toString(),
                    "-proc:none",
                    "-d",
                    fixture.productionOutput().toString(),
                    consumerSource.toString()))
            .isZero();
      } finally {
        if (previousPluginOutput == null) {
          System.clearProperty(JAVAC_PLUGIN_OUTPUT_PROPERTY);
        } else {
          System.setProperty(JAVAC_PLUGIN_OUTPUT_PROPERTY, previousPluginOutput);
        }
      }
      assertThat(generatedClass).exists();

      final List<Provider> providers = new ArrayList<>(snapshot.classProviders().providers());
      providers.add(
          Provider.dependencyArchive(
              ArtifactCoordinate.of(EXAMPLE_GROUP, "javac-plugin", TEST_VERSION), pluginArchive));
      final PreconditionClassInventory inventory = PreconditionClassInventory.complete(providers);
      final VulnerabilitySymbolMapping mapping =
          new VulnerabilitySymbolMapping(
              TEST_CVE,
              fixture.coordinate(),
              TEST_RANGE,
              Set.of(),
              null,
              ConfidenceLevel.HIGH,
              PREREQUISITE_COORDINATE,
              "org.example.MissingPrerequisite");

      assertThatThrownBy(
              () ->
                  PreconditionProof.prove(
                      ExplicitEvidenceTestSupport.genericPrerequisiteFinding(mapping),
                      mapping.affectedCoordinate(),
                      inventory))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Javac plugin service provider");
    }

    @Test
    void resourceTargetPathCannotHideAJavacPluginServiceDescriptor() throws IOException {
      final Fixture fixture = fixture("remapped-javac-plugin-service");
      fixture.project().getResources().get(0).setTargetPath("META-INF/services");
      writeSource(
          fixture.productionResources(), "com.sun.source.util.Plugin", "plugin.ProviderPlugin\n");

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
      final VulnerabilitySymbolMapping mapping =
          new VulnerabilitySymbolMapping(
              TEST_CVE,
              fixture.coordinate(),
              TEST_RANGE,
              Set.of(),
              null,
              ConfidenceLevel.HIGH,
              PREREQUISITE_COORDINATE,
              "org.example.MissingPrerequisite");

      assertThat(snapshot.complete()).isTrue();
      assertThat(snapshot.proofInventoryPair()).isEmpty();
      assertThat(snapshot.proofInventoryFailure())
          .hasValueSatisfying(value -> assertThat(value).contains("Javac plugin service provider"));
      assertThatThrownBy(
              () ->
                  PreconditionProof.prove(
                      ExplicitEvidenceTestSupport.genericPrerequisiteFinding(mapping),
                      mapping.affectedCoordinate(),
                      snapshot.classProviders()))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Javac plugin service provider");
    }

    @Test
    void generatedSourceRootsAreNotScannedAtProcessClasses() throws IOException {
      final Fixture fixture = fixture("compiler-generated-default-roots");
      final Path productionRoot =
          fixture.productionOutput().getParent().resolve("generated-sources/annotations");
      final Path testRoot =
          fixture.testOutput().getParent().resolve("generated-test-sources/test-annotations");
      final Path productionSource =
          writeSource(
              productionRoot, "Generated.java", "package generated; public class Generated {}\n");
      final Path testSource =
          writeSource(
              testRoot, "GeneratedTest.java", "package generated; public class GeneratedTest {}\n");

      assertThat(fixture.project().getCompileSourceRoots())
          .doesNotContain(productionRoot.toString());
      assertThat(fixture.project().getTestCompileSourceRoots()).doesNotContain(testRoot.toString());

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      assertThat(snapshot.complete()).isTrue();
      assertThat(snapshot.classProviders().providers())
          .noneMatch(
              provider ->
                  provider.path().equals(productionSource) || provider.path().equals(testSource));
    }

    @Test
    void customCompilerGeneratedTestSourceRootIsExcludedFromProof() throws IOException {
      final Fixture fixture = fixture("custom-test-generated-source-root");
      final Plugin compiler = compilerPlugin();
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      testCompile.setConfiguration(
          configuration(
              "generatedTestSourcesDirectory",
              fixture.productionOutput().getParent().resolve("elsewhere/generated").toString()));
      compiler.addExecution(testCompile);
      fixture.project().getBuild().addPlugin(compiler);

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      assertThat(snapshot.complete()).isTrue();

      final Fixture propertyFixture = fixture("custom-test-generated-source-property");
      propertyFixture
          .project()
          .getProperties()
          .setProperty(
              "maven.compiler.generatedTestSourcesDirectory", "target/custom-test-sources");

      final MavenPreconditionInventory.Snapshot propertySnapshot = capture(propertyFixture);

      assertThat(propertySnapshot.complete()).isTrue();
    }

    @Test
    void interfaceAssertionHelperClassIsCoveredByCompiledClassOutput() throws IOException {
      final Fixture fixture = fixture("interface-assertion");
      final Path source =
          writeSource(
              fixture.productionSources(),
              "Assertive.java",
              "package app; public interface Assertive { default void check(boolean enabled) { "
                  + "assert enabled; } }\n");
      Files.createDirectories(fixture.productionOutput());
      final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
      assertThat(compiler).isNotNull();

      final int compilationResult =
          compiler.run(
              null,
              null,
              null,
              "--release",
              "21",
              "-proc:none",
              "-d",
              fixture.productionOutput().toString(),
              source.toString());

      assertThat(compilationResult).isZero();
      assertThat(fixture.productionOutput().resolve("app/Assertive$1.class")).exists();

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      final Path realAssertiveHelper =
          fixture.productionOutput().resolve("app/Assertive$1.class").toRealPath();
      assertThat(snapshot.complete()).isTrue();
      assertThat(snapshot.classProviders().providers())
          .anySatisfy(provider -> assertThat(provider.path()).isEqualTo(realAssertiveHelper));
    }
  }

  @Test
  void disabledPreconditionProofInventoryIsIncomplete() throws IOException {
    final Fixture fixture = fixture();
    writeSource(fixture.productionSources(), "Invalid.java", "class Invalid { syntax ??? }\n");

    final MavenPreconditionInventory.Snapshot snapshot =
        MavenPreconditionInventory.capture(
            fixture.project(), fixture.plan(), fixture.analysis(), false);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("opt-in is disabled");
  }

  /** WHY: Groups request lifecycle cases that determine inventory freshness. */
  @Nested
  @DisplayName("Maven request and test lifecycle")
  class MavenRequestTests {
    @Test
    void omittedEliderPhaseUsesProcessClassesCaptureBoundary() throws IOException {
      final Fixture fixture = fixture("elider-default-phase");
      final Plugin elider = new Plugin();
      elider.setGroupId("io.github.spockz");
      elider.setArtifactId("dependency-elider-maven-plugin");
      final PluginExecution elide = new PluginExecution();
      elide.setId("default-elide");
      elide.setGoals(List.of("elide"));
      elider.addExecution(elide);
      fixture.project().getBuild().addPlugin(elider);

      final MavenSession session = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY);
      session.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);
      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertThat(snapshot.complete()).as(snapshot.classProviders().detail()).isTrue();
    }

    @Test
    void packageBoundSpringRepackageIsKnownAfterProviderCapture() throws IOException {
      final Fixture fixture = fixture("spring-repackage-after-capture");
      final Plugin spring = new Plugin();
      spring.setGroupId("org.springframework.boot");
      spring.setArtifactId("spring-boot-maven-plugin");
      final PluginExecution repackage = new PluginExecution();
      repackage.setId("repackage");
      repackage.setPhase(GOAL_PACKAGE);
      repackage.setGoals(List.of("repackage"));
      spring.addExecution(repackage);
      fixture.project().getBuild().addPlugin(spring);

      final MavenSession session = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY);
      session.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);
      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertThat(snapshot.complete()).as(snapshot.classProviders().detail()).isTrue();
    }

    @Test
    void explicitCompiledOutputAllowsDirectElideProofWithoutLifecycleProvenance()
        throws IOException {
      final Fixture fixture = fixture("direct-elide-complete-output");
      final Path applicationClass = fixture.productionOutput().resolve("app/Main.class");
      writeClass(applicationClass, "app/Main");
      final MavenSession session =
          sessionForGoals(
              fixture.project(), "io.github.spockz:dependency-elider-maven-plugin:elide");

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              explicitProductionClassesAnalysis(fixture.analysis()),
              true);

      final Path realApplicationClass = applicationClass.toRealPath();
      assertAll(
          "explicit production completeness plus inspected runtime providers is sufficient",
          () -> Assertions.assertTrue(snapshot.complete(), snapshot.classProviders().detail()),
          () ->
              assertThat(snapshot.classProviders().providers())
                  .anySatisfy(
                      provider -> assertThat(provider.path()).isEqualTo(realApplicationClass)));
    }

    @Test
    void directGoalCoordinateFormsRequireExplicitProductionCompleteness() throws IOException {
      final Fixture fixture = fixture("direct-goal-coordinate-forms");
      for (final String goal :
          List.of(
              "dependency-elider:elide",
              "io.github.spockz:dependency-elider-maven-plugin:elide",
              "io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:elide",
              "dependency-elider:analyze",
              "io.github.spockz:dependency-elider-maven-plugin:analyze",
              "io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze")) {
        final MavenSession session = sessionForGoals(fixture.project(), goal);
        assertThatCode(
                () ->
                    MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
                        fixture.project(), session, false, true))
            .doesNotThrowAnyException();
      }
    }

    @Test
    void requestedGoalsMustBeOneKnownDefaultLifecycleInvocation() throws IOException {
      final Fixture safe = fixture("safe-goals");
      final Plugin clean = cleanPlugin();
      final PluginExecution defaultClean = new PluginExecution();
      defaultClean.setId("default-clean");
      defaultClean.setPhase(GOAL_CLEAN);
      defaultClean.setGoals(List.of(GOAL_CLEAN));
      clean.addExecution(defaultClean);
      safe.project().getBuild().addPlugin(clean);
      final Plugin install = new Plugin();
      install.setGroupId(MAVEN_PLUGIN_GROUP);
      install.setArtifactId("maven-install-plugin");
      final PluginExecution defaultInstall = new PluginExecution();
      defaultInstall.setId("default-install");
      defaultInstall.setPhase("install");
      defaultInstall.setGoals(List.of("install"));
      install.addExecution(defaultInstall);
      safe.project().getBuild().addPlugin(install);
      final MavenPreconditionInventory.Snapshot cleanVerify =
          capture(safe, sessionForGoals(safe.project(), GOAL_CLEAN, GOAL_VERIFY));
      assertThat(cleanVerify.complete()).isTrue();

      final Fixture customizedClean = fixture("custom-clean");
      final Plugin customClean = cleanPlugin();
      customClean.setConfiguration(configuration("excludeDefaultDirectories", TRUE));
      final PluginExecution cleanExecution = new PluginExecution();
      cleanExecution.setId("default-clean");
      cleanExecution.setPhase(GOAL_CLEAN);
      cleanExecution.setGoals(List.of(GOAL_CLEAN));
      customClean.addExecution(cleanExecution);
      customizedClean.project().getBuild().addPlugin(customClean);
      final MavenPreconditionInventory.Snapshot customCleanSnapshot =
          capture(
              customizedClean, sessionForGoals(customizedClean.project(), GOAL_CLEAN, GOAL_VERIFY));
      assertThat(customCleanSnapshot.complete()).isFalse();
      assertThat(customCleanSnapshot.classProviders().detail()).contains("custom configuration");

      final List<List<String>> unsupportedGoals =
          List.of(
              List.of(GOAL_VERIFY, GOAL_SITE),
              List.of(GOAL_SITE),
              List.of(GOAL_VERIFY, GOAL_CLEAN),
              List.of(GOAL_VERIFY, "validate"),
              List.of(GOAL_CLEAN, GOAL_VERIFY, GOAL_SITE));
      for (final List<String> goals : unsupportedGoals) {
        final Fixture fixture = fixture("unsafe-goals-" + goals.hashCode());
        final MavenPreconditionInventory.Snapshot snapshot =
            capture(fixture, sessionForGoals(fixture.project(), goals.toArray(String[]::new)));

        assertThat(snapshot.complete()).isFalse();
        assertThat(snapshot.classProviders().detail()).contains("Maven goal sequence");
      }

      final Fixture directElideWithoutOutputAssertion =
          fixture("direct-elide-without-output-assertion");
      final MavenPreconditionInventory.Snapshot directElideSnapshot =
          capture(
              directElideWithoutOutputAssertion,
              sessionForGoals(
                  directElideWithoutOutputAssertion.project(),
                  "io.github.spockz:dependency-elider-maven-plugin:elide"));
      assertThat(directElideSnapshot.complete()).isFalse();
      assertThat(directElideSnapshot.classProviders().detail())
          .contains("direct elide requires elide.productionClassesComplete=true");

      final Fixture directAnalyzeWithoutOutputAssertion = fixture("direct-analyze-incomplete");
      final MavenPreconditionInventory.Snapshot directAnalyzeSnapshot =
          capture(
              directAnalyzeWithoutOutputAssertion,
              sessionForGoals(
                  directAnalyzeWithoutOutputAssertion.project(), "dependency-elider:analyze"));
      assertThat(directAnalyzeSnapshot.complete()).isFalse();
      assertThat(directAnalyzeSnapshot.classProviders().detail())
          .contains("direct analyze requires elide.productionClassesComplete=true");

      final Fixture missingSession = fixture("missing-session");
      final MavenPreconditionInventory.Snapshot missingSessionSnapshot =
          MavenPreconditionInventory.capture(
              missingSession.project(), missingSession.plan(), missingSession.analysis(), true);

      assertThat(missingSessionSnapshot.complete()).isFalse();
      assertThat(missingSessionSnapshot.classProviders().detail())
          .contains("Maven session goal order is unavailable");
    }

    @Test
    void unsupportedPackagingSuppressesPreconditionInventory() throws IOException {
      for (final String packaging : List.of("war", "maven-plugin")) {
        final Fixture fixture = fixture("unsupported-packaging-" + packaging);
        fixture.project().setPackaging(packaging);

        assertGenerationIncomplete(fixture, "custom or unavailable Maven packaging");
      }
    }

    @Test
    void jarPackagingAndDefaultJarExecutionsRequireCleanBeforePackage() throws IOException {
      final Fixture jarPackaging = fixture("jar-packaging-without-clean");
      final MavenPreconditionInventory.Snapshot staleDefaultJar =
          capture(jarPackaging, sessionForGoals(jarPackaging.project(), GOAL_VERIFY));
      assertThat(staleDefaultJar.complete()).isFalse();
      assertThat(staleDefaultJar.classProviders().detail()).contains("requires a clean goal");

      assertThat(
              capture(
                      jarPackaging,
                      sessionForGoals(jarPackaging.project(), GOAL_CLEAN, GOAL_VERIFY))
                  .complete())
          .isTrue();

      final Fixture explicitJarGoal = fixture("explicit-jar-goal-without-clean");
      explicitJarGoal.project().setPackaging("pom");
      final Plugin jarPlugin = jarPlugin();
      final PluginExecution defaultJar = new PluginExecution();
      defaultJar.setId("default-jar");
      defaultJar.setPhase(GOAL_PACKAGE);
      defaultJar.setGoals(List.of(JAR_TYPE));
      jarPlugin.addExecution(defaultJar);
      explicitJarGoal.project().getBuild().addPlugin(jarPlugin);

      final MavenPreconditionInventory.Snapshot explicitJarWithoutClean =
          capture(explicitJarGoal, sessionForGoals(explicitJarGoal.project(), GOAL_VERIFY));
      assertThat(explicitJarWithoutClean.complete()).isFalse();
      assertThat(explicitJarWithoutClean.classProviders().detail())
          .contains("requires a clean goal");
    }

    @Test
    void surefireMustBeSkippedForTestLifecycleAfterInventoryCapture() throws IOException {
      final Fixture missingSkip = fixture("surefire-not-skipped");
      final MavenSession missingSkipSession = sessionForGoals(missingSkip.project(), GOAL_VERIFY);
      missingSkipSession.getUserProperties().remove(SKIP_TESTS);

      final MavenPreconditionInventory.Snapshot missingSnapshot =
          capture(missingSkip, missingSkipSession);

      assertThat(missingSnapshot.complete()).isFalse();
      assertThat(missingSnapshot.classProviders().detail()).contains("skipTests=true");

      final Fixture falseSkip = fixture("surefire-skip-false");
      final MavenSession falseSkipSession = sessionForGoals(falseSkip.project(), GOAL_VERIFY);
      falseSkipSession.getUserProperties().setProperty(SKIP_TESTS, FALSE);

      final MavenPreconditionInventory.Snapshot falseSnapshot =
          capture(falseSkip, falseSkipSession);

      assertThat(falseSnapshot.complete()).isFalse();
      assertThat(falseSnapshot.classProviders().detail()).contains("skipTests=true");

      final Fixture customSurefire = fixture("surefire-custom-config");
      final Plugin surefire =
          customSurefire.project().getBuild().getPlugins().stream()
              .filter(ADR0008MavenPreconditionInventoryTest::isSurefirePlugin)
              .findFirst()
              .orElseThrow();
      surefire.setConfiguration(configuration(SKIP_TESTS, FALSE));
      final MavenPreconditionInventory.Snapshot customSnapshot = capture(customSurefire);
      assertThat(customSnapshot.complete()).isFalse();
      assertThat(customSnapshot.classProviders().detail()).contains("change test execution");

      final Fixture beforeTest = fixture("surefire-not-run-before-test");
      final MavenSession initializeSession = sessionForGoals(beforeTest.project(), "initialize");
      initializeSession.getUserProperties().remove(SKIP_TESTS);
      assertThat(capture(beforeTest, initializeSession).complete()).isTrue();
    }
  }

  @Test
  void unavailableProjectOrBuildSuppressesProofWithoutThrowing() throws IOException {
    final Fixture fixture = fixture("unavailable-build");
    final MavenProject missingBuildProject =
        new MavenProject() {
          @Override
          public Build getBuild() {
            return null;
          }
        };

    final MavenPreconditionInventory.Snapshot missingBuild =
        MavenPreconditionInventory.capture(
            missingBuildProject,
            sessionForGoals(fixture.project(), GOAL_VERIFY),
            fixture.plan(),
            fixture.analysis(),
            true);
    final MavenPreconditionInventory.Snapshot missingProject =
        MavenPreconditionInventory.capture(
            null,
            sessionForGoals(fixture.project(), GOAL_VERIFY),
            fixture.plan(),
            fixture.analysis(),
            true);

    assertThat(missingBuild.complete()).isFalse();
    assertThat(missingBuild.classProviders().detail())
        .contains("Maven build configuration is unavailable");
    assertThat(missingProject.complete()).isFalse();
    assertThat(missingProject.classProviders().detail())
        .contains("Maven build configuration is unavailable");
  }

  /** WHY: Groups compiler settings that can invalidate source inventory. */
  @Nested
  @DisplayName("Compiler configuration")
  class CompilerConfigurationTests {
    @Test
    void explicitProcessingDisablementIsRequiredForBothCompilerGoals() throws IOException {
      final Fixture missingSetting = fixture();
      missingSetting.project().getProperties().remove(PROCESSING_PROPERTY);

      final MavenPreconditionInventory.Snapshot missingSnapshot = capture(missingSetting);

      assertThat(missingSnapshot.complete()).isFalse();
      assertThat(missingSnapshot.classProviders().detail())
          .contains("explicit proc=none is required for default compile execution");

      final Fixture unresolvedSetting = fixture("project-unresolved");
      unresolvedSetting
          .project()
          .getProperties()
          .setProperty(PROCESSING_PROPERTY, "${unknown.processing.mode}");

      final MavenPreconditionInventory.Snapshot unresolvedSnapshot = capture(unresolvedSetting);

      assertThat(unresolvedSnapshot.complete()).isFalse();
      assertThat(unresolvedSnapshot.classProviders().detail())
          .contains("unresolved compiler property unknown.processing.mode");

      for (final String unsupported : List.of(PROCESSING_FULL, "only")) {
        final Fixture configured = fixture("project-" + unsupported);
        configured.project().getProperties().setProperty(PROCESSING_PROPERTY, unsupported);

        final MavenPreconditionInventory.Snapshot snapshot = capture(configured);

        assertThat(snapshot.complete()).isFalse();
        assertThat(snapshot.classProviders().detail()).contains("unsupported proc value");
      }
    }

    @Test
    void productionCompilerProvidersAreGuardedButTestProvidersAreExcluded() throws IOException {
      final Fixture processorPath = fixture();
      final Plugin activeCompiler = compilerPlugin();
      activeCompiler.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      pluginConfiguration(activeCompiler).addChild(setting(ANNOTATION_PROCESSOR_PATHS, null));
      processorPath.project().getBuild().addPlugin(activeCompiler);

      final MavenPreconditionInventory.Snapshot processorPathSnapshot = capture(processorPath);

      assertThat(processorPathSnapshot.complete()).isFalse();
      assertThat(processorPathSnapshot.classProviders().detail())
          .contains(ANNOTATION_PROCESSOR_PATHS);

      final Fixture testCompile = fixture("test-compile");
      final Plugin managedCompiler = compilerPlugin();
      managedCompiler.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      final PluginExecution execution = new PluginExecution();
      execution.setId(DEFAULT_TEST_COMPILE);
      execution.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_FULL));
      managedCompiler.addExecution(execution);
      final PluginManagement management = new PluginManagement();
      management.addPlugin(managedCompiler);
      testCompile.project().getBuild().setPluginManagement(management);
      assertThat(testCompile.project().getBuild().getPluginManagement().getPlugins())
          .contains(managedCompiler);
      assertThat(execution.getGoals()).isEmpty();
      assertThat(executionConfiguration(execution).getChild(PROCESSING_SETTING).getValue())
          .isEqualTo(PROCESSING_FULL);

      final MavenPreconditionInventory.Snapshot testCompileSnapshot = capture(testCompile);

      assertThat(testCompileSnapshot.complete()).isTrue();

      final Fixture compile = fixture(DEFAULT_COMPILE);
      final Plugin compileManagedCompiler = compilerPlugin();
      compileManagedCompiler.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      final PluginExecution compileExecution = new PluginExecution();
      compileExecution.setId(DEFAULT_COMPILE);
      compileExecution.setConfiguration(configuration(PROCESSING_SETTING, "only"));
      compileManagedCompiler.addExecution(compileExecution);
      final PluginManagement compileManagement = new PluginManagement();
      compileManagement.addPlugin(compileManagedCompiler);
      compile.project().getBuild().setPluginManagement(compileManagement);

      final MavenPreconditionInventory.Snapshot compileSnapshot = capture(compile);

      assertThat(compileSnapshot.complete()).isFalse();
      assertThat(compileSnapshot.classProviders().detail())
          .contains("conflicting or unsupported proc value in execution default-compile");

      final Fixture sourceOverride = fixture("test-source-override");
      final Plugin sourceCompiler = compilerPlugin();
      final PluginExecution testSourceExecution = new PluginExecution();
      testSourceExecution.setId(DEFAULT_TEST_COMPILE);
      final Xpp3Dom testSourceConfiguration = configuration(PROCESSING_SETTING, PROCESSING_NONE);
      testSourceConfiguration.addChild(setting("compileSourceRoots", "/external/sources"));
      testSourceExecution.setConfiguration(testSourceConfiguration);
      sourceCompiler.addExecution(testSourceExecution);
      sourceOverride.project().getBuild().addPlugin(sourceCompiler);

      final MavenPreconditionInventory.Snapshot sourceOverrideSnapshot = capture(sourceOverride);

      assertThat(sourceOverrideSnapshot.complete()).isTrue();
    }

    @Test
    @DisplayName("ADR-0008/trusted capture excludes isolated test compiler output")
    void trustedCaptureAllowsTestCompileProcessorsWithIsolatedOutput() throws IOException {
      final Fixture fixture = fixture("trusted-compile-processors");
      fixture.project().getProperties().remove(PROCESSING_PROPERTY);
      final Plugin compiler = compilerPlugin();
      final PluginExecution compile = new PluginExecution();
      compile.setId(DEFAULT_COMPILE);
      compile.setGoals(List.of(GOAL_COMPILE));
      final Xpp3Dom compileConfiguration = new Xpp3Dom(CONFIGURATION_ELEMENT);
      compileConfiguration.addChild(new Xpp3Dom(ANNOTATION_PROCESSOR_PATHS));
      compile.setConfiguration(compileConfiguration);
      compiler.addExecution(compile);
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      testCompile.setGoals(List.of(GOAL_TEST_COMPILE));
      testCompile.setConfiguration(new Xpp3Dom(CONFIGURATION_ELEMENT));
      compiler.addExecution(testCompile);
      fixture.project().getBuild().addPlugin(compiler);
      final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
      request.setGoals(List.of(PROCESS_CLASSES_PHASE));
      final MavenSession session = new MavenSession(null, request, null, fixture.project());
      session.getUserProperties().setProperty(SKIP_TESTS, TRUE);

      assertThatCode(
              () ->
                  MavenCompilerGenerationGuard.requireSafeCompilerConfiguration(
                      fixture.project(), session, true))
          .doesNotThrowAnyException();

      assertThat(testCompile.getConfiguration()).isNotNull();
    }

    @Test
    @DisplayName(
        "ADR-0008/trusted COMPLETE inventory uses compiled providers with compile processors")
    void trustedCompleteInventoryIgnoresSourceRootsWithCompileProcessorPaths() throws IOException {
      final Fixture fixture = fixture("trusted-complete-generated-processor");
      Files.writeString(
          fixture.productionSources().resolve("Generated.java"),
          "package generated; public final class Generated {}\n");
      addUnknownGenerator(fixture, "generate-sources");
      fixture.project().getProperties().remove(PROCESSING_PROPERTY);
      final Plugin compiler = compilerPlugin();
      final PluginExecution compile = new PluginExecution();
      compile.setId(DEFAULT_COMPILE);
      compile.setGoals(List.of(GOAL_COMPILE));
      final Xpp3Dom compileConfiguration = new Xpp3Dom(CONFIGURATION_ELEMENT);
      compileConfiguration.addChild(new Xpp3Dom(ANNOTATION_PROCESSOR_PATHS));
      compile.setConfiguration(compileConfiguration);
      compiler.addExecution(compile);
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      testCompile.setGoals(List.of(GOAL_TEST_COMPILE));
      testCompile.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      compiler.addExecution(testCompile);
      fixture.project().getBuild().addPlugin(compiler);
      addDefaultTestResourcesExecution(fixture.project(), null);
      final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
      request.setGoals(List.of(GOAL_CLEAN, PROCESS_CLASSES_PHASE));
      final MavenSession session = new MavenSession(null, request, null, fixture.project());
      session.getUserProperties().setProperty(SKIP_TESTS, TRUE);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertThat(snapshot.complete()).isTrue();
      assertThat(snapshot.classProviders().providers())
          .noneMatch(
              provider ->
                  provider.path().equals(fixture.productionSources().resolve("Generated.java")));

      testCompile.setConfiguration(new Xpp3Dom(CONFIGURATION_ELEMENT));
      final MavenPreconditionInventory.Snapshot unsafe =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);
      assertThat(unsafe.complete()).isTrue();
    }

    @Test
    void testOnlyProvidersDoNotBlockRuntimeProofWhenTestCompilationRuns() throws IOException {
      final Fixture fixture = fixture("isolated-test-output");
      final Path testOnlySource =
          writeSource(
              fixture.testSources(),
              "FuturePrerequisite.java",
              "package testonly; public final class FuturePrerequisite {}\n");
      final ElisionAnalysisModel.Analysis trusted =
          trustedProcessClassesAnalysis(fixture.analysis());
      final Path testClass = fixture.testOutput().resolve("testonly/FuturePrerequisite.class");
      writeClass(testClass, "testonly/FuturePrerequisite");
      final Path testResource = fixture.testResources().resolve("META-INF/test-only.txt");
      Files.createDirectories(testResource.getParent());
      Files.writeString(testResource, "test-only");
      final Resource filteredTestResource = new Resource();
      filteredTestResource.setDirectory(fixture.testResources().toString());
      filteredTestResource.setFiltering(true);
      fixture.project().getBuild().setTestResources(List.of(filteredTestResource));
      addDefaultTestResourcesExecution(fixture.project(), null);
      final MavenSession testSession = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY);
      testSession.getUserProperties().setProperty(SKIP_TESTS, TRUE);
      testSession.getUserProperties().setProperty(MAVEN_TEST_SKIP, FALSE);
      final Plugin testCompiler = compilerPlugin();
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      testCompile.setGoals(List.of(GOAL_TEST_COMPILE));
      testCompile.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_FULL));
      testCompiler.addExecution(testCompile);
      fixture.project().getBuild().addPlugin(testCompiler);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(), testSession, fixture.plan(), trusted, true);

      assertAll(
          "isolated test compilation and test resources do not change runtime provider inventory",
          () ->
              Assertions.assertTrue(
                  snapshot.complete(), "test-only compiler settings preserve runtime completeness"),
          () ->
              assertThat(snapshot.classProviders().providers())
                  .noneMatch(
                      provider ->
                          provider.path().equals(testOnlySource)
                              || provider.path().equals(testClass)
                              || provider.path().equals(testResource)),
          () ->
              assertThat(snapshot.classProviders().providers())
                  .noneMatch(
                      provider ->
                          provider.path().startsWith(fixture.testOutput())
                              || provider.path().startsWith(fixture.testResources())));
    }

    @Test
    void testOutputOverlappingProductionOutputStillBlocksRuntimeProof() throws IOException {
      final Fixture fixture = fixture("test-output-overlaps-runtime");
      fixture
          .project()
          .getBuild()
          .setTestOutputDirectory(fixture.productionOutput().resolve("test-classes").toString());
      final MavenSession session = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY);
      session.getUserProperties().setProperty(SKIP_TESTS, TRUE);
      session.getUserProperties().setProperty(MAVEN_TEST_SKIP, FALSE);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail())
          .contains("Maven test output overlaps production provider root");
    }

    @Test
    void rootCompilerConfigurationCannotRedirectTestOutputIntoProduction() throws IOException {
      final Fixture fixture = fixture("test-output-root-configuration");
      final Plugin compiler = compilerPlugin();
      compiler.setConfiguration(
          configuration("testOutputDirectory", fixture.productionOutput().toString()));
      fixture.project().getBuild().addPlugin(compiler);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              sessionForGoals(fixture.project(), GOAL_CLEAN, PROCESS_CLASSES_PHASE),
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail()).contains("testOutputDirectory");
    }

    @Test
    void testCompileTargetDoesNotRestrictRuntimeProof() throws IOException {
      final Fixture fixture = fixture("test-compile-target");
      fixture.project().getProperties().setProperty("maven.compiler.testRelease", "8");
      final MavenSession session = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY);
      session.getUserProperties().setProperty(SKIP_TESTS, TRUE);
      session.getUserProperties().setProperty(MAVEN_TEST_SKIP, FALSE);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertThat(snapshot.complete()).isTrue();
    }

    @Test
    void customCompilerExecutionsCannotReplaceLifecycleFallbackOrSkipNullConfigurations()
        throws IOException {
      final Fixture customExecutions = fixture("custom-compiler-executions");
      customExecutions.project().getProperties().remove(PROCESSING_PROPERTY);
      final Plugin compiler = compilerPlugin();
      addCompilerExecution(
          compiler,
          "extra-compile",
          GOAL_COMPILE,
          configuration(PROCESSING_SETTING, PROCESSING_NONE));
      addCompilerExecution(
          compiler,
          "extra-testCompile",
          GOAL_TEST_COMPILE,
          configuration(PROCESSING_SETTING, PROCESSING_NONE));
      customExecutions.project().getBuild().addPlugin(compiler);

      final MavenPreconditionInventory.Snapshot customSnapshot = capture(customExecutions);

      assertThat(customSnapshot.complete()).isFalse();
      assertThat(customSnapshot.classProviders().detail())
          .contains("explicit proc=none is required for default compile execution");

      final Fixture extraExecution = fixture("unconfigured-extra-compile");
      extraExecution.project().getProperties().remove(PROCESSING_PROPERTY);
      final Plugin compilerWithDefault = compilerPlugin();
      final PluginExecution defaultCompile = new PluginExecution();
      defaultCompile.setId(DEFAULT_COMPILE);
      defaultCompile.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      compilerWithDefault.addExecution(defaultCompile);
      final PluginExecution additionalCompile = new PluginExecution();
      additionalCompile.setId("extra-compile");
      additionalCompile.setGoals(List.of(GOAL_COMPILE));
      compilerWithDefault.addExecution(additionalCompile);
      final PluginExecution defaultTestCompile = new PluginExecution();
      defaultTestCompile.setId(DEFAULT_TEST_COMPILE);
      defaultTestCompile.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      compilerWithDefault.addExecution(defaultTestCompile);
      extraExecution.project().getBuild().addPlugin(compilerWithDefault);

      final MavenPreconditionInventory.Snapshot extraSnapshot = capture(extraExecution);

      assertThat(extraSnapshot.complete()).isFalse();
      assertThat(extraSnapshot.classProviders().detail())
          .contains("explicit proc=none is required for compiler execution extra-compile");
    }

    @Test
    void compilerExecutionCannotDiscardRootProcessingDisablementWithMergeOverride()
        throws IOException {
      final Fixture fixture = fixture("compiler-merge-override");
      final Plugin compiler = compilerPlugin();
      compiler.setConfiguration(configuration(PROCESSING_SETTING, PROCESSING_NONE));
      final PluginExecution defaultCompile = new PluginExecution();
      defaultCompile.setId(DEFAULT_COMPILE);
      final Xpp3Dom override = new Xpp3Dom(CONFIGURATION_ELEMENT);
      override.setAttribute("combine.self", "override");
      defaultCompile.setConfiguration(override);
      compiler.addExecution(defaultCompile);
      fixture.project().getBuild().addPlugin(compiler);

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail())
          .contains("compiler configuration merge override");
    }

    @Test
    void testCompilerArgumentChannelsMakeInventoryIncomplete() throws IOException {
      for (final String settingName : List.of("testCompilerArgument", "testCompilerArguments")) {
        assertCompilerArgumentRejected(settingName);
      }
      for (final String propertyName :
          List.of("maven.compiler.testCompilerArgument", "maven.compiler.testCompilerArguments")) {
        assertCompilerPropertyRejected(propertyName);
      }
    }

    private void assertCompilerArgumentRejected(final String settingName) throws IOException {
      final Fixture fixture = fixture("test-argument-" + settingName);
      final Plugin compiler = compilerPlugin();
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      final Xpp3Dom testConfiguration = configuration(PROCESSING_SETTING, PROCESSING_NONE);
      testConfiguration.addChild(setting(settingName, PROCESSOR_FLAG));
      testCompile.setConfiguration(testConfiguration);
      compiler.addExecution(testCompile);
      fixture.project().getBuild().addPlugin(compiler);
      assertGenerationIncomplete(fixture, settingName);
    }

    private void assertCompilerPropertyRejected(final String propertyName) throws IOException {
      final Fixture fixture = fixture("test-argument-property-" + propertyName);
      fixture.project().getProperties().setProperty(propertyName, PROCESSOR_FLAG);
      assertGenerationIncomplete(fixture, propertyName);
    }

    @Test
    void diagnosticOnlyCompilerArgumentIsAllowedButOtherArgumentsAreRejected() throws IOException {
      final Fixture diagnosticOnly = fixture("compiler-diagnostic-argument");
      final Plugin diagnosticCompiler = compilerPlugin();
      diagnosticCompiler.setConfiguration(compilerArgsConfiguration("-Xlint:all"));
      diagnosticOnly.project().getBuild().addPlugin(diagnosticCompiler);

      assertThat(capture(diagnosticOnly).complete()).isTrue();

      for (final String argument : List.of(PROCESSOR_FLAG, "-Xplugin:unknown")) {
        final Fixture fixture = fixture("compiler-argument-" + argument.hashCode());
        final Plugin compiler = compilerPlugin();
        compiler.setConfiguration(compilerArgsConfiguration(argument));
        fixture.project().getBuild().addPlugin(compiler);

        final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

        assertThat(snapshot.complete()).isFalse();
        assertThat(snapshot.classProviders().detail()).contains("unsupported compilerArgs");
      }

      final Fixture propertyArgument = fixture("compiler-argument-property");
      propertyArgument
          .project()
          .getProperties()
          .setProperty("maven.compiler.compilerArgs", PROCESSOR_FLAG);

      final MavenPreconditionInventory.Snapshot propertySnapshot = capture(propertyArgument);

      assertThat(propertySnapshot.complete()).isFalse();
      assertThat(propertySnapshot.classProviders().detail())
          .contains("maven.compiler.compilerArgs");
    }

    @Test
    void compilerVersionAndTargetLevelsMustBeExplicitlySupported() throws IOException {
      final Fixture oldCompiler = fixture("old-compiler");
      managedCompiler(oldCompiler).setVersion("2.1");

      final MavenPreconditionInventory.Snapshot oldCompilerSnapshot = capture(oldCompiler);

      assertThat(oldCompilerSnapshot.complete()).isFalse();
      assertThat(oldCompilerSnapshot.classProviders().detail()).contains("at least 3.13");

      final Fixture unboundProcProperty = fixture("compiler-3.12");
      managedCompiler(unboundProcProperty).setVersion("3.12.0");

      final MavenPreconditionInventory.Snapshot unboundProcSnapshot = capture(unboundProcProperty);

      assertThat(unboundProcSnapshot.complete()).isFalse();
      assertThat(unboundProcSnapshot.classProviders().detail()).contains("at least 3.13");

      final Fixture supportedCompiler = fixture("compiler-3.13");

      assertThat(capture(supportedCompiler).complete()).isTrue();

      final Fixture activeCompilerDependency = fixture("active-compiler-dependency");
      final Plugin activeCompiler = compilerPlugin();
      activeCompiler.addDependency(compilerExtensionDependency());
      activeCompilerDependency.project().getBuild().addPlugin(activeCompiler);

      final MavenPreconditionInventory.Snapshot activeDependencySnapshot =
          capture(activeCompilerDependency);

      assertThat(activeDependencySnapshot.complete()).isFalse();
      assertThat(activeDependencySnapshot.classProviders().detail())
          .contains("Maven Compiler Plugin dependencies");

      final Fixture managedCompilerDependency = fixture("managed-compiler-dependency");
      managedCompiler(managedCompilerDependency).addDependency(compilerExtensionDependency());

      final MavenPreconditionInventory.Snapshot managedDependencySnapshot =
          capture(managedCompilerDependency);

      assertThat(managedDependencySnapshot.complete()).isFalse();
      assertThat(managedDependencySnapshot.classProviders().detail())
          .contains("Maven Compiler Plugin dependencies");

      final Fixture unresolvedCompiler = fixture("unresolved-compiler");
      managedCompiler(unresolvedCompiler).setVersion("${unknown.compiler.version}");

      final MavenPreconditionInventory.Snapshot unresolvedCompilerSnapshot =
          capture(unresolvedCompiler);

      assertThat(unresolvedCompilerSnapshot.complete()).isFalse();
      assertThat(unresolvedCompilerSnapshot.classProviders().detail())
          .contains("unresolved compiler property");

      final Fixture oldRelease = fixture("old-release");
      oldRelease.project().getProperties().setProperty("maven.compiler.release", "8");
      writeSource(
          oldRelease.productionSources(),
          "Outer.java",
          "public class Outer { private static class Hidden { private Hidden() {} } "
              + "public static Object create() { return new Hidden(); } }\n");

      final MavenPreconditionInventory.Snapshot oldReleaseSnapshot = capture(oldRelease);

      assertThat(oldReleaseSnapshot.complete()).isFalse();
      assertThat(oldReleaseSnapshot.classProviders().detail()).contains("at least 11");

      final Fixture oldTestRelease = fixture("old-test-release");
      oldTestRelease.project().getProperties().setProperty("maven.compiler.testRelease", "8");
      assertThat(capture(oldTestRelease).complete()).isTrue();

      final Fixture oldTestSourceTarget = fixture("old-test-source-target");
      oldTestSourceTarget.project().getProperties().remove("maven.compiler.release");
      oldTestSourceTarget.project().getProperties().setProperty("maven.compiler.source", "21");
      oldTestSourceTarget.project().getProperties().setProperty("maven.compiler.target", "21");
      oldTestSourceTarget.project().getProperties().remove("maven.compiler.testRelease");
      oldTestSourceTarget.project().getProperties().setProperty("maven.compiler.testSource", "8");
      oldTestSourceTarget.project().getProperties().setProperty("maven.compiler.testTarget", "8");
      assertThat(capture(oldTestSourceTarget).complete()).isTrue();

      final Fixture oldTestExecutionTarget = fixture("old-test-execution-target");
      final Plugin compiler = compilerPlugin();
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      testCompile.setConfiguration(configuration("testRelease", "8"));
      compiler.addExecution(testCompile);
      oldTestExecutionTarget.project().getBuild().addPlugin(compiler);
      assertThat(capture(oldTestExecutionTarget).complete()).isTrue();
    }
  }

  /** WHY: Groups executions that can add providers after inventory capture. */
  @Nested
  @DisplayName("Lifecycle plugin and package providers")
  class LifecyclePluginTests {
    @Test
    void enforcerAndFilteredResourcesMakeInventoryIncomplete() throws IOException {
      final Fixture enforcerFixture = fixture("enforcer-execution");
      final Plugin enforcer = new Plugin();
      enforcer.setGroupId(MAVEN_PLUGIN_GROUP);
      enforcer.setArtifactId(ENFORCER_PLUGIN);
      final PluginExecution execution = new PluginExecution();
      execution.setId("custom-rule");
      execution.setPhase("initialize");
      execution.setGoals(List.of("enforce"));
      enforcer.addExecution(execution);
      enforcerFixture.project().getBuild().addPlugin(enforcer);

      final MavenPreconditionInventory.Snapshot enforcerSnapshot = capture(enforcerFixture);

      assertThat(enforcerSnapshot.complete()).isFalse();
      assertThat(enforcerSnapshot.classProviders().detail()).contains(ENFORCER_PLUGIN);

      final Fixture earlierEnforcer = fixture("enforcer-before-inventory");
      final Plugin earlierPlugin = new Plugin();
      earlierPlugin.setGroupId(MAVEN_PLUGIN_GROUP);
      earlierPlugin.setArtifactId(ENFORCER_PLUGIN);
      final PluginExecution earlierExecution = new PluginExecution();
      earlierExecution.setId("default-enforce");
      earlierExecution.setGoals(List.of("enforce"));
      earlierPlugin.addExecution(earlierExecution);
      earlierEnforcer.project().getBuild().addPlugin(earlierPlugin);

      assertThat(capture(earlierEnforcer).complete()).isTrue();

      final Fixture filteredProductionResources = fixture("filtered-production-resources");
      filteredProductionResources.project().getBuild().getResources().get(0).setFiltering(true);
      assertGenerationIncomplete(filteredProductionResources, "resources enable filtering");

      final Fixture filteredTestResources = fixture("filtered-test-resources");
      filteredTestResources.project().getBuild().getTestResources().get(0).setFiltering(true);
      assertThat(capture(filteredTestResources).complete()).isTrue();
    }

    @Test
    void preCaptureEnforcerAllowsOnlyKnownBuiltInRulesWithoutExtensions() throws IOException {
      final Fixture builtInRulesFixture = fixture("enforcer-built-in-rules");
      final Xpp3Dom builtInRules = new Xpp3Dom("rules");
      for (final String name :
          List.of(
              "requireJavaVersion",
              "requireMavenVersion",
              "requirePluginVersions",
              "banDuplicatePomDependencyVersions",
              "dependencyConvergence",
              "requireUpperBoundDeps")) {
        addEnforcerRule(builtInRules, name);
      }
      final Plugin builtInPlugin = enforcerPlugin();
      builtInPlugin.setConfiguration(enforcerConfiguration(builtInRules));
      builtInPlugin.addExecution(enforcerExecution());
      builtInRulesFixture.project().getBuild().addPlugin(builtInPlugin);

      assertThat(capture(builtInRulesFixture).complete()).isTrue();

      final Xpp3Dom customRule = new Xpp3Dom("requireJavaVersion");
      customRule.setAttribute("implementation", "com.example.CustomRule");
      final Fixture customRuleFixture = fixture("enforcer-custom-rule");
      final Plugin customRulePlugin = enforcerPlugin();
      customRulePlugin.setConfiguration(enforcerConfiguration(enforcerRules(customRule)));
      customRulePlugin.addExecution(enforcerExecution());
      customRuleFixture.project().getBuild().addPlugin(customRulePlugin);

      final MavenPreconditionInventory.Snapshot customRuleSnapshot = capture(customRuleFixture);

      assertThat(customRuleSnapshot.complete()).isFalse();
      assertThat(customRuleSnapshot.classProviders().detail()).contains("custom Enforcer rule");

      final Fixture customDependencyFixture = fixture("enforcer-custom-dependency");
      final Plugin customDependencyPlugin = enforcerPlugin();
      customDependencyPlugin.addExecution(enforcerExecution());
      final Dependency dependency = new Dependency();
      dependency.setGroupId(EXAMPLE_GROUP);
      dependency.setArtifactId("custom-enforcer-rule");
      dependency.setVersion(TEST_VERSION);
      customDependencyPlugin.addDependency(dependency);
      customDependencyFixture.project().getBuild().addPlugin(customDependencyPlugin);

      final MavenPreconditionInventory.Snapshot customDependencySnapshot =
          capture(customDependencyFixture);

      assertThat(customDependencySnapshot.complete()).isFalse();
      assertThat(customDependencySnapshot.classProviders().detail())
          .contains("Enforcer plugin dependencies");
    }

    private static void addEnforcerRule(final Xpp3Dom rules, final String name) {
      rules.addChild(new Xpp3Dom(name));
    }

    @Test
    void downstreamProviderGeneratorsMakeInventoryIncomplete() throws IOException {
      for (final String phase :
          List.of(
              GOAL_CLEAN,
              "validate",
              "generate-test-sources",
              PROCESS_TEST_RESOURCES,
              PROCESS_CLASSES_PHASE,
              "process-test-classes",
              GOAL_PACKAGE)) {
        final Fixture fixture = fixture("generator-" + phase);
        addUnknownGenerator(fixture, phase);

        final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

        assertThat(snapshot.complete()).isFalse();
        assertThat(snapshot.classProviders().detail()).contains("downstream provider generation");
      }

      final Fixture laterSiteGenerator = fixture("later-site-generator");
      addUnknownGenerator(laterSiteGenerator, GOAL_SITE);
      assertThat(capture(laterSiteGenerator).complete()).isTrue();

      final Fixture extensionFixture = fixture("plugin-extension");
      final Plugin extension = new Plugin();
      extension.setGroupId(EXAMPLE_GROUP);
      extension.setArtifactId("provider-extension");
      extension.setExtensions(true);
      extensionFixture.project().getBuild().addPlugin(extension);

      final MavenPreconditionInventory.Snapshot extensionSnapshot = capture(extensionFixture);

      assertThat(extensionSnapshot.complete()).isFalse();
      assertThat(extensionSnapshot.classProviders().detail()).contains("plugin extension");
    }

    @Test
    @DisplayName("ADR-0008/trusted process-classes rejects same-phase and later writers")
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    void trustedProcessClassesRejectsSamePhaseAndLaterWriters() throws IOException {
      for (final String phase : List.of(PROCESS_CLASSES_PHASE, "verify")) {
        final Fixture fixture = fixture("trusted-writer-" + phase);
        addUnknownGenerator(fixture, phase);
        final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
        request.setGoals(List.of(GOAL_CLEAN, phase));
        final MavenSession session = new MavenSession(null, request, null, fixture.project());
        session.getUserProperties().setProperty(SKIP_TESTS, TRUE);
        session.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);

        assertThatThrownBy(
                () ->
                    MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
                        fixture.project(), session, true))
            .isInstanceOf(IOException.class)
            .hasMessageContaining("lifecycle writer");
      }
    }

    @Test
    @DisplayName("ADR-0008/testResources output is outside runtime inventory")
    void defaultTestResourcesAreExcludedFromRuntimeInventory() throws IOException {
      final Fixture fixture = fixture("trusted-skipped-test-resources");
      addDefaultTestResourcesExecution(fixture.project(), null);
      final Path staleTestClass = fixture.testOutput().resolve("stale/Provider.class");
      writeClass(staleTestClass, "stale/Provider");
      final MavenSession session = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_PACKAGE);
      session.getUserProperties().setProperty(MAVEN_TEST_SKIP, FALSE);
      session.getUserProperties().setProperty(SKIP_TESTS, TRUE);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(),
              session,
              fixture.plan(),
              trustedProcessClassesAnalysis(fixture.analysis()),
              true);

      assertAll(
          "testResources output does not enter the packaged runtime provider inventory",
          () -> Assertions.assertTrue(snapshot.complete(), "test resources preserve completeness"),
          () ->
              assertThat(snapshot.classProviders().providers())
                  .noneMatch(provider -> provider.path().equals(staleTestClass)));
    }

    @Test
    @DisplayName("ADR-0008/testResources does not require maven.test.skip")
    void defaultTestResourcesAllowsEitherTestCompilationSkipSetting() throws IOException {
      final Fixture skipTestsOnly = fixture("trusted-test-resources-skip-tests-only");
      addDefaultTestResourcesExecution(skipTestsOnly.project(), null);
      final MavenSession skipTestsSession =
          sessionForGoals(skipTestsOnly.project(), GOAL_CLEAN, GOAL_PACKAGE);
      skipTestsSession.getUserProperties().setProperty(SKIP_TESTS, TRUE);
      final MavenPreconditionInventory.Snapshot skipTestsSnapshot =
          MavenPreconditionInventory.capture(
              skipTestsOnly.project(),
              skipTestsSession,
              skipTestsOnly.plan(),
              trustedProcessClassesAnalysis(skipTestsOnly.analysis()),
              true);

      final Fixture skipFalse = fixture("trusted-test-resources-skip-false");
      addDefaultTestResourcesExecution(skipFalse.project(), configuration(SKIP, FALSE));
      final MavenSession skipFalseSession =
          sessionForGoals(skipFalse.project(), GOAL_CLEAN, GOAL_PACKAGE);
      skipFalseSession.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);
      final MavenPreconditionInventory.Snapshot skipFalseSnapshot =
          MavenPreconditionInventory.capture(
              skipFalse.project(),
              skipFalseSession,
              skipFalse.plan(),
              trustedProcessClassesAnalysis(skipFalse.analysis()),
              true);

      assertAll(
          "test compilation skip settings do not define runtime provider completeness",
          () ->
              Assertions.assertTrue(
                  skipTestsSnapshot.complete(), "skipTests does not change runtime completeness"),
          () ->
              Assertions.assertTrue(
                  skipFalseSnapshot.complete(), "test compiler skip does not change completeness"));
    }

    @Test
    @DisplayName("ADR-0008/testResources skip flags do not affect runtime inventory")
    void defaultTestResourcesSkipFlagsDoNotAffectRuntimeInventory() throws IOException {
      final Fixture explicitExecutionSkip = fixture("test-resources-explicit-execution-skip");
      addDefaultTestResourcesExecution(explicitExecutionSkip.project(), configuration(SKIP, TRUE));
      final MavenPreconditionInventory.Snapshot explicitSkip =
          captureAtTestResources(explicitExecutionSkip);

      final Fixture executionOverridesPlugin = fixture("test-resources-execution-overrides-plugin");
      final Plugin executionOverride = resourcesPlugin();
      executionOverride.setConfiguration(configuration(SKIP, FALSE));
      addTestResourcesExecution(executionOverride, configuration(SKIP, TRUE));
      executionOverridesPlugin.project().getBuild().addPlugin(executionOverride);
      final MavenPreconditionInventory.Snapshot executionSkip =
          captureAtTestResources(executionOverridesPlugin);

      final Fixture pluginSkipFalse = fixture("test-resources-plugin-skip-false");
      final Plugin pluginOverride = resourcesPlugin();
      pluginOverride.setConfiguration(configuration(SKIP, FALSE));
      addTestResourcesExecution(pluginOverride, null);
      pluginSkipFalse.project().getBuild().addPlugin(pluginOverride);
      final MavenSession propertyCannotOverridePluginFalse =
          sessionForGoals(pluginSkipFalse.project(), GOAL_CLEAN, PROCESS_TEST_RESOURCES);
      propertyCannotOverridePluginFalse.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);
      final MavenPreconditionInventory.Snapshot pluginFalse =
          MavenPreconditionInventory.capture(
              pluginSkipFalse.project(),
              propertyCannotOverridePluginFalse,
              pluginSkipFalse.plan(),
              trustedProcessClassesAnalysis(pluginSkipFalse.analysis()),
              true);

      final Fixture executionSkipFalse = fixture("test-resources-execution-skip-false");
      addDefaultTestResourcesExecution(executionSkipFalse.project(), configuration(SKIP, FALSE));
      final MavenSession propertyCannotOverrideExecutionFalse =
          sessionForGoals(executionSkipFalse.project(), GOAL_CLEAN, PROCESS_TEST_RESOURCES);
      propertyCannotOverrideExecutionFalse.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);
      final MavenPreconditionInventory.Snapshot executionFalse =
          MavenPreconditionInventory.capture(
              executionSkipFalse.project(),
              propertyCannotOverrideExecutionFalse,
              executionSkipFalse.plan(),
              trustedProcessClassesAnalysis(executionSkipFalse.analysis()),
              true);

      assertAll(
          "valid skip values are irrelevant to the runtime inventory boundary",
          () ->
              Assertions.assertTrue(
                  explicitSkip.complete(), "explicit skip preserves completeness"),
          () ->
              Assertions.assertTrue(
                  executionSkip.complete(), "execution skip preserves completeness"),
          () ->
              Assertions.assertTrue(
                  pluginFalse.complete(), "plugin skip does not change runtime completeness"),
          () ->
              Assertions.assertTrue(
                  executionFalse.complete(),
                  "execution skip does not change runtime completeness"));
    }

    @Test
    @DisplayName("ADR-0008/trusted capture rejects supported writers bound at capture phase")
    void trustedProcessClassesRejectsCompilerAndResourceWritersAtCapturePhase() throws IOException {
      for (final Plugin writer :
          List.of(
              lifecyclePlugin(
                  MAVEN_PLUGIN_GROUP, "maven-compiler-plugin", "compile-at-capture", "compile"),
              lifecyclePlugin(
                  MAVEN_PLUGIN_GROUP,
                  MAVEN_RESOURCES_PLUGIN,
                  "resources-at-capture",
                  "resources"))) {
        final Fixture fixture = fixture("same-phase-supported-writer-" + writer.getArtifactId());
        final PluginExecution execution = writer.getExecutions().get(0);
        execution.setPhase(PROCESS_CLASSES_PHASE);
        assertTrustedWriterRejected(fixture, writer);
      }
    }

    @Test
    @DisplayName("ADR-0008/trusted capture rejects resource writers before the requested endpoint")
    void trustedProcessClassesRejectsLaterResourceWriters() throws IOException {
      final Fixture fixture = fixture("trusted-later-resource-writer");
      final Plugin writer =
          lifecyclePlugin(
              MAVEN_PLUGIN_GROUP,
              MAVEN_RESOURCES_PLUGIN,
              "resources-before-verify",
              "resources",
              PROCESS_TEST_RESOURCES);

      assertTrustedWriterRejected(fixture, writer, "verify");
    }

    @Test
    @DisplayName("ADR-0008/trusted capture preserves package and Shade validation")
    void trustedCaptureKeepsRequestedPackageValidation() throws IOException {
      final Fixture packageWithoutClean = fixture("trusted-package-without-clean");
      final MavenSession packageSession = sessionForGoals(packageWithoutClean.project(), "package");
      packageSession.getUserProperties().setProperty("maven.test.skip", TRUE);
      assertThatThrownBy(
              () ->
                  MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
                      packageWithoutClean.project(), packageSession, true))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("requires a clean goal before packaging");

      final Fixture unsafeShade = fixture("trusted-package-unsafe-shade");
      final Plugin shade = shadePlugin();
      shade.setConfiguration(shadeRootConfiguration());
      pluginConfiguration(shade).addChild(setting("extraArtifacts", "com.example:unscanned"));
      unsafeShade.project().getBuild().addPlugin(shade);
      final MavenSession cleanPackageSession =
          sessionForGoals(unsafeShade.project(), GOAL_CLEAN, "package");
      cleanPackageSession.getUserProperties().setProperty("maven.test.skip", TRUE);
      assertThatThrownBy(
              () ->
                  MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
                      unsafeShade.project(), cleanPackageSession, true))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("unmodeled Maven Shade Plugin root option");
    }

    @Test
    void exactInheritedShadeConfigurationKeepsInventoryComplete() throws IOException {
      final Fixture fixture = fixture("safe-shade-configuration");
      final Plugin managedShade = shadePluginManagement();
      final Plugin activeShade = shadePlugin();
      activeShade.setConfiguration(shadeRootConfiguration());
      fixture.project().getBuild().getPluginManagement().addPlugin(managedShade);
      fixture.project().getBuild().addPlugin(activeShade);

      final MavenPreconditionInventory.Snapshot snapshot =
          capture(fixture, sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY));

      assertThat(snapshot.complete()).isTrue();

      final Fixture partialEffective = fixture("shade-inheritance-not-merged");
      partialEffective
          .project()
          .getBuild()
          .getPluginManagement()
          .addPlugin(shadePluginManagement());
      final Plugin partialActive = shadePlugin();
      partialActive.setConfiguration(configuration("createDependencyReducedPom", FALSE));
      partialEffective.project().getBuild().addPlugin(partialActive);
      assertGenerationIncomplete(partialEffective, "does not include managed filters");

      final Fixture mergedExecution = fixture("shade-managed-execution-merged");
      final Plugin managedExecutionPlugin = shadePluginManagement();
      managedExecutionPlugin.addExecution(shadePlugin().getExecutions().get(0));
      mergedExecution.project().getBuild().getPluginManagement().addPlugin(managedExecutionPlugin);
      final Plugin effectiveExecutionPlugin = shadePlugin();
      effectiveExecutionPlugin.setConfiguration(shadeRootConfiguration());
      mergedExecution.project().getBuild().addPlugin(effectiveExecutionPlugin);
      assertThat(
              capture(
                      mergedExecution,
                      sessionForGoals(mergedExecution.project(), GOAL_CLEAN, GOAL_VERIFY))
                  .complete())
          .isTrue();

      final Fixture overriddenManagedExecution = fixture("shade-managed-execution-overridden");
      final Plugin managedExecution = shadePluginManagement();
      managedExecution.addExecution(shadePlugin().getExecutions().get(0));
      overriddenManagedExecution
          .project()
          .getBuild()
          .getPluginManagement()
          .addPlugin(managedExecution);
      final Plugin overriddenExecution = shadePlugin();
      final Xpp3Dom otherMainClass = shadeExecutionConfiguration();
      otherMainClass
          .getChild(SHADE_TRANSFORMERS)
          .getChild(0)
          .getChild("mainClass")
          .setValue("org.example.application.Other");
      overriddenExecution.getExecutions().get(0).setConfiguration(otherMainClass);
      overriddenExecution.setConfiguration(shadeRootConfiguration());
      overriddenManagedExecution.project().getBuild().addPlugin(overriddenExecution);
      assertGenerationIncomplete(
          overriddenManagedExecution, "overrides the managed manifest mainClass");

      final Fixture inactiveManagement = fixture("inactive-shade-management");
      final Plugin unusedManagedShade = new Plugin();
      unusedManagedShade.setGroupId(MAVEN_PLUGIN_GROUP);
      unusedManagedShade.setArtifactId("maven-shade-plugin");
      unusedManagedShade.setConfiguration(configuration("relocations", "unmodeled"));
      inactiveManagement.project().getBuild().getPluginManagement().addPlugin(unusedManagedShade);
      assertThat(capture(inactiveManagement).complete()).isTrue();
    }

    @Test
    void untrustedPackagePluginDoesNotBlockBuildStoppingAtProcessClasses() throws IOException {
      final Fixture packagePluginFixture = fixture("package-plugin-after-process-classes");
      final Plugin customPackager = new Plugin();
      customPackager.setGroupId("org.example");
      customPackager.setArtifactId("custom-packager");
      final PluginExecution execution = new PluginExecution();
      execution.setId("repackage-custom");
      execution.setPhase("package");
      customPackager.addExecution(execution);
      packagePluginFixture.project().getBuild().addPlugin(customPackager);

      final MavenPreconditionInventory.Snapshot atProcessClasses =
          capture(
              packagePluginFixture,
              sessionForGoals(packagePluginFixture.project(), "process-classes"));
      final MavenPreconditionInventory.Snapshot atVerify =
          capture(
              packagePluginFixture, sessionForGoals(packagePluginFixture.project(), GOAL_VERIFY));

      assertAll(
          "Untrusted package-phase plugin is ignored when build stops at process-classes",
          () ->
              Assertions.assertTrue(
                  atProcessClasses.complete(), "process-classes snapshot should be complete"),
          () ->
              Assertions.assertFalse(atVerify.complete(), "verify snapshot should be incomplete"));
    }

    @Test
    void shadeExecutionsAreCheckedAgainstTheRequestedLifecycleEndpoint() throws IOException {
      final Fixture safeFutureShade = fixture("safe-shade-after-compile");
      safeFutureShade.project().getBuild().addPlugin(shadePlugin());
      final MavenPreconditionInventory.Snapshot futureSnapshot =
          capture(safeFutureShade, sessionForGoals(safeFutureShade.project(), GOAL_COMPILE));
      assertThat(futureSnapshot.complete()).isTrue();

      final Fixture packageWithoutClean = fixture("shade-package-without-clean");
      packageWithoutClean.project().getBuild().addPlugin(shadePlugin());
      final MavenPreconditionInventory.Snapshot staleJarRisk =
          capture(packageWithoutClean, sessionForGoals(packageWithoutClean.project(), GOAL_VERIFY));
      assertThat(staleJarRisk.complete()).isFalse();
      assertThat(staleJarRisk.classProviders().detail()).contains("requires a clean goal");

      final Fixture earlyShade = fixture("early-shade-before-compile");
      final Plugin earlyShadePlugin = shadePlugin();
      earlyShadePlugin.getExecutions().get(0).setPhase("initialize");
      earlyShade.project().getBuild().addPlugin(earlyShadePlugin);
      final MavenPreconditionInventory.Snapshot earlySnapshot =
          capture(earlyShade, sessionForGoals(earlyShade.project(), GOAL_COMPILE));
      assertThat(earlySnapshot.complete()).isFalse();
      assertThat(earlySnapshot.classProviders().detail())
          .contains("one package-phase shade execution");

      final Fixture unknownShadePhase = fixture("unknown-shade-phase");
      final Plugin unknownShadePlugin = shadePlugin();
      unknownShadePlugin.getExecutions().get(0).setPhase("not-a-lifecycle-phase");
      unknownShadePhase.project().getBuild().addPlugin(unknownShadePlugin);
      assertGenerationIncomplete(unknownShadePhase, "unknown phase");

      final Fixture shadeExtensionBeforePackage = fixture("shade-extension-before-package");
      final Plugin extension = shadePluginDeclaration();
      extension.setExtensions(true);
      shadeExtensionBeforePackage.project().getBuild().addPlugin(extension);
      final MavenPreconditionInventory.Snapshot extensionSnapshot =
          capture(
              shadeExtensionBeforePackage,
              sessionForGoals(shadeExtensionBeforePackage.project(), GOAL_COMPILE));
      assertThat(extensionSnapshot.complete()).isFalse();
      assertThat(extensionSnapshot.classProviders().detail()).contains("extension");
    }

    @Test
    void cleanPropertiesCannotPreserveAnOlderShadeInputJar() throws IOException {
      for (final Map.Entry<String, String> property :
          Map.of(
                  CLEAN_SKIP_PROPERTY,
                  TRUE,
                  "clean.skip",
                  TRUE,
                  "maven.clean.excludeDefaultDirectories",
                  TRUE,
                  "clean.excludeDefaultDirectories",
                  TRUE,
                  "maven.clean.failOnError",
                  FALSE,
                  "clean.failOnError",
                  FALSE,
                  "maven.clean.fastMode",
                  "defer")
              .entrySet()) {
        assertUnsafeCleanProperty(property.getKey(), property.getValue());
      }

      final Fixture projectProperty = fixture("project-clean-skip");
      projectProperty.project().getProperties().setProperty(CLEAN_SKIP_PROPERTY, TRUE);
      projectProperty.project().getBuild().addPlugin(shadePlugin());
      final MavenPreconditionInventory.Snapshot projectSnapshot =
          capture(
              projectProperty, sessionForGoals(projectProperty.project(), GOAL_CLEAN, GOAL_VERIFY));
      assertThat(projectSnapshot.complete()).isFalse();
      assertThat(projectSnapshot.classProviders().detail()).contains(CLEAN_SKIP_PROPERTY);

      final Fixture noShadeProperty = fixture("non-shaded-project-clean-skip");
      noShadeProperty.project().getProperties().setProperty(CLEAN_SKIP_PROPERTY, TRUE);
      final MavenPreconditionInventory.Snapshot noShadeSnapshot =
          capture(
              noShadeProperty, sessionForGoals(noShadeProperty.project(), GOAL_CLEAN, GOAL_VERIFY));
      assertThat(noShadeSnapshot.complete()).isFalse();
      assertThat(noShadeSnapshot.classProviders().detail()).contains(CLEAN_SKIP_PROPERTY);

      final Fixture requestProperty = fixture("request-clean-fast-mode");
      requestProperty.project().getBuild().addPlugin(shadePlugin());
      final MavenSession requestPropertySession =
          sessionForGoals(requestProperty.project(), GOAL_CLEAN, GOAL_VERIFY);
      requestSystemProperties(requestPropertySession).setProperty("maven.clean.fastMode", "defer");
      final MavenPreconditionInventory.Snapshot requestSnapshot =
          capture(requestProperty, requestPropertySession);
      assertThat(requestSnapshot.complete()).isFalse();
      assertThat(requestSnapshot.classProviders().detail()).contains("maven.clean.fastMode");

      final Fixture explicitSafeValues = fixture("explicit-safe-clean-properties");
      explicitSafeValues.project().getProperties().setProperty(CLEAN_SKIP_PROPERTY, FALSE);
      explicitSafeValues
          .project()
          .getProperties()
          .setProperty("clean.excludeDefaultDirectories", FALSE);
      explicitSafeValues.project().getProperties().setProperty("maven.clean.failOnError", TRUE);
      explicitSafeValues.project().getBuild().addPlugin(shadePlugin());
      final MavenSession explicitSafeSession =
          sessionForGoals(explicitSafeValues.project(), GOAL_CLEAN, GOAL_VERIFY);
      explicitSafeSession.getUserProperties().setProperty(CLEAN_SKIP_PROPERTY, FALSE);
      assertThat(capture(explicitSafeValues, explicitSafeSession).complete()).isTrue();
    }

    private void assertUnsafeCleanProperty(final String key, final String value)
        throws IOException {
      final Fixture fixture = fixture("unsafe-clean-property-" + key);
      fixture.project().getBuild().addPlugin(shadePlugin());
      final MavenSession session = sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY);
      session.getUserProperties().setProperty(key, value);

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture, session);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail()).contains(key);
    }

    @Test
    void unmodeledShadeAndJarConfigurationSuppressesProof() throws IOException {
      final Fixture unsafeShade = fixture("shade-extra-inputs");
      final Plugin shadeWithExtraInputs = shadePlugin();
      shadeWithExtraInputs.setConfiguration(shadeRootConfiguration());
      pluginConfiguration(shadeWithExtraInputs)
          .addChild(setting("extraArtifacts", "com.example:unscanned"));
      unsafeShade.project().getBuild().addPlugin(shadeWithExtraInputs);
      assertGenerationIncomplete(unsafeShade, "unmodeled Maven Shade Plugin root option");

      final Fixture unsafeTransformer = fixture("shade-custom-transformer");
      final Plugin customTransformer = shadePlugin();
      final PluginExecution transformerExecution = customTransformer.getExecutions().get(0);
      final Xpp3Dom customConfiguration = shadeExecutionConfiguration();
      customConfiguration
          .getChild(SHADE_TRANSFORMERS)
          .getChild(0)
          .setAttribute("implementation", "com.example.CustomTransformer");
      transformerExecution.setConfiguration(customConfiguration);
      unsafeTransformer.project().getBuild().addPlugin(customTransformer);
      assertGenerationIncomplete(unsafeTransformer, "built-in manifest transformer");

      final Fixture unsafeFilter = fixture("shade-class-filter");
      final Plugin managedShade = shadePluginManagement();
      final Xpp3Dom filters = pluginConfiguration(managedShade).getChild(SHADE_FILTERS);
      final Xpp3Dom excludes = filters.getChild(0).getChild("excludes");
      excludes.addChild(setting("exclude", "**/*.class"));
      unsafeFilter.project().getBuild().getPluginManagement().addPlugin(managedShade);
      unsafeFilter.project().getBuild().addPlugin(shadePlugin());
      assertGenerationIncomplete(unsafeFilter, "only exclude signature resources");

      final Fixture duplicateEffectiveFilters = fixture("shade-duplicate-filters");
      final Plugin duplicateFilterShade = shadePlugin();
      final Xpp3Dom duplicateRoot = shadeRootConfiguration();
      duplicateRoot.addChild(shadeRootConfiguration().getChild("filters"));
      duplicateFilterShade.setConfiguration(duplicateRoot);
      duplicateEffectiveFilters.project().getBuild().addPlugin(duplicateFilterShade);
      assertGenerationIncomplete(
          duplicateEffectiveFilters, "duplicate Maven Shade Plugin option filters");

      final Fixture multipleTransformers = fixture("shade-multiple-transformers");
      final Plugin multipleTransformerShade = shadePlugin();
      final Xpp3Dom multipleTransformerConfiguration = shadeExecutionConfiguration();
      multipleTransformerConfiguration
          .getChild(SHADE_TRANSFORMERS)
          .addChild(shadeExecutionConfiguration().getChild(SHADE_TRANSFORMERS).getChild(0));
      multipleTransformerShade
          .getExecutions()
          .get(0)
          .setConfiguration(multipleTransformerConfiguration);
      multipleTransformers.project().getBuild().addPlugin(multipleTransformerShade);
      assertGenerationIncomplete(multipleTransformers, "one built-in manifest transformer");
    }

    @Test
    void unmodeledJarConfigurationSuppressesProof() throws IOException {
      final Fixture unsafeJarConfiguration = fixture("jar-custom-configuration");
      final Plugin jar = jarPlugin();
      jar.setConfiguration(configuration("classesDirectory", "/outside/classes"));
      unsafeJarConfiguration.project().getBuild().addPlugin(jar);
      assertGenerationIncomplete(unsafeJarConfiguration, "custom Maven JAR Plugin configuration");

      final Fixture unsafeJarExecution = fixture("jar-custom-execution");
      final Plugin jarWithExecution = jarPlugin();
      final PluginExecution customJar = new PluginExecution();
      customJar.setId("custom-jar");
      customJar.setPhase(GOAL_PACKAGE);
      customJar.setGoals(List.of(JAR_TYPE));
      jarWithExecution.addExecution(customJar);
      unsafeJarExecution.project().getBuild().addPlugin(jarWithExecution);
      assertGenerationIncomplete(unsafeJarExecution, "custom Maven JAR Plugin executions");

      final Fixture managedJarConfiguration = fixture("managed-jar-custom-configuration");
      final Plugin managedJar = jarPlugin();
      managedJar.setConfiguration(configuration("classesDirectory", "/outside/classes"));
      managedJarConfiguration.project().getBuild().getPluginManagement().addPlugin(managedJar);
      assertGenerationIncomplete(managedJarConfiguration, "custom Maven JAR Plugin configuration");

      final Fixture managedJarDependency = fixture("managed-jar-plugin-dependency");
      final Plugin jarWithDependency = jarPlugin();
      final Dependency jarDependency = new Dependency();
      jarDependency.setGroupId(EXAMPLE_GROUP);
      jarDependency.setArtifactId("custom-jar-plugin");
      jarDependency.setVersion(TEST_VERSION);
      jarWithDependency.addDependency(jarDependency);
      managedJarDependency.project().getBuild().getPluginManagement().addPlugin(jarWithDependency);
      assertGenerationIncomplete(managedJarDependency, "Maven JAR Plugin dependencies");
    }

    @Test
    void shadeExtensionsAndSourceContentPropertySuppressProof() throws IOException {
      final Fixture dependencyFixture = fixture("shade-plugin-dependency");
      final Plugin shadeWithDependency = shadePlugin();
      final Dependency dependency = new Dependency();
      dependency.setGroupId(EXAMPLE_GROUP);
      dependency.setArtifactId("custom-shader");
      dependency.setVersion(TEST_VERSION);
      shadeWithDependency.addDependency(dependency);
      dependencyFixture.project().getBuild().addPlugin(shadeWithDependency);
      assertGenerationIncomplete(dependencyFixture, "Maven Shade Plugin dependencies");

      final Fixture managedDependencyFixture = fixture("managed-shade-plugin-dependency");
      final Plugin managedShade = shadePluginManagement();
      managedShade.addDependency(dependency);
      managedDependencyFixture.project().getBuild().getPluginManagement().addPlugin(managedShade);
      managedDependencyFixture.project().getBuild().addPlugin(shadePlugin());
      assertGenerationIncomplete(
          managedDependencyFixture, "Maven Shade Plugin management dependencies");

      final Fixture extensionFixture = fixture("shade-extension");
      final Plugin shadeExtension = shadePlugin();
      shadeExtension.setExtensions(true);
      extensionFixture.project().getBuild().addPlugin(shadeExtension);
      assertGenerationIncomplete(extensionFixture, "Maven Shade Plugin extension");

      final Fixture missingManagedExecution = fixture("missing-effective-managed-shade-execution");
      final Plugin managedWithExecution = shadePluginManagement();
      managedWithExecution.addExecution(shadePlugin().getExecutions().get(0));
      missingManagedExecution
          .project()
          .getBuild()
          .getPluginManagement()
          .addPlugin(managedWithExecution);
      missingManagedExecution.project().getBuild().addPlugin(shadePluginDeclaration());
      assertGenerationIncomplete(missingManagedExecution, "does not include its managed execution");

      final Fixture wrongVersion = fixture("shade-version");
      final Plugin unsupportedShade = shadePlugin();
      unsupportedShade.setVersion("3.5.0");
      wrongVersion.project().getBuild().addPlugin(unsupportedShade);
      assertGenerationIncomplete(wrongVersion, "version must be exactly 3.6.0");

      final Fixture sourceContent = fixture("shade-source-content-property");
      sourceContent.project().getProperties().setProperty(SHADE_SOURCE_CONTENT_PROPERTY, FALSE);
      sourceContent.project().getBuild().addPlugin(shadePlugin());
      assertGenerationIncomplete(sourceContent, SHADE_SOURCE_CONTENT_PROPERTY);

      final Fixture userProperty = fixture("shade-source-content-user-property");
      userProperty.project().getBuild().addPlugin(shadePlugin());
      final MavenSession userPropertySession = sessionForGoals(userProperty.project(), GOAL_VERIFY);
      userPropertySession.getUserProperties().setProperty(SHADE_SOURCE_CONTENT_PROPERTY, FALSE);
      final MavenPreconditionInventory.Snapshot userPropertySnapshot =
          capture(userProperty, userPropertySession);
      assertThat(userPropertySnapshot.complete()).isFalse();
      assertThat(userPropertySnapshot.classProviders().detail())
          .contains(SHADE_SOURCE_CONTENT_PROPERTY);
    }

    @Test
    void ordinaryCompilerAndDeclaredResourceExecutionsKeepInventoryComplete() throws IOException {
      final Fixture fixture = fixture("ordinary-lifecycle");
      final Plugin compiler = compilerPlugin();
      final PluginExecution productionCompile = new PluginExecution();
      productionCompile.setId(DEFAULT_COMPILE);
      productionCompile.setPhase(GOAL_COMPILE);
      compiler.addExecution(productionCompile);
      final PluginExecution testCompile = new PluginExecution();
      testCompile.setId(DEFAULT_TEST_COMPILE);
      testCompile.setPhase("test-compile");
      compiler.addExecution(testCompile);
      fixture.project().getBuild().addPlugin(compiler);

      final Plugin resources = new Plugin();
      resources.setGroupId(MAVEN_PLUGIN_GROUP);
      resources.setArtifactId(MAVEN_RESOURCES_PLUGIN);
      final PluginExecution productionResources = new PluginExecution();
      productionResources.setId("default-resources");
      productionResources.setPhase("process-resources");
      resources.addExecution(productionResources);
      final PluginExecution testResources = new PluginExecution();
      testResources.setId("default-testResources");
      testResources.setPhase(PROCESS_TEST_RESOURCES);
      resources.addExecution(testResources);
      fixture.project().getBuild().addPlugin(resources);

      final Plugin jar = jarPlugin();
      final PluginExecution defaultJar = new PluginExecution();
      defaultJar.setId("default-jar");
      defaultJar.setPhase(GOAL_PACKAGE);
      defaultJar.setGoals(List.of(JAR_TYPE));
      jar.addExecution(defaultJar);
      fixture.project().getBuild().addPlugin(jar);

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      assertThat(snapshot.complete()).isTrue();
    }

    @Test
    void resourcePluginDependenciesSuppressPreconditionInventory() throws IOException {
      final Fixture active = fixture("active-resources-plugin-dependency");
      final Plugin activeResources = resourcesPlugin();
      activeResources.addDependency(providerPluginDependency());
      active.project().getBuild().addPlugin(activeResources);
      assertGenerationIncomplete(active, "Maven Resources Plugin dependencies");

      final Fixture managed = fixture("managed-resources-plugin-dependency");
      final Plugin managedResources = resourcesPlugin();
      managedResources.addDependency(providerPluginDependency());
      managed.project().getBuild().getPluginManagement().addPlugin(managedResources);
      assertGenerationIncomplete(managed, "Maven Resources Plugin dependencies");

      final Fixture managedActive = fixture("effective-managed-resources-plugin-dependency");
      final Plugin effectiveManagedResources = resourcesPlugin();
      effectiveManagedResources.addDependency(providerPluginDependency());
      managedActive.project().getBuild().getPluginManagement().addPlugin(effectiveManagedResources);
      managedActive.project().getBuild().addPlugin(resourcesPlugin());
      assertGenerationIncomplete(managedActive, "Maven Resources Plugin management dependencies");
    }

    @Test
    void userCompilerOverrideConflictsWithProjectProcessingSetting() throws IOException {
      final Fixture fixture = fixture();
      final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
      request.setGoals(List.of(GOAL_VERIFY));
      final MavenSession session = new MavenSession(null, request, null, fixture.project());
      session.getUserProperties().setProperty(SKIP_TESTS, TRUE);
      session.getUserProperties().setProperty(PROCESSING_PROPERTY, PROCESSING_FULL);

      final MavenPreconditionInventory.Snapshot snapshot =
          MavenPreconditionInventory.capture(
              fixture.project(), session, fixture.plan(), fixture.analysis(), true);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail()).contains("conflicting or unsupported proc");
    }
  }

  private void assertGenerationIncomplete(final Fixture fixture, final String reason)
      throws IOException {
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains(reason);
  }

  // PMD: Maven model fixtures expose nested Xpp3Dom values through accessors.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Xpp3Dom pluginConfiguration(final Plugin plugin) {
    return (Xpp3Dom) plugin.getConfiguration();
  }

  // PMD: Maven model fixtures expose nested Xpp3Dom values through accessors.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Xpp3Dom executionConfiguration(final PluginExecution execution) {
    return (Xpp3Dom) execution.getConfiguration();
  }

  // PMD: Maven's request properties are nested under the execution request API.
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Properties requestSystemProperties(final MavenSession session) {
    return session.getRequest().getSystemProperties();
  }

  @Test
  void missingRetainedArtifactFileProducesIncompleteProofInventory() throws IOException {
    final Fixture fixture = fixture();
    final Artifact retainedArtifact = fixture.plan().resolvedArtifacts().iterator().next();
    retainedArtifact.setFile(null);

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isFalse();
    assertThat(snapshot.classProviders().detail()).contains("has no file");
  }

  @Test
  void indeterminateSourceRootExistenceDoesNotAffectProviderInventory() throws IOException {
    assumeUnixEnvironment();
    final Fixture fixture = fixture();
    final Path unqueryableRoot = fixture.productionSources().resolve("x".repeat(300));
    Assumptions.assumeTrue(!Files.exists(unqueryableRoot, LinkOption.NOFOLLOW_LINKS));
    Assumptions.assumeTrue(!Files.notExists(unqueryableRoot, LinkOption.NOFOLLOW_LINKS));
    fixture.project().addCompileSourceRoot(unqueryableRoot.toString());

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isTrue();
  }

  @Test
  void rawClassBytesAtAnOutputTargetRemainClassProviders() throws IOException {
    final Fixture fixture = fixture();
    assertThat(fixture.project().getResources()).hasSize(1);
    final Path outputTarget = fixture.productionResources().resolve("custom-report.json");
    Files.createDirectories(outputTarget.getParent());
    Files.write(outputTarget, classBytes("hidden/ShadedPrerequisite"));
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            TEST_CVE,
            fixture.coordinate(),
            TEST_RANGE,
            Set.of(),
            null,
            ConfidenceLevel.HIGH,
            PREREQUISITE_COORDINATE,
            "hidden.ShadedPrerequisite");

    final Path realOutputTarget = outputTarget.toRealPath();
    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .anySatisfy(provider -> assertThat(provider.path()).isEqualTo(realOutputTarget));
    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    ExplicitEvidenceTestSupport.genericPrerequisiteFinding(mapping),
                    mapping.affectedCoordinate(),
                    snapshot.classProviders()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  void nonJavaSourceRootMemberIsNotACompiledResourceProvider() throws IOException {
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionSources());
    Files.writeString(fixture.productionSources().resolve("resource.txt"), "resource body");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .noneMatch(
            provider ->
                provider.path().equals(fixture.productionSources().resolve("resource.txt")));
  }

  @Test
  @DisplayName("ADR-0008/uncompiled source files are outside provider inventory")
  void unparsedSourceLanguageDoesNotEnterProviderInventory() throws IOException {
    final Fixture fixture = fixture();
    Files.createDirectories(fixture.productionSources());
    Files.writeString(fixture.productionSources().resolve("generated.scala"), "class Unknown");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .noneMatch(
            provider ->
                provider.path().equals(fixture.productionSources().resolve("generated.scala")));
  }

  @Test
  void localAndAnonymousJavaSourceIsNotScannedBeforeCompilation() throws IOException {
    final Fixture fixture = fixture();
    writeSource(
        fixture.productionSources(),
        "LocalTypes.java",
        "package app; public class LocalTypes { void run() { class Local {} "
            + "Runnable r = new Runnable() { public void run() {} }; } }\n");

    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .noneMatch(
            provider ->
                provider.path().equals(fixture.productionSources().resolve("LocalTypes.java")));
  }

  @Test
  void enumSwitchSourceWithoutCompiledOutputIsNotInventoried() throws IOException {
    final Fixture fixture = fixture();
    writeSource(
        fixture.productionSources(),
        "Holder.java",
        "package app; enum Mode { A, B } "
            + "class Holder { int value(Mode mode) { return switch (mode) { "
            + "case A -> 1; case B -> 2; }; } }\n");
    final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

    assertThat(snapshot.complete()).isTrue();
    assertThat(snapshot.classProviders().providers())
        .noneMatch(
            provider -> provider.path().equals(fixture.productionSources().resolve("Holder.java")));
  }

  @Test
  void socketFilesMakeInventoryIncompleteInsteadOfBeingSkipped() throws IOException {
    assumeUnixEnvironment();
    final Fixture fixture = fixture();
    // Keep UNIX socket paths under macOS's 104-byte sun_path limit.
    final Path shortResources = Files.createTempDirectory(Path.of("/tmp"), "es");
    fixture.project().getResources().get(0).setDirectory(shortResources.toString());
    final Path socketPath = shortResources.resolve("p.sock");

    try (ServerSocketChannel socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
      socket.bind(UnixDomainSocketAddress.of(socketPath));

      final MavenPreconditionInventory.Snapshot snapshot = capture(fixture);

      assertThat(snapshot.complete()).isFalse();
      assertThat(snapshot.classProviders().detail()).contains("Unsupported filesystem entry");
    } finally {
      Files.deleteIfExists(socketPath);
      Files.deleteIfExists(shortResources);
    }
  }

  private MavenPreconditionInventory.Snapshot capture(final Fixture fixture) throws IOException {
    return capture(fixture, sessionForGoals(fixture.project(), GOAL_CLEAN, GOAL_VERIFY));
  }

  private MavenPreconditionInventory.Snapshot capture(
      final Fixture fixture, final MavenSession session) throws IOException {
    return MavenPreconditionInventory.capture(
        fixture.project(), session, fixture.plan(), fixture.analysis(), true);
  }

  private MavenPreconditionInventory.Snapshot captureAtTestResources(final Fixture fixture)
      throws IOException {
    return MavenPreconditionInventory.capture(
        fixture.project(),
        sessionForGoals(fixture.project(), GOAL_CLEAN, PROCESS_TEST_RESOURCES),
        fixture.plan(),
        trustedProcessClassesAnalysis(fixture.analysis()),
        true);
  }

  private static ElisionAnalysisModel.Analysis trustedProcessClassesAnalysis(
      final ElisionAnalysisModel.Analysis analysis) {
    return analysisWithProductionCompleteness(analysis, true, true);
  }

  private static ElisionAnalysisModel.Analysis explicitProductionClassesAnalysis(
      final ElisionAnalysisModel.Analysis analysis) {
    return analysisWithProductionCompleteness(analysis, true, false);
  }

  private static ElisionAnalysisModel.Analysis analysisWithProductionCompleteness(
      final ElisionAnalysisModel.Analysis analysis,
      final boolean productionClassesComplete,
      final boolean trustedProcessClassesContext) {
    return new ElisionAnalysisModel.Analysis(
        new ElisionAnalysisModel.ArtifactViews(
            analysis.artifacts().resolvedSnapshots(),
            analysis.artifacts().directArtifactsPresent(),
            analysis.artifacts().directSnapshots()),
        analysis.decision(),
        analysis.effectiveDecision(),
        new ElisionAnalysisModel.AnalysisEvidence(
            analysis.evidence().classUsageReport(),
            analysis.evidence().bytecodeScan(),
            analysis.evidence().unprovenServiceRoots(),
            productionClassesComplete,
            trustedProcessClassesContext,
            null),
        new TrimResult(
            analysis.trimResult().records(),
            analysis.trimResult().multiReleasePassthroughArtifacts(),
            analysis.trimResult().moduleInfoPassthroughArtifacts(),
            analysis.trimResult().configuredPassThroughArtifacts(),
            analysis.trimResult().cacheHits(),
            analysis.trimResult().maximumCacheHitNanos(),
            analysis.trimResult().analysisRuns(),
            analysis.trimResult().executionEnvironment(),
            analysis.trimResult().toleratedDuplicates()),
        analysis.graphProjection(),
        analysis.mediatedGraph(),
        analysis.policyIdentity());
  }

  private static MavenSession sessionForGoals(final MavenProject project, final String... goals) {
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of(goals));
    final MavenSession session = new MavenSession(null, request, null, project);
    session.getUserProperties().setProperty(SKIP_TESTS, TRUE);
    return session;
  }

  private static void assumeUnixEnvironment() {
    final String operatingSystem = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    Assumptions.assumeTrue(operatingSystem.contains("linux") || operatingSystem.contains("mac"));
  }

  private Fixture fixture() throws IOException {
    return fixture("project");
  }

  private Fixture fixture(final String name) throws IOException {
    final Path basedir = temporaryDirectory.resolve(name);
    Files.createDirectories(basedir);
    final Path sourceRoot = basedir.resolve("src/main/java");
    final Path testSourceRoot = basedir.resolve("src/test/java");
    final Path productionOutput = basedir.resolve("target/classes");
    final Path testOutput = basedir.resolve("target/test-classes");
    final Path productionResources = basedir.resolve("src/main/resources");
    final Path testResources = basedir.resolve("src/test/resources");
    Files.createDirectories(sourceRoot);
    final Path dependency = temporaryDirectory.resolve("affected.jar");
    writeJar(dependency);
    final Artifact artifact =
        new DefaultArtifact(
            ORG_EXAMPLE_GROUP,
            "affected",
            TEST_VERSION,
            GOAL_COMPILE,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    artifact.setFile(dependency.toFile());
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(artifact));
    final MavenProject project = new MavenProject();
    project.setFile(basedir.resolve("pom.xml").toFile());
    project.setPackaging(JAR_TYPE);
    project.setArtifacts(artifacts);
    project.getProperties().setProperty(PROCESSING_PROPERTY, PROCESSING_NONE);
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.addCompileSourceRoot(sourceRoot.toString());
    project.addTestCompileSourceRoot(testSourceRoot.toString());
    final Build build = new Build();
    build.setDirectory(basedir.resolve("target").toString());
    build.setOutputDirectory(productionOutput.toString());
    build.setTestOutputDirectory(testOutput.toString());
    final PluginManagement management = new PluginManagement();
    management.addPlugin(compilerPlugin());
    management.addPlugin(surefirePlugin(basedir));
    build.setPluginManagement(management);
    final Plugin surefire = surefirePlugin(basedir);
    final PluginExecution defaultTest = new PluginExecution();
    defaultTest.setId("default-test");
    defaultTest.setPhase(TEST);
    defaultTest.setGoals(List.of(TEST));
    defaultTest.setConfiguration(surefireConfiguration(basedir));
    surefire.addExecution(defaultTest);
    build.addPlugin(surefire);
    final Resource productionResource = new Resource();
    productionResource.setDirectory(productionResources.toString());
    final Resource testResource = new Resource();
    testResource.setDirectory(testResources.toString());
    project.setBuild(build);
    project.addResource(productionResource);
    project.addTestResource(testResource);
    final ArtifactCoordinate coordinate = MavenArtifactInventory.toCoordinate(artifact);
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(
                MavenArtifactInventory.snapshots(List.of(artifact)), false, List.of()),
            new io.github.spockz.elider.model.ElisionDecision(
                Set.of(), Set.of(coordinate), Map.of(), Map.of(), 0L));
    final ElisionAnalysisModel.ApplyPlan plan =
        new ElisionAnalysisModel.ApplyPlan(artifacts, false, Set.of());
    return new Fixture(
        project,
        analysis,
        plan,
        coordinate,
        dependency,
        sourceRoot,
        testSourceRoot,
        productionOutput,
        testOutput,
        productionResources,
        testResources);
  }

  private static Plugin compilerPlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId("maven-compiler-plugin");
    plugin.setVersion("3.13.0");
    return plugin;
  }

  private static Plugin resourcesPlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId(MAVEN_RESOURCES_PLUGIN);
    return plugin;
  }

  private static void addDefaultTestResourcesExecution(
      final MavenProject project, final Xpp3Dom configuration) {
    final Plugin resources = resourcesPlugin();
    addTestResourcesExecution(resources, configuration);
    project.getBuild().addPlugin(resources);
  }

  private static void addTestResourcesExecution(
      final Plugin resources, final Xpp3Dom configuration) {
    final PluginExecution execution = new PluginExecution();
    execution.setId("default-testResources");
    execution.setPhase(PROCESS_TEST_RESOURCES);
    execution.setGoals(List.of("testResources"));
    execution.setConfiguration(configuration);
    resources.addExecution(execution);
  }

  private static Dependency providerPluginDependency() {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(EXAMPLE_GROUP);
    dependency.setArtifactId("custom-provider");
    dependency.setVersion(TEST_VERSION);
    return dependency;
  }

  private static Plugin managedCompiler(final Fixture fixture) {
    return fixture.project().getBuild().getPluginManagement().getPlugins().stream()
        .filter(plugin -> "maven-compiler-plugin".equals(plugin.getArtifactId()))
        .findFirst()
        .orElseThrow();
  }

  private static Dependency compilerExtensionDependency() {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(EXAMPLE_GROUP);
    dependency.setArtifactId("custom-compiler-provider");
    dependency.setVersion(TEST_VERSION);
    return dependency;
  }

  private static void addUnknownGenerator(final Fixture fixture, final String phase) {
    final Plugin generator = new Plugin();
    generator.setGroupId(EXAMPLE_GROUP);
    generator.setArtifactId("provider-generator");
    final PluginExecution execution = new PluginExecution();
    execution.setId("generate-providers");
    execution.setPhase(phase);
    execution.setGoals(List.of("generate"));
    generator.addExecution(execution);
    fixture.project().getBuild().addPlugin(generator);
  }

  private void assertTrustedWriterRejected(final Fixture fixture, final Plugin writer)
      throws IOException {
    assertTrustedWriterRejected(fixture, writer, PROCESS_CLASSES_PHASE);
  }

  private void assertTrustedWriterRejected(
      final Fixture fixture, final Plugin writer, final String requestedPhase) throws IOException {
    fixture.project().getBuild().addPlugin(writer);
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of(GOAL_CLEAN, requestedPhase));
    final MavenSession session = new MavenSession(null, request, null, fixture.project());
    session.getUserProperties().setProperty(SKIP_TESTS, TRUE);
    session.getUserProperties().setProperty(MAVEN_TEST_SKIP, TRUE);

    assertThatThrownBy(
            () ->
                MavenPreconditionGenerationGuard.requireKnownProviderGeneration(
                    fixture.project(), session, true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("lifecycle writer");
  }

  private static Plugin lifecyclePlugin(
      final String group, final String artifact, final String executionId, final String goal) {
    return lifecyclePlugin(group, artifact, executionId, goal, PROCESS_CLASSES_PHASE);
  }

  private static Plugin lifecyclePlugin(
      final String group,
      final String artifact,
      final String executionId,
      final String goal,
      final String phase) {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(group);
    plugin.setArtifactId(artifact);
    final PluginExecution execution = new PluginExecution();
    execution.setId(executionId);
    execution.setPhase(phase);
    execution.setGoals(List.of(goal));
    plugin.addExecution(execution);
    return plugin;
  }

  private static Plugin enforcerPlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId(ENFORCER_PLUGIN);
    return plugin;
  }

  private static Plugin shadePluginManagement() {
    final Plugin plugin = shadePluginDeclaration();
    plugin.setConfiguration(shadeRootConfiguration());
    return plugin;
  }

  private static Plugin shadePlugin() {
    final Plugin plugin = shadePluginDeclaration();
    plugin.setConfiguration(shadeRootConfiguration());
    final PluginExecution execution = new PluginExecution();
    execution.setId("shade-application");
    execution.setPhase(GOAL_PACKAGE);
    execution.setGoals(List.of("shade"));
    execution.setConfiguration(shadeExecutionConfiguration());
    plugin.addExecution(execution);
    return plugin;
  }

  private static Plugin shadePluginDeclaration() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId("maven-shade-plugin");
    plugin.setVersion("3.6.0");
    return plugin;
  }

  private static Plugin jarPlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId("maven-jar-plugin");
    return plugin;
  }

  private static Plugin cleanPlugin() {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId("maven-clean-plugin");
    return plugin;
  }

  private static Plugin surefirePlugin(final Path basedir) {
    final Plugin plugin = new Plugin();
    plugin.setGroupId(MAVEN_PLUGIN_GROUP);
    plugin.setArtifactId("maven-surefire-plugin");
    plugin.setVersion("3.5.2");
    plugin.setConfiguration(surefireConfiguration(basedir));
    return plugin;
  }

  private static boolean isSurefirePlugin(final Plugin plugin) {
    return "maven-surefire-plugin".equals(plugin.getArtifactId());
  }

  private static Xpp3Dom surefireConfiguration(final Path basedir) {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    final Xpp3Dom systemProperties = new Xpp3Dom("systemPropertyVariables");
    systemProperties.addChild(setting("elider.verifyElision", FALSE));
    systemProperties.addChild(
        setting("elider.examples.dir", basedir.resolve("examples").toString()));
    configuration.addChild(systemProperties);
    return configuration;
  }

  private static Xpp3Dom shadeRootConfiguration() {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(setting("createDependencyReducedPom", FALSE));
    final Xpp3Dom filters = new Xpp3Dom("filters");
    final Xpp3Dom filter = new Xpp3Dom("filter");
    filter.addChild(setting("artifact", "*:*"));
    final Xpp3Dom excludes = new Xpp3Dom("excludes");
    for (final String signature :
        List.of(
            "META-INF/*.SF",
            "META-INF/*.DSA",
            "META-INF/*.RSA",
            "META-INF/*.EC",
            "META-INF/SIG-*")) {
      excludes.addChild(setting("exclude", signature));
    }
    filter.addChild(excludes);
    filters.addChild(filter);
    configuration.addChild(filters);
    return configuration;
  }

  private static Xpp3Dom shadeExecutionConfiguration() {
    final Xpp3Dom configuration = shadeRootConfiguration();
    final Xpp3Dom transformers = new Xpp3Dom(SHADE_TRANSFORMERS);
    final Xpp3Dom transformer = new Xpp3Dom("transformer");
    transformer.setAttribute(
        "implementation", "org.apache.maven.plugins.shade.resource.ManifestResourceTransformer");
    transformer.addChild(setting("mainClass", "org.example.application.Main"));
    transformers.addChild(transformer);
    configuration.addChild(transformers);
    return configuration;
  }

  private static PluginExecution enforcerExecution() {
    final PluginExecution execution = new PluginExecution();
    execution.setId("default-enforce");
    execution.setGoals(List.of("enforce"));
    return execution;
  }

  private static Xpp3Dom enforcerConfiguration(final Xpp3Dom rules) {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(rules);
    return configuration;
  }

  private static Xpp3Dom enforcerRules(final Xpp3Dom rule) {
    final Xpp3Dom rules = new Xpp3Dom("rules");
    rules.addChild(rule);
    return rules;
  }

  private static void addCompilerExecution(
      final Plugin plugin,
      final String executionId,
      final String goal,
      final Xpp3Dom configuration) {
    final PluginExecution execution = new PluginExecution();
    execution.setId(executionId);
    execution.setGoals(List.of(goal));
    execution.setConfiguration(configuration);
    plugin.addExecution(execution);
  }

  private static Xpp3Dom configuration(final String name, final String value) {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    configuration.addChild(setting(name, value));
    return configuration;
  }

  private static Xpp3Dom compilerArgsConfiguration(final String argument) {
    final Xpp3Dom configuration = new Xpp3Dom(CONFIGURATION_ELEMENT);
    final Xpp3Dom arguments = new Xpp3Dom("compilerArgs");
    arguments.addChild(setting("arg", argument));
    configuration.addChild(arguments);
    return configuration;
  }

  private static Xpp3Dom setting(final String name, final String value) {
    final Xpp3Dom element = new Xpp3Dom(name);
    element.setValue(value);
    return element;
  }

  private static Path writeSource(final Path root, final String name, final String source)
      throws IOException {
    Files.createDirectories(root);
    final Path file = root.resolve(name);
    Files.writeString(file, source);
    return file;
  }

  private static String javacPluginSource(final String generatedClassBase64) {
    return String.join(
        "\n",
        "package plugin;",
        "import com.sun.source.util.JavacTask;",
        "import com.sun.source.util.Plugin;",
        "import com.sun.source.util.TaskEvent;",
        "import com.sun.source.util.TaskListener;",
        "import java.io.IOException;",
        "import java.nio.file.Files;",
        "import java.nio.file.Path;",
        "import java.util.Base64;",
        "public final class ProviderPlugin implements Plugin {",
        "  @Override public String getName() { return \"ProviderPlugin\"; }",
        "  @Override public boolean autoStart() { return true; }",
        "  @Override public void init(JavacTask task, String... args) {",
        "    task.addTaskListener(new TaskListener() {",
        "      @Override public void started(TaskEvent event) {}",
        "      @Override public void finished(TaskEvent event) {",
        "        if (event.getKind() == TaskEvent.Kind.GENERATE) {",
        "          try {",
        "            Path output = Path.of(System.getProperty("
            + "\"elider.test.javacPluginOutput\"));",
        "            Files.createDirectories(output.getParent());",
        "            Files.write(output, Base64.getDecoder().decode(\"%s\"));"
            .formatted(generatedClassBase64),
        "          } catch (IOException exception) {",
        "            throw new IllegalStateException(exception);",
        "          }",
        "        }",
        "      }",
        "    });",
        "  }",
        "}");
  }

  private static void writeJar(final Path path) throws IOException {
    ImmutableTestJar.write(
        path,
        Map.of(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\n\n".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  private static Map.Entry<String, byte[]> pluginClassEntry(
      final Path classesRoot, final Path classFile) {
    final String entryName = classesRoot.relativize(classFile).toString().replace('\\', '/');
    try {
      return Map.entry(entryName, Files.readAllBytes(classFile));
    } catch (final IOException exception) {
      throw new java.io.UncheckedIOException(exception);
    }
  }

  private static void writeClass(final Path path, final String internalName) throws IOException {
    Files.createDirectories(path.getParent());
    Files.write(path, classBytes(internalName));
  }

  private static byte[] classBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record Fixture(
      MavenProject project,
      ElisionAnalysisModel.Analysis analysis,
      ElisionAnalysisModel.ApplyPlan plan,
      ArtifactCoordinate coordinate,
      Path dependency,
      Path productionSources,
      Path testSources,
      Path productionOutput,
      Path testOutput,
      Path productionResources,
      Path testResources) {}
}
