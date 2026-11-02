// WHY: Proves strict bans use the detached Analyze graph and never publish artifact changes.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Tests detached bans. JUnit constructs the test. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods"
})
final class NoExtensionAnalyzeBanPredictionTest {
  private static final String BAN = "fixture:banned";
  private static final String USED_TRACE = "used.Api\n";
  private static final String GROUP_ID = "fixture";
  private static final String JAR_TYPE = "jar";
  private static final String VERSION = "1.0";
  private static final String RUNTIME_SCOPE = "runtime";
  private static final String BANNED_ARTIFACT_ID = "banned";
  private static final String USED_ARTIFACT_ID = "used";
  private static final String UNUSED_ARTIFACT_ID = "unused";
  private static final String SUMMARY_FILENAME = "elide-summary.json";
  private static final String CLASS_USAGE_FILENAME = "elide-class-usage.json";
  private static final String BANNED_PROVIDER_FAILURE =
      "no retained provider for class banned.Idle";
  private static final String PREVIOUS_REPORT = "prior report\n";
  private static final String PREVIOUS_SUMMARY = "prior summary\n";

  /** Isolates each graph and evidence fixture from the other scenarios. */
  @TempDir private Path temporaryDirectory;

  @Test
  void plansSafeTransitiveBanWithoutChangingLiveViews() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    final Set<org.apache.maven.artifact.Artifact> liveResolved = fixture.project().getArtifacts();
    final Set<org.apache.maven.artifact.Artifact> liveDirect =
        fixture.project().getDependencyArtifacts();

    final AnalyzePrediction prediction =
        new MavenElisionService()
            .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver());

    assertAll(
        "detached ban is only an uncommitted prediction tied to its Resolver inventory",
        () ->
            assertThat(prediction.provenance())
                .isEqualTo(MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL),
        () ->
            assertThat(prediction.banPlan().entries())
                .singleElement()
                .satisfies(
                    entry ->
                        assertAll(
                            () -> assertThat(entry.dependency().toString()).isEqualTo(BAN),
                            () -> assertThat(entry.matched()).isTrue(),
                            () -> assertThat(entry.artifacts()).hasSize(1))),
        () ->
            assertThat(prediction.wouldElideArtifacts())
                .containsAll(prediction.banPlan().forcedAbsentAfterResolution()),
        () -> assertThat(fixture.project().getArtifacts()).isSameAs(liveResolved),
        () -> assertThat(fixture.project().getDependencyArtifacts()).isSameAs(liveDirect),
        () ->
            assertThat(
                    fixture
                        .session()
                        .getRepositorySession()
                        .getData()
                        .get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY))
                .isNull());
  }

  @Test
  void reportsMatchedAndUnmatchedBansAsUnappliedSchemaOnePlans() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    final AnalyzePrediction prediction =
        new MavenElisionService()
            .predict(
                fixture.project(),
                fixture.options(List.of("fixture:missing", BAN)),
                fixture.resolver());
    final AnalyzePrediction withoutBan =
        new MavenElisionService()
            .predict(fixture.project(), fixture.options(List.of()), fixture.resolver());
    final Path report = temporaryDirectory.resolve("ban-plan-report.json");
    MavenClassUsageReportWriter.write(
        report,
        prediction.evidence().classUsageReport(),
        prediction.evidence().bytecodeScan(),
        prediction);
    final com.fasterxml.jackson.databind.JsonNode json =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(report.toFile());
    final com.fasterxml.jackson.databind.JsonNode rows =
        json.path("dependencyPrediction").path("banPlan");

    assertAll(
        "schema-one prediction records action, unmatched policy, and no applied Maven mutation",
        () -> assertThat(json.path("schemaVersion").asInt()).isEqualTo(1),
        () ->
            assertThat(json.path("dependencyPrediction").path("banContextFingerprint").asText())
                .hasSize(64),
        () -> assertThat(rows.size()).isEqualTo(2),
        () -> assertThat(rows.get(0).path("dependency").asText()).isEqualTo(BAN),
        () ->
            assertThat(rows.get(0).path("status").asText())
                .isEqualTo("FORCED_ABSENT_AFTER_RESOLUTION"),
        () -> assertThat(rows.get(0).path("matchedArtifacts").size()).isEqualTo(1),
        () -> assertThat(rows.get(0).path("applied").asBoolean()).isFalse(),
        () -> assertThat(rows.get(1).path("dependency").asText()).isEqualTo("fixture:missing"),
        () -> assertThat(rows.get(1).path("status").asText()).isEqualTo("UNMATCHED"),
        () -> assertThat(rows.get(1).path("matchedArtifacts").size()).isZero(),
        () -> assertThat(rows.get(1).path("applied").asBoolean()).isFalse(),
        () ->
            assertThat(prediction.operationFingerprint())
                .isNotEqualTo(withoutBan.operationFingerprint()));
  }

  @Test
  void activeAuditAnalyzeReportsExcludedBanWithoutChangingLiveState() throws Exception {
    final Fixture fixture = activeExcludedFixture(USED_TRACE);
    final List<org.apache.maven.artifact.Artifact> resolvedBefore =
        List.copyOf(fixture.project().getArtifacts());
    final List<org.apache.maven.artifact.Artifact> directBefore =
        List.copyOf(fixture.project().getDependencyArtifacts());
    final Object priorResolverPlan = new Object();
    fixture
        .repositorySession()
        .getData()
        .set(ResolverArtifactPlanPublisher.SESSION_DATA_KEY, priorResolverPlan);

    final AnalyzePrediction prediction =
        new MavenElisionService()
            .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver());
    final Path report = temporaryDirectory.resolve("active-audit-ban-plan.json");
    MavenClassUsageReportWriter.write(
        report,
        prediction.evidence().classUsageReport(),
        prediction.evidence().bytecodeScan(),
        prediction);
    final com.fasterxml.jackson.databind.JsonNode row =
        new com.fasterxml.jackson.databind.ObjectMapper()
            .readTree(report.toFile())
            .path("dependencyPrediction")
            .path("banPlan")
            .get(0);

    assertAll(
        "active Analyze predicts from original audit without changing Resolver state",
        () ->
            assertThat(prediction.provenance())
                .isEqualTo(MavenAnalysisResolutionContext.Provenance.CAPTURED_EFFECTIVE_RESOLVER),
        () ->
            assertThat(prediction.banPlan().entries().getFirst().status())
                .isEqualTo(MavenBanPlan.Entry.Status.EXCLUDED_BEFORE_RESOLUTION),
        () -> assertThat(row.path("status").asText()).isEqualTo("EXCLUDED_BEFORE_RESOLUTION"),
        () -> assertThat(row.path("matchedArtifacts")).hasSize(0),
        () -> assertThat(row.path("originalArtifacts")).hasSize(1),
        () -> assertThat(row.path("applied").asBoolean()).isFalse(),
        () -> assertSameArtifactReferences(fixture.project().getArtifacts(), resolvedBefore),
        () ->
            assertSameArtifactReferences(fixture.project().getDependencyArtifacts(), directBefore),
        () ->
            assertThat(
                    fixture
                        .repositorySession()
                        .getData()
                        .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isSameAs(priorResolverPlan));
  }

  @Test
  void elideAppliesSafeTransitiveBanWithTrimDisabledAndEnabled() throws Exception {
    final Fixture withoutTrim = basicFixture(USED_TRACE);
    final Fixture withTrim = basicFixture(USED_TRACE);
    final ElideMojo withoutTrimMojo = elideMojo(withoutTrim, false);
    final ElideMojo withTrimMojo = elideMojo(withTrim, true);
    final org.apache.maven.artifact.Artifact withoutTrimUsed =
        withoutTrim.project().getDependencyArtifacts().iterator().next();
    final org.apache.maven.artifact.Artifact withTrimUsed =
        withTrim.project().getDependencyArtifacts().iterator().next();
    final Set<org.apache.maven.artifact.Artifact> withoutTrimDirect =
        withoutTrim.project().getDependencyArtifacts();
    final Set<org.apache.maven.artifact.Artifact> withTrimDirect =
        withTrim.project().getDependencyArtifacts();

    withoutTrimMojo.execute();
    withTrimMojo.execute();
    final ResolverArtifactPlan withoutTrimPlan = resolverPlan(withoutTrim);
    final ResolverArtifactPlan withTrimPlan = resolverPlan(withTrim);

    assertAll(
        "safe transitive bans are applied in both trim modes before resolver-plan publication",
        () -> assertAppliedBan(withoutTrim, withoutTrimPlan, withoutTrimUsed, withoutTrimDirect),
        () -> assertAppliedBan(withTrim, withTrimPlan, withTrimUsed, withTrimDirect));
  }

  @Nested
  /* default */ final class UnrelatedTraceDropTest {
    @Test
    void detachedBanOperationMayApplyValidatedUnrelatedTraceDrop() throws Exception {
      final Fixture fixture = fixtureWithUnrelatedTraceDrop(USED_TRACE);
      final ElideMojo mojo = elideMojo(fixture, false);

      mojo.execute();

      final MavenElisionReportSnapshot summary =
          MavenElisionReportWriter.read(fixture.trace().getParent().resolve(SUMMARY_FILENAME));
      assertAll(
          "detached ban planning validates both forced absence and ordinary trace-based drops",
          () ->
              assertThat(fixture.project().getArtifacts())
                  .extracting(org.apache.maven.artifact.Artifact::getArtifactId)
                  .containsExactly(USED_ARTIFACT_ID),
          () ->
              assertThat(summary.appliedBans())
                  .singleElement()
                  .satisfies(
                      ban -> assertThat(ban.status()).isEqualTo("FORCED_ABSENT_AFTER_RESOLUTION")),
          () ->
              assertThat(summary.droppedArtifacts())
                  .extracting(MavenElisionReportSnapshot.DroppedArtifact::coordinate)
                  .containsExactlyInAnyOrder(
                      "fixture:banned:jar:1.0 (runtime)", "fixture:unused:jar:1.0 (runtime)"),
          () ->
              assertThat(summary.rawDroppedCoordinates())
                  .containsExactly("fixture:unused:jar:1.0 (runtime)")
                  .doesNotContain("fixture:banned:jar:1.0 (runtime)"));
    }
  }

  @Nested
  /* default */ final class BlankTypeBanTest {
    @Test
    void rejectsExplicitBlankTypeForRequestedBan() throws Exception {
      final Fixture fixture = blankTypeFixture();

      assertThatThrownBy(
              () ->
                  new MavenElisionService()
                      .predict(
                          fixture.project(), fixture.options(List.of(BAN)), fixture.resolver()))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("no Maven artifact type")
          .hasMessageContaining(BAN);
    }

    private Fixture blankTypeFixture() throws IOException {
      final Fixture fixture = basicFixture(USED_TRACE);
      final DependencyNode usedNode = fixture.root().getChildren().getFirst();
      final org.eclipse.aether.graph.Dependency originalBan =
          usedNode.getChildren().getFirst().getDependency();
      final org.eclipse.aether.artifact.Artifact originalArtifact = originalBan.getArtifact();
      final org.eclipse.aether.artifact.Artifact blankTypeArtifact =
          new org.eclipse.aether.artifact.DefaultArtifact(
              originalArtifact.getGroupId(),
              originalArtifact.getArtifactId(),
              originalArtifact.getClassifier(),
              originalArtifact.getExtension(),
              originalArtifact.getVersion(),
              Map.of("type", "", "constitutesBuildPath", "true"),
              originalArtifact.getFile());
      final org.eclipse.aether.graph.Dependency blankTypeDependency =
          new org.eclipse.aether.graph.Dependency(blankTypeArtifact, originalBan.getScope());
      ((DefaultDependencyNode) usedNode)
          .setChildren(List.of(new DefaultDependencyNode(blankTypeDependency)));
      replaceResolvedMavenArtifact(fixture, blankTypeArtifact);
      return withBlankTypeResolver(fixture, blankTypeDependency);
    }

    private void replaceResolvedMavenArtifact(
        final Fixture fixture, final org.eclipse.aether.artifact.Artifact resolverArtifact) {
      final Set<org.apache.maven.artifact.Artifact> resolved = new LinkedHashSet<>();
      for (final org.apache.maven.artifact.Artifact artifact : fixture.project().getArtifacts()) {
        if (!resolverArtifact.getArtifactId().equals(artifact.getArtifactId())) {
          resolved.add(artifact);
        }
      }
      final org.apache.maven.artifact.Artifact replacement =
          org.apache.maven.RepositoryUtils.toArtifact(resolverArtifact);
      replacement.setScope(RUNTIME_SCOPE);
      resolved.add(replacement);
      fixture.project().setArtifacts(resolved);
    }

    private Fixture withBlankTypeResolver(
        final Fixture fixture, final org.eclipse.aether.graph.Dependency blankTypeDependency) {
      return new Fixture(
          fixture.project(),
          fixture.session(),
          fixture.repositorySession(),
          fixtureResolver(fixture.root(), List.of(fixture.usedDependency(), blankTypeDependency)),
          fixture.trace(),
          fixture.root(),
          fixture.usedDependency());
    }
  }

  @Test
  void elideAppliesMatchedClasslessJarBan() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    final org.apache.maven.artifact.Artifact bannedArtifact =
        fixture.project().getArtifacts().stream()
            .filter(artifact -> BANNED_ARTIFACT_ID.equals(artifact.getArtifactId()))
            .findFirst()
            .orElseThrow();
    writeClasslessJar(bannedArtifact.getFile().toPath());
    final ElideMojo mojo = elideMojo(fixture, false);

    mojo.execute();

    final MavenElisionReportSnapshot summary =
        MavenElisionReportWriter.read(fixture.trace().getParent().resolve(SUMMARY_FILENAME));
    assertAll(
        "a matched archive without classes is safely absent from the final Maven and output views",
        () ->
            assertThat(fixture.project().getArtifacts())
                .noneMatch(artifact -> BANNED_ARTIFACT_ID.equals(artifact.getArtifactId())),
        () ->
            assertThat(fixture.project().getDependencyArtifacts())
                .extracting(org.apache.maven.artifact.Artifact::getArtifactId)
                .containsExactly(USED_ARTIFACT_ID),
        () -> assertThat(summary.appliedBans()).hasSize(1),
        () ->
            assertThat(summary.appliedBans().getFirst().matchedArtifacts())
                .containsExactly("fixture:banned:jar:1.0 (runtime)"),
        () -> assertThat(summary.appliedBans().getFirst().applied()).isTrue(),
        () ->
            assertThat(resolverPlan(fixture).replacements().keySet())
                .noneMatch(identity -> BANNED_ARTIFACT_ID.equals(identity.artifactId())));
  }

  @Test
  void rejectsRuntimeObservationOfBannedProviderBeforePrediction() throws Exception {
    final Fixture fixture = basicFixture("used.Api\nbanned.Idle\n");

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver()))
        .hasMessageContaining(BANNED_PROVIDER_FAILURE);
  }

  @Test
  void keepsActiveHookMissingCaptureDistinctFromPluginOnlyPlanning() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    MavenOriginalInputAudit.markHookPresent(fixture.session());

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Original-input audit has no frozen project capture");
  }

  @Test
  void rejectsPreMediationVersionProtectionAndAncestorPromotion() throws Exception {
    final Fixture competing = basicFixture(USED_TRACE);
    final DefaultDependencyNode direct =
        (DefaultDependencyNode) competing.root().getChildren().getFirst();
    final DependencyNode winner = direct.getChildren().getFirst();
    final org.eclipse.aether.graph.Dependency otherVersion =
        new org.eclipse.aether.graph.Dependency(
            new org.eclipse.aether.artifact.DefaultArtifact(
                GROUP_ID, BANNED_ARTIFACT_ID, "", JAR_TYPE, "2.0"),
            RUNTIME_SCOPE);
    direct.setChildren(List.of(winner, new DefaultDependencyNode(otherVersion)));
    competing
        .repositorySession()
        .setDependencyGraphTransformer(
            (root, context) -> {
              direct.setChildren(List.of(winner));
              return root;
            });
    final Fixture ancestor = basicFixture(USED_TRACE);
    final DefaultDependencyNode bannedNode =
        (DefaultDependencyNode) ancestor.root().getChildren().getFirst().getChildren().getFirst();
    bannedNode.setChildren(List.of(new DefaultDependencyNode(ancestor.usedDependency())));

    assertAll(
        "a forced ban cannot override graph protection or retained-descendant promotion",
        () ->
            assertThatThrownBy(() -> predict(competing))
                .hasMessageContaining("graph protects or promotes"),
        () ->
            assertThatThrownBy(() -> predict(ancestor))
                .hasMessageContaining("graph protects or promotes"));
  }

  @Test
  void rejectsRetainedBytecodeClosureWithAndWithoutTrim() throws Exception {
    final Fixture fixture = fixture(USED_TRACE, true);

    assertAll(
        "retained bytecode cannot promote the banned provider in either trim mode",
        () ->
            assertThatThrownBy(() -> predict(fixture))
                .hasMessageContaining(BANNED_PROVIDER_FAILURE),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionService()
                            .predict(
                                fixture.project(),
                                fixture.options(List.of(BAN), true),
                                fixture.resolver()))
                .hasMessageContaining(BANNED_PROVIDER_FAILURE));
  }

  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // assertAll checks each rollback invariant
  // independently.
  @Test
  void retainedBytecodeConflictLeavesReportsViewsAndResolverPlanUntouched() throws Exception {
    final Fixture fixture = fixture(USED_TRACE, true);
    final ElideMojo mojo = elideMojo(fixture, false);
    final Path directory = fixture.trace().getParent();
    final Path report = directory.resolve(CLASS_USAGE_FILENAME);
    final Path summary = directory.resolve(SUMMARY_FILENAME);
    Files.writeString(report, PREVIOUS_REPORT);
    Files.writeString(summary, PREVIOUS_SUMMARY);
    final List<org.apache.maven.artifact.Artifact> resolvedView =
        List.copyOf(fixture.project().getArtifacts());
    final List<org.apache.maven.artifact.Artifact> directView =
        List.copyOf(fixture.project().getDependencyArtifacts());
    final Map<org.apache.maven.artifact.Artifact, java.io.File> artifactFiles =
        artifactFiles(resolvedView, directView);
    final Object priorResolverPlan = new Object();
    fixture
        .repositorySession()
        .getData()
        .set(ResolverArtifactPlanPublisher.SESSION_DATA_KEY, priorResolverPlan);

    assertThatThrownBy(mojo::execute).hasMessageContaining(BANNED_PROVIDER_FAILURE);

    assertAll(
        "a retained bytecode conflict fails before any report, view, file pointer, or plan changes",
        () -> assertThat(Files.readString(report)).isEqualTo(PREVIOUS_REPORT),
        () -> assertThat(Files.readString(summary)).isEqualTo(PREVIOUS_SUMMARY),
        () -> assertSameArtifactReferences(fixture.project().getArtifacts(), resolvedView),
        () -> assertSameArtifactReferences(fixture.project().getDependencyArtifacts(), directView),
        () -> assertThat(artifactFiles(resolvedView, directView)).isEqualTo(artifactFiles),
        () ->
            assertThat(
                    fixture
                        .repositorySession()
                        .getData()
                        .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isSameAs(priorResolverPlan));
  }

  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // assertAll checks each rollback invariant
  // independently.
  @Test
  void planPublicationFailureRollsBackFilesViewsAndResolverPlan() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    final ElideMojo mojo = elideMojo(fixture, false);
    final Path directory = fixture.trace().getParent();
    final Path report = directory.resolve(CLASS_USAGE_FILENAME);
    final Path summary = directory.resolve(SUMMARY_FILENAME);
    Files.writeString(report, PREVIOUS_REPORT);
    Files.writeString(summary, PREVIOUS_SUMMARY);
    final List<org.apache.maven.artifact.Artifact> resolvedView =
        List.copyOf(fixture.project().getArtifacts());
    final List<org.apache.maven.artifact.Artifact> directView =
        List.copyOf(fixture.project().getDependencyArtifacts());
    final Map<org.apache.maven.artifact.Artifact, java.io.File> artifactFiles =
        artifactFiles(resolvedView, directView);
    final Object priorResolverPlan = new Object();
    fixture
        .repositorySession()
        .getData()
        .set(ResolverArtifactPlanPublisher.SESSION_DATA_KEY, priorResolverPlan);
    set(
        mojo,
        "planPublication",
        (MavenElideExecutionConfiguration.PlanPublication)
            (session, project, trimRecords, graphProjection) -> {
              throw new IOException("injected resolver plan failure");
            });

    assertThatThrownBy(mojo::execute).hasMessageContaining("injected resolver plan failure");

    assertAll(
        "publication failure restores staged files, exact Maven views and artifact file pointers",
        () -> assertThat(Files.readString(report)).isEqualTo(PREVIOUS_REPORT),
        () -> assertThat(Files.readString(summary)).isEqualTo(PREVIOUS_SUMMARY),
        () -> assertSameArtifactReferences(fixture.project().getArtifacts(), resolvedView),
        () -> assertSameArtifactReferences(fixture.project().getDependencyArtifacts(), directView),
        () -> assertThat(artifactFiles(resolvedView, directView)).isEqualTo(artifactFiles),
        () ->
            assertThat(
                    fixture
                        .repositorySession()
                        .getData()
                        .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isSameAs(priorResolverPlan));
  }

  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // assertAll independently checks every rollback
  // surface.
  @Test
  void failureAfterTrimGenerationStagingRollsBackBeforePublication() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    final ElideMojo mojo = elideMojo(fixture, true);
    final Path directory = fixture.trace().getParent();
    final Path report = directory.resolve(CLASS_USAGE_FILENAME);
    final Path summary = directory.resolve(SUMMARY_FILENAME);
    Files.writeString(report, PREVIOUS_REPORT);
    Files.writeString(summary, PREVIOUS_SUMMARY);
    final List<org.apache.maven.artifact.Artifact> resolvedView =
        List.copyOf(fixture.project().getArtifacts());
    final List<org.apache.maven.artifact.Artifact> directView =
        List.copyOf(fixture.project().getDependencyArtifacts());
    final Map<org.apache.maven.artifact.Artifact, java.io.File> artifactFiles =
        artifactFiles(resolvedView, directView);
    final Path generatedOutputRoot =
        Path.of(fixture.project().getBuild().getDirectory()).resolve("elided-artifacts");
    final List<String> priorGenerationFiles = fileSnapshot(generatedOutputRoot);
    final Object priorResolverPlan = new Object();
    fixture
        .repositorySession()
        .getData()
        .set(ResolverArtifactPlanPublisher.SESSION_DATA_KEY, priorResolverPlan);
    set(
        mojo,
        "afterGenerationStaging",
        (MavenElisionOutputPublisher.AfterStaging)
            () -> {
              throw new IOException("injected failure after trim generation staging");
            });

    assertThatThrownBy(mojo::execute)
        .hasMessageContaining("injected failure after trim generation staging");

    assertAll(
        "a failed post-stage binding step closes the generation handle before any publication",
        () -> assertThat(Files.readString(report)).isEqualTo(PREVIOUS_REPORT),
        () -> assertThat(Files.readString(summary)).isEqualTo(PREVIOUS_SUMMARY),
        () -> assertSameArtifactReferences(fixture.project().getArtifacts(), resolvedView),
        () -> assertSameArtifactReferences(fixture.project().getDependencyArtifacts(), directView),
        () -> assertThat(artifactFiles(resolvedView, directView)).isEqualTo(artifactFiles),
        () -> assertThat(fileSnapshot(generatedOutputRoot)).isEqualTo(priorGenerationFiles),
        () ->
            assertThat(
                    fixture
                        .repositorySession()
                        .getData()
                        .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isSameAs(priorResolverPlan));
  }

  @Test
  void ignoresOnlySelfOriginServiceMetadataWithAndWithoutTrim() throws Exception {
    final Fixture selfOrigin = fixture(USED_TRACE, false, false, true);
    final AnalyzePrediction withoutTrim =
        new MavenElisionService()
            .predict(
                selfOrigin.project(),
                selfOrigin.options(List.of(BAN), false, true),
                selfOrigin.resolver());
    final AnalyzePrediction withTrim =
        new MavenElisionService()
            .predict(
                selfOrigin.project(),
                selfOrigin.options(List.of(BAN), true, true),
                selfOrigin.resolver());
    final String bannedProvider = "banned.Idle";
    assertAll(
        "self-origin metadata remains in evidence but cannot retain its own banned artifact",
        () ->
            assertThat(withoutTrim.wouldElideArtifacts())
                .containsAll(withoutTrim.banPlan().forcedAbsentAfterResolution()),
        () ->
            assertThat(withTrim.wouldElideArtifacts())
                .containsAll(withTrim.banPlan().forcedAbsentAfterResolution()),
        () ->
            assertThat(withoutTrim.evidence().unprovenServiceRoots().values())
                .anySatisfy(roots -> assertThat(roots).contains(bannedProvider)),
        () ->
            assertThat(withTrim.evidence().unprovenServiceRoots().values())
                .anySatisfy(roots -> assertThat(roots).contains(bannedProvider)));
  }

  @Test
  void rejectsRetainedResourceIncludeMaskedByBannedArchiveExclude() throws Exception {
    final Fixture fixture = basicFixture(USED_TRACE);
    final Path directory = fixture.trace().getParent();
    jar(
        directory.resolve("used.jar"),
        "used/Api",
        false,
        null,
        "-H:IncludeResources=required[.]txt",
        false);
    jar(
        directory.resolve("banned.jar"),
        "banned/Idle",
        false,
        null,
        "-H:ExcludeResources=required[.]txt",
        true);

    assertAll(
        "a banned archive's disappearing exclusion cannot erase a retained resource obligation",
        () ->
            assertThatThrownBy(() -> predict(fixture))
                .hasMessageContaining("resource or provider metadata requires the artifact"),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionService()
                            .predict(
                                fixture.project(),
                                fixture.options(List.of(BAN), true),
                                fixture.resolver()))
                .hasMessageContaining("resource or provider metadata requires the artifact"));
  }

  @Test
  void rejectsRetainedServiceProviderMetadata() throws Exception {
    final Fixture fixture = fixture(USED_TRACE, false, true, true);

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .predict(
                        fixture.project(),
                        fixture.options(List.of(BAN), false, true),
                        fixture.resolver()))
        .hasMessageContaining(BANNED_PROVIDER_FAILURE);
  }

  private static AnalyzePrediction predict(final Fixture fixture)
      throws IOException, MojoFailureException {
    return new MavenElisionService()
        .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver());
  }

  @SuppressWarnings(
      "PMD.AvoidAccessibilityAlteration") // The descriptor is injected by Maven in production.
  private ElideMojo elideMojo(final Fixture fixture, final boolean trim)
      throws ReflectiveOperationException {
    fixture.session().getRequest().setOffline(true);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", fixture.project());
    set(mojo, "session", fixture.session());
    set(mojo, "projectDependenciesResolver", fixture.resolver());
    set(mojo, "traceFiles", List.of(fixture.trace().toFile()));
    set(mojo, "banishedDependencies", List.of(BAN));
    set(mojo, "sourceRootsComplete", true);
    set(mojo, "trimJars", trim);
    set(mojo, "leafOnly", false);
    set(mojo, "reportFile", fixture.trace().getParent().resolve(CLASS_USAGE_FILENAME).toFile());
    set(mojo, "summaryFile", fixture.trace().getParent().resolve(SUMMARY_FILENAME).toFile());
    set(
        mojo,
        "cveCacheDirectory",
        fixture.trace().getParent().resolve("vulnerability-cache").toFile());
    final Field pluginDescriptor =
        PluginCacheMojoSupport.class.getDeclaredField("pluginDescriptor");
    pluginDescriptor.setAccessible(true);
    pluginDescriptor.set(mojo, MavenPluginDescriptorFixtures.releasedPluginDescriptor());
    return mojo;
  }

  private static void assertAppliedBan(
      final Fixture fixture,
      final ResolverArtifactPlan plan,
      final org.apache.maven.artifact.Artifact retained,
      final Set<org.apache.maven.artifact.Artifact> directBefore)
      throws IOException {
    final MavenElisionReportSnapshot summary =
        MavenElisionReportWriter.read(fixture.trace().getParent().resolve(SUMMARY_FILENAME));
    assertAll(
        "the requested transitive artifact is absent from the final Maven and Resolver views",
        () -> assertThat(fixture.project().getArtifacts()).containsExactly(retained),
        () -> assertThat(fixture.project().getDependencyArtifacts()).isSameAs(directBefore),
        () ->
            assertThat(fixture.project().getArtifacts())
                .noneMatch(artifact -> BANNED_ARTIFACT_ID.equals(artifact.getArtifactId())),
        () -> assertThat(plan.graphProjection()).isNotNull(),
        () -> assertThat(plan.graphProjection().removedNodeIds()).hasSize(1),
        () -> assertThat(summary.appliedBans()).hasSize(1),
        () ->
            assertThat(summary.appliedBans().getFirst().status())
                .isEqualTo("FORCED_ABSENT_AFTER_RESOLUTION"),
        () -> assertThat(summary.appliedBans().getFirst().applied()).isTrue(),
        () ->
            assertThat(summary.rawDroppedCoordinates())
                .noneMatch(coordinate -> coordinate.startsWith("fixture:banned:")),
        () ->
            assertThat(summary.droppedArtifacts())
                .anyMatch(artifact -> artifact.coordinate().startsWith("fixture:banned:")),
        () ->
            assertThat(plan.replacements().keySet())
                .noneMatch(identity -> BANNED_ARTIFACT_ID.equals(identity.artifactId())));
  }

  private static ResolverArtifactPlan resolverPlan(final Fixture fixture) {
    final Object payload =
        fixture
            .session()
            .getRepositorySession()
            .getData()
            .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    return ResolverArtifactPlanStore.fromPayload(payload)
        .find(
            new ResolverArtifactPlan.ProjectIdentity(
                fixture.project().getBasedir().toPath(),
                fixture.project().getGroupId(),
                fixture.project().getArtifactId(),
                fixture.project().getVersion()));
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Artifact file snapshots must key by identity.
  private static Map<org.apache.maven.artifact.Artifact, java.io.File> artifactFiles(
      final Iterable<org.apache.maven.artifact.Artifact> resolved,
      final Iterable<org.apache.maven.artifact.Artifact> direct) {
    final Map<org.apache.maven.artifact.Artifact, java.io.File> files =
        new java.util.IdentityHashMap<>();
    resolved.forEach(artifact -> files.put(artifact, artifact.getFile()));
    direct.forEach(artifact -> files.putIfAbsent(artifact, artifact.getFile()));
    return files;
  }

  private static void assertSameArtifactReferences(
      final Iterable<org.apache.maven.artifact.Artifact> actual,
      final List<org.apache.maven.artifact.Artifact> expected) {
    final List<org.apache.maven.artifact.Artifact> actualItems = new ArrayList<>();
    actual.forEach(actualItems::add);
    assertThat(actualItems).hasSameSizeAs(expected);
    for (int index = 0; index < expected.size(); index++) {
      assertThat(actualItems.get(index)).isSameAs(expected.get(index));
    }
  }

  @SuppressWarnings(
      "PMD.AvoidAccessibilityAlteration") // Tests supply Maven-injected private state.
  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static List<String> fileSnapshot(final Path root) throws IOException {
    if (!Files.exists(root)) {
      return List.of();
    }
    try (Stream<Path> paths = Files.walk(root)) {
      final List<Path> files = paths.filter(Files::isRegularFile).sorted().toList();
      final List<String> snapshot = new ArrayList<>(files.size());
      for (final Path file : files) {
        snapshot.add(root.relativize(file) + ":" + ArtifactDigests.read(file).sha256());
      }
      return List.copyOf(snapshot);
    }
  }

  private Fixture basicFixture(final String traceContents) throws IOException {
    return fixture(traceContents, false);
  }

  private Fixture fixtureWithUnrelatedTraceDrop(final String traceContents) throws IOException {
    final Fixture fixture = fixture(traceContents, false, false, false);
    final Path unusedJar =
        jar(fixture.trace().getParent().resolve("unused.jar"), "unused/Leaf", false, null);
    final org.eclipse.aether.artifact.Artifact unused =
        resolverArtifact(UNUSED_ARTIFACT_ID, unusedJar);
    final org.eclipse.aether.graph.Dependency unusedDependency =
        new org.eclipse.aether.graph.Dependency(unused, RUNTIME_SCOPE);
    final DefaultDependencyNode usedNode =
        (DefaultDependencyNode) fixture.root().getChildren().getFirst();
    final List<DependencyNode> children = new ArrayList<>(usedNode.getChildren());
    children.add(new DefaultDependencyNode(unusedDependency));
    usedNode.setChildren(children);
    final org.apache.maven.artifact.Artifact liveUnused =
        org.apache.maven.RepositoryUtils.toArtifact(unused);
    liveUnused.setScope(RUNTIME_SCOPE);
    final Set<org.apache.maven.artifact.Artifact> artifacts =
        new LinkedHashSet<>(fixture.project().getArtifacts());
    artifacts.add(liveUnused);
    fixture.project().setArtifacts(artifacts);
    final org.eclipse.aether.graph.Dependency bannedDependency =
        usedNode.getChildren().getFirst().getDependency();
    final ProjectDependenciesResolver resolver =
        fixtureResolver(
            fixture.root(), List.of(fixture.usedDependency(), bannedDependency, unusedDependency));
    return new Fixture(
        fixture.project(),
        fixture.session(),
        fixture.repositorySession(),
        resolver,
        fixture.trace(),
        fixture.root(),
        fixture.usedDependency());
  }

  private Fixture activeExcludedFixture(final String traceContents) throws IOException {
    final Fixture fixture = basicFixture(traceContents);
    final DependencyNode originalRoot = fixture.root();
    final org.eclipse.aether.graph.Dependency bannedDependency =
        originalRoot.getChildren().getFirst().getChildren().getFirst().getDependency();
    final DefaultDependencyNode effectiveRoot =
        new DefaultDependencyNode(
            new org.eclipse.aether.artifact.DefaultArtifact(
                GROUP_ID, "consumer", "", "pom", VERSION));
    effectiveRoot.setChildren(List.of(new DefaultDependencyNode(fixture.usedDependency())));
    final ProjectDependenciesResolver activeResolver =
        resolutionRequest -> {
          final RepositorySystemSession repositorySession =
              resolutionRequest.getRepositorySession();
          final boolean audit = MavenOriginalInputAudit.isAuditMode(repositorySession);
          final DependencyNode selectedRoot = audit ? originalRoot : effectiveRoot;
          final List<org.eclipse.aether.graph.Dependency> dependencies =
              audit
                  ? List.of(fixture.usedDependency(), bannedDependency)
                  : List.of(fixture.usedDependency());
          final DependencyNode transformed;
          try {
            transformed =
                repositorySession
                    .getDependencyGraphTransformer()
                    .transformGraph(selectedRoot, context(repositorySession));
          } catch (final org.eclipse.aether.RepositoryException exception) {
            throw new IllegalStateException("Cannot transform active audit fixture", exception);
          }
          return result(dependencies, transformed);
        };
    final org.apache.maven.artifact.Artifact retained =
        fixture.project().getArtifacts().stream()
            .filter(artifact -> USED_ARTIFACT_ID.equals(artifact.getArtifactId()))
            .findFirst()
            .orElseThrow();
    fixture.project().setArtifacts(new LinkedHashSet<>(List.of(retained)));
    fixture.project().setDependencyArtifacts(new LinkedHashSet<>(List.of(retained)));
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(
            fixture.project(),
            List.of(
                new BanishedDependencyOriginalModel.ExecutionPolicy(
                    "run", "elide", VERSION, "initialize", "LIFECYCLE", List.of(BAN))),
            List.of(BAN));
    fixture
        .project()
        .setDependencies(
            BanishedDependencyLifecycleActivation.injectExclusions(
                fixture.project(), List.of(BAN)));
    EliderPreparationState.sessionData(fixture.session())
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    final String projectKey = MavenElisionGraphBinding.projectKey(fixture.project());
    final ResolverArtifactGraphSnapshot before =
        ResolverArtifactGraphSnapshot.capture(effectiveRoot, projectKey, false, null, 0L, 1L);
    final ResolverArtifactGraphSnapshot after =
        ResolverArtifactGraphSnapshot.capture(effectiveRoot, projectKey, false, null, 0L, 1L);
    final ResolverArtifactGraphCapturePair effectivePair =
        new ResolverArtifactGraphCapturePair(
            projectKey, "active-effective-fixture", 1L, false, null, 0L, before, after);
    EliderPreparationState.sessionData(fixture.session())
        .set(
            EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY,
            ResolverArtifactGraphSnapshotStore.empty().append(effectivePair).toPayload());
    MavenOriginalInputAudit.markHookPresent(fixture.session());
    return new Fixture(
        fixture.project(),
        fixture.session(),
        fixture.repositorySession(),
        activeResolver,
        fixture.trace(),
        (DefaultDependencyNode) originalRoot,
        fixture.usedDependency());
  }

  private Fixture fixture(final String traceContents, final boolean usedReferencesBanned)
      throws IOException {
    return fixture(traceContents, usedReferencesBanned, false);
  }

  private Fixture fixture(
      final String traceContents, final boolean usedReferencesBanned, final boolean serviceProvider)
      throws IOException {
    return fixture(traceContents, usedReferencesBanned, serviceProvider, false);
  }

  private Fixture fixture(
      final String traceContents,
      final boolean usedReferencesBanned,
      final boolean retainedServiceProvider,
      final boolean bannedServiceProvider)
      throws IOException {
    final Path directory = Files.createTempDirectory(temporaryDirectory, "ban-");
    final Path usedJar =
        jar(
            directory.resolve("used.jar"),
            "used/Api",
            usedReferencesBanned,
            retainedServiceProvider ? "used.Api" : null);
    final Path bannedJar =
        jar(
            directory.resolve("banned.jar"),
            "banned/Idle",
            false,
            bannedServiceProvider ? "banned.Service" : null);
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion(VERSION);
    project.setPackaging(JAR_TYPE);
    project.setFile(Files.createFile(directory.resolve("pom.xml")).toFile());
    project.getProperties().setProperty("maven.compiler.release", "17");
    final Build build = new Build();
    build.setDirectory(directory.resolve("target").toString());
    project.setBuild(build);
    final Dependency declared = new Dependency();
    declared.setGroupId(GROUP_ID);
    declared.setArtifactId(USED_ARTIFACT_ID);
    declared.setVersion(VERSION);
    project.getDependencies().add(declared);
    final Path sourceRoot = Files.createDirectories(directory.resolve("src"));
    Files.writeString(
        sourceRoot.resolve("App.java"), "public class App { private used.Api value; }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    final org.eclipse.aether.artifact.Artifact used = resolverArtifact(USED_ARTIFACT_ID, usedJar);
    final org.eclipse.aether.artifact.Artifact banned =
        resolverArtifact(BANNED_ARTIFACT_ID, bannedJar);
    final org.eclipse.aether.graph.Dependency usedDependency =
        new org.eclipse.aether.graph.Dependency(used, "compile");
    final org.eclipse.aether.graph.Dependency bannedDependency =
        new org.eclipse.aether.graph.Dependency(banned, RUNTIME_SCOPE);
    final org.apache.maven.artifact.Artifact liveUsed =
        org.apache.maven.RepositoryUtils.toArtifact(used);
    liveUsed.setScope("compile");
    final org.apache.maven.artifact.Artifact liveBanned =
        org.apache.maven.RepositoryUtils.toArtifact(banned);
    liveBanned.setScope(RUNTIME_SCOPE);
    project.setArtifacts(new LinkedHashSet<>(List.of(liveUsed, liveBanned)));
    project.setDependencyArtifacts(new LinkedHashSet<>(List.of(liveUsed)));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setBaseDirectory(directory.toFile());
    final PlexusContainer container =
        (PlexusContainer)
            Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class<?>[] {PlexusContainer.class},
                (proxy, method, arguments) ->
                    "lookup".equals(method.getName()) ? new DefaultToolchainManager() : null);
    final MavenSession session = new MavenSession(container, repositorySession, request, null);
    session.setCurrentProject(project);
    final DefaultDependencyNode root =
        new DefaultDependencyNode(
            new org.eclipse.aether.artifact.DefaultArtifact(
                GROUP_ID, "consumer", "", "pom", VERSION));
    final DefaultDependencyNode direct = new DefaultDependencyNode(usedDependency);
    direct.setChildren(List.of(new DefaultDependencyNode(bannedDependency)));
    root.setChildren(List.of(direct));
    final ProjectDependenciesResolver resolver =
        fixtureResolver(root, List.of(usedDependency, bannedDependency));
    final Path trace = directory.resolve("trace.lst");
    Files.writeString(trace, traceContents);
    return new Fixture(project, session, repositorySession, resolver, trace, root, usedDependency);
  }

  private static Path jar(
      final Path path,
      final String className,
      final boolean referencesBanned,
      final String serviceInterface)
      throws IOException {
    return jar(path, className, referencesBanned, serviceInterface, null, false);
  }

  private static Path jar(
      final Path path,
      final String className,
      final boolean referencesBanned,
      final String serviceInterface,
      final String nativeImageArguments,
      final boolean resource)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
    if (referencesBanned) {
      writer.visitField(Opcodes.ACC_PRIVATE, "dependency", "Lbanned/Idle;", null, null).visitEnd();
    }
    writer.visitEnd();
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(path))) {
      zip.putNextEntry(new ZipEntry(className + ".class"));
      zip.write(writer.toByteArray());
      zip.closeEntry();
      if (serviceInterface != null) {
        zip.putNextEntry(new ZipEntry("META-INF/services/" + serviceInterface));
        zip.write("banned.Idle\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        zip.closeEntry();
      }
      if (nativeImageArguments != null) {
        zip.putNextEntry(new ZipEntry("META-INF/native-image/test/native-image.properties"));
        zip.write(
            ("Args = " + nativeImageArguments + "\n")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        zip.closeEntry();
      }
      if (resource) {
        zip.putNextEntry(new ZipEntry("required.txt"));
        zip.write(new byte[] {42});
        zip.closeEntry();
      }
    }
    return path;
  }

  private static void writeClasslessJar(final Path path) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(path))) {
      zip.putNextEntry(new ZipEntry("data.txt"));
      zip.write("resource-only".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      zip.closeEntry();
    }
  }

  private static org.eclipse.aether.artifact.Artifact resolverArtifact(
      final String artifactId, final Path file) {
    return new org.eclipse.aether.artifact.DefaultArtifact(
        GROUP_ID,
        artifactId,
        "",
        JAR_TYPE,
        VERSION,
        Map.of("type", JAR_TYPE, "constitutesBuildPath", "true"),
        file.toFile());
  }

  private static DependencyGraphTransformationContext context(
      final RepositorySystemSession session) {
    return (DependencyGraphTransformationContext)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyGraphTransformationContext.class},
            (proxy, method, arguments) -> "getSession".equals(method.getName()) ? session : null);
  }

  private static DependencyResolutionResult result(
      final List<org.eclipse.aether.graph.Dependency> dependencies, final DependencyNode graph) {
    return (DependencyResolutionResult)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyResolutionResult.class},
            (proxy, method, arguments) ->
                switch (method.getName()) {
                  case "getCollectionErrors", "getUnresolvedDependencies", "getResolutionErrors" ->
                      List.of();
                  case "getResolvedDependencies" -> dependencies;
                  case "getDependencyGraph" -> graph;
                  default -> null;
                });
  }

  private static ProjectDependenciesResolver fixtureResolver(
      final DependencyNode root, final List<org.eclipse.aether.graph.Dependency> dependencies) {
    return resolutionRequest -> {
      final RepositorySystemSession detachedSession = resolutionRequest.getRepositorySession();
      final DependencyNode transformed;
      try {
        transformed =
            detachedSession
                .getDependencyGraphTransformer()
                .transformGraph(root, context(detachedSession));
      } catch (final org.eclipse.aether.RepositoryException exception) {
        throw new IllegalStateException("Cannot transform detached fixture", exception);
      }
      return result(dependencies, transformed);
    };
  }

  private record Fixture(
      MavenProject project,
      MavenSession session,
      DefaultRepositorySystemSession repositorySession,
      ProjectDependenciesResolver resolver,
      Path trace,
      DefaultDependencyNode root,
      org.eclipse.aether.graph.Dependency usedDependency) {
    private AnalysisOptions options(final List<String> bans) {
      return options(bans, false);
    }

    private AnalysisOptions options(final List<String> bans, final boolean trim) {
      return options(bans, trim, false);
    }

    private AnalysisOptions options(
        final List<String> bans, final boolean trim, final boolean conservativeServiceRoots) {
      return new AnalysisOptions(
          List.of(trace.toFile()),
          List.of(),
          bans,
          null,
          session,
          new CompletenessOptions(true, false, false, true),
          new TrimOptions(
              trim,
              List.of(),
              false,
              List.of(),
              false,
              MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
              MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
          new DynamicRootOptions(conservativeServiceRoots));
    }
  }
}
