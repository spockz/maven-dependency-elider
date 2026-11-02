// WHY: Proves original-only providers are removed by effective reachability, including shared
// descendants.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.plugin.AnalysisEnvironment.JdkToolchainState;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports"
})
final class MavenBanAuditContextTest {
  private static final String GROUP = "fixture";
  private static final String VERSION = "1.0";
  private static final String LEFT = "left";
  private static final String RIGHT = "right";
  private static final String SHARED = "shared";
  private static final String EXCLUDED = "excluded";
  private static final String EXCLUDED_BEFORE_RESOLUTION = "excluded-before-resolution";
  private static final String EFFECTIVE = "effective";
  private static final String OBJECT_INTERNAL_NAME = "java/lang/Object";

  @TempDir private Path temporaryDirectory;

  @Test
  void excludesOriginalOnlyDescendantButPreservesAlternateEffectivePath() throws Exception {
    final Path leftJar = jar(LEFT);
    final Path rightJar = jar(RIGHT);
    final Path sharedJar = jar(SHARED);
    final Path excludedJar = jar(EXCLUDED);
    final MavenProject project = MavenBanAuditTestSupport.project(temporaryDirectory);
    final String projectKey = MavenElisionGraphBinding.projectKey(project);

    final DependencyNode originalRoot = MavenBanAuditTestSupport.root();
    final DefaultDependencyNode originalLeft = MavenBanAuditTestSupport.node(LEFT, leftJar);
    final DefaultDependencyNode originalRight = MavenBanAuditTestSupport.node(RIGHT, rightJar);
    final DefaultDependencyNode leftShared = MavenBanAuditTestSupport.node(SHARED, sharedJar);
    final DefaultDependencyNode rightShared = MavenBanAuditTestSupport.node(SHARED, sharedJar);
    leftShared.setChildren(List.of(MavenBanAuditTestSupport.node(EXCLUDED, excludedJar)));
    originalLeft.setChildren(List.of(leftShared));
    originalRight.setChildren(List.of(rightShared));
    originalRoot.setChildren(List.of(originalLeft, originalRight));

    final DependencyNode effectiveRoot = MavenBanAuditTestSupport.root();
    final DefaultDependencyNode effectiveRight = MavenBanAuditTestSupport.node(RIGHT, rightJar);
    effectiveRight.setChildren(List.of(MavenBanAuditTestSupport.node(SHARED, sharedJar)));
    effectiveRoot.setChildren(List.of(effectiveRight));

    final ResolverArtifactGraphCapturePair originalPair =
        MavenBanAuditTestSupport.graphPair(projectKey, originalRoot);
    final ResolverArtifactGraphCapturePair effectivePair =
        MavenBanAuditTestSupport.graphPair(projectKey, effectiveRoot);
    final List<MavenOriginalInputAudit.AuditArtifact> originalArtifacts =
        List.of(
            MavenBanAuditTestSupport.auditArtifact(LEFT, leftJar),
            MavenBanAuditTestSupport.auditArtifact(RIGHT, rightJar),
            MavenBanAuditTestSupport.auditArtifact(SHARED, sharedJar),
            MavenBanAuditTestSupport.auditArtifact(EXCLUDED, excludedJar));
    final MavenOriginalInputAudit.Inventory originalInventory =
        new MavenOriginalInputAudit.Inventory(
            BanishedDependencyOriginalModel.projectIdentity(project),
            "frozen-source-fingerprint",
            originalPair,
            originalArtifacts,
            List.of(
                MavenBanAuditTestSupport.coordinate(LEFT),
                MavenBanAuditTestSupport.coordinate(RIGHT)),
            null);
    final List<ArtifactSnapshot> effectiveSnapshots =
        MavenArtifactInventory.snapshots(
            List.of(
                MavenBanAuditTestSupport.mavenArtifact(RIGHT, rightJar),
                MavenBanAuditTestSupport.mavenArtifact(SHARED, sharedJar)));
    final AnalysisEnvironment environment =
        new AnalysisEnvironment(
            Map.of(), Map.of(), temporaryDirectory, JdkToolchainState.UNSELECTED, null);
    final MavenAnalysisResolutionContext effectiveContext =
        new MavenAnalysisResolutionContext(
            new MavenProject(project),
            project,
            MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
            environment,
            new ArtifactViews(effectiveSnapshots, true, List.of(effectiveSnapshots.getFirst())),
            "resolved-fingerprint",
            "direct-fingerprint",
            effectivePair);

    final MavenBanAuditContext auditContext =
        MavenBanAuditContext.create(originalInventory, effectiveContext);
    final MavenOriginalInputAudit.Inventory changedAuditInventory =
        new MavenOriginalInputAudit.Inventory(
            originalInventory.project(),
            "different-frozen-source-fingerprint",
            originalInventory.graphPair(),
            originalInventory.resolvedArtifacts(),
            originalInventory.directArtifacts(),
            null);
    final MavenBanAuditContext changedAuditContext =
        MavenBanAuditContext.create(changedAuditInventory, effectiveContext);
    final MavenElisionGraphBinding.Result operation =
        new MavenElisionGraphBinding.Result(
            null, "same-inventory", "same-operation", effectivePair);
    final String operationFingerprint =
        operation
            .withAdditionalOperationFingerprint(
                MavenBanPlan.contextFingerprint(
                    effectivePair.after().graphFingerprint(), auditContext))
            .operationFingerprint();
    final String changedOperationFingerprint =
        operation
            .withAdditionalOperationFingerprint(
                MavenBanPlan.contextFingerprint(
                    effectivePair.after().graphFingerprint(), changedAuditContext))
            .operationFingerprint();
    final MavenElisionGraphBinding.Result baseOperation =
        new MavenElisionGraphBinding.Result(null, "inventory", "operation", effectivePair);
    final String operationWithAudit =
        baseOperation
            .withAdditionalOperationFingerprint(
                MavenBanPlan.contextFingerprint(
                    effectivePair.after().graphFingerprint(), auditContext))
            .operationFingerprint();
    final String operationWithChangedAudit =
        baseOperation
            .withAdditionalOperationFingerprint(
                MavenBanPlan.contextFingerprint(
                    effectivePair.after().graphFingerprint(), changedAuditContext))
            .operationFingerprint();

    assertAll(
        "original-only membership, freshness identity, and resource closure are independent",
        () ->
            assertThat(auditContext.auditOnlyArtifacts())
                .extracting(artifact -> artifact.coordinate().artifactId())
                .containsExactly(EXCLUDED, LEFT),
        () ->
            assertThat(auditContext.auditOnlyArtifacts())
                .extracting(artifact -> artifact.coordinate().artifactId())
                .doesNotContain(SHARED, RIGHT),
        () ->
            assertThat(
                    MavenBanPlan.contextFingerprint(
                        effectivePair.after().graphFingerprint(), auditContext))
                .isNotEqualTo(
                    MavenBanPlan.contextFingerprint(
                        effectivePair.after().graphFingerprint(), changedAuditContext)),
        () -> assertThat(operationFingerprint).isNotEqualTo(changedOperationFingerprint),
        () -> assertThat(operationWithAudit).isNotEqualTo(operationWithChangedAudit),
        () ->
            assertThatThrownBy(
                    () ->
                        verifyClasslessResourceClosure(
                            effectiveContext,
                            effectiveSnapshots,
                            auditContext,
                            rightJar,
                            temporaryDirectory))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("retained resource pattern")
                .hasMessageContaining("original-only provider"));
  }

  @Test
  void classifiesExcludedBeforeResolutionFromOriginalAuditAndRejectsMutatedBytes()
      throws Exception {
    final Path effectiveJar = jar(EFFECTIVE);
    final Path excludedJar = jar(EXCLUDED_BEFORE_RESOLUTION);
    final MavenProject project = MavenBanAuditTestSupport.project(temporaryDirectory);
    final org.apache.maven.model.Dependency direct = new org.apache.maven.model.Dependency();
    direct.setGroupId(GROUP);
    direct.setArtifactId(EFFECTIVE);
    direct.setVersion(VERSION);
    project.setDependencies(List.of(direct));
    final String projectKey = MavenElisionGraphBinding.projectKey(project);
    final DependencyNode originalRoot = MavenBanAuditTestSupport.root();
    final DefaultDependencyNode originalEffective =
        MavenBanAuditTestSupport.node(EFFECTIVE, effectiveJar);
    originalEffective.setChildren(
        List.of(MavenBanAuditTestSupport.node(EXCLUDED_BEFORE_RESOLUTION, excludedJar)));
    originalRoot.setChildren(List.of(originalEffective));
    final DependencyNode effectiveRoot = MavenBanAuditTestSupport.root();
    effectiveRoot.setChildren(List.of(MavenBanAuditTestSupport.node(EFFECTIVE, effectiveJar)));
    final ResolverArtifactGraphCapturePair originalPair =
        MavenBanAuditTestSupport.graphPair(projectKey, originalRoot);
    final ResolverArtifactGraphCapturePair effectivePair =
        MavenBanAuditTestSupport.graphPair(projectKey, effectiveRoot);
    final ArtifactSnapshot effectiveSnapshot =
        MavenArtifactInventory.snapshots(
                List.of(MavenBanAuditTestSupport.mavenArtifact(EFFECTIVE, effectiveJar)))
            .getFirst();
    final AnalysisEnvironment environment =
        new AnalysisEnvironment(
            Map.of(), Map.of(), temporaryDirectory, JdkToolchainState.UNSELECTED, null);
    final MavenAnalysisResolutionContext effectiveContext =
        new MavenAnalysisResolutionContext(
            new MavenProject(project),
            project,
            MavenAnalysisResolutionContext.Provenance.CAPTURED_EFFECTIVE_RESOLVER,
            environment,
            new ArtifactViews(List.of(effectiveSnapshot), true, List.of(effectiveSnapshot)),
            "resolved-fingerprint",
            "direct-fingerprint",
            effectivePair);
    final MavenOriginalInputAudit.Inventory originalAudit =
        new MavenOriginalInputAudit.Inventory(
            BanishedDependencyOriginalModel.projectIdentity(project),
            "frozen-source-fingerprint",
            originalPair,
            List.of(
                MavenBanAuditTestSupport.auditArtifact(EFFECTIVE, effectiveJar),
                MavenBanAuditTestSupport.auditArtifact(EXCLUDED_BEFORE_RESOLUTION, excludedJar)),
            List.of(MavenBanAuditTestSupport.coordinate(EFFECTIVE)),
            null);
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(),
            List.of(),
            List.of("fixture:" + EXCLUDED_BEFORE_RESOLUTION),
            null,
            null,
            new CompletenessOptions(true, false, false, true),
            new TrimOptions(
                false,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new DynamicRootOptions(false),
            environment);

    final MavenBanPlan plan = MavenBanPlan.create(effectiveContext, options, originalAudit);

    assertAll(
        "the plan classification and post-audit byte freshness check are independent",
        () ->
            assertThat(plan.entries())
                .singleElement()
                .satisfies(
                    entry ->
                        assertAll(
                            () ->
                                assertThat(entry.status())
                                    .isEqualTo(
                                        MavenBanPlan.Entry.Status.EXCLUDED_BEFORE_RESOLUTION),
                            () -> assertThat(entry.artifacts()).isEmpty(),
                            () ->
                                assertThat(entry.originalArtifacts())
                                    .containsExactly(
                                        MavenBanAuditTestSupport.coordinate(
                                            EXCLUDED_BEFORE_RESOLUTION)))),
        () -> {
          Files.writeString(excludedJar, "mutated after the original audit");
          assertThatThrownBy(plan::verifyAuditBytesFresh)
              .isInstanceOf(IOException.class)
              .hasMessageContaining("bytes changed after audit");
        });
  }

  @Test
  void checksBanReferencesFromClassesRetainedOnlyInAnUpperMrjarTier() throws Exception {
    final Path multiReleaseJar = multiReleaseJar(RIGHT);
    final Path sharedJar = jar(SHARED);
    final MavenProject project = MavenBanAuditTestSupport.project(temporaryDirectory);
    final List<ArtifactSnapshot> snapshots =
        MavenArtifactInventory.snapshots(
            List.of(
                MavenBanAuditTestSupport.mavenArtifact(RIGHT, multiReleaseJar),
                MavenBanAuditTestSupport.mavenArtifact(SHARED, sharedJar)));
    final AnalysisEnvironment environment =
        new AnalysisEnvironment(
            Map.of(), Map.of(), temporaryDirectory, JdkToolchainState.UNSELECTED, null);
    final List<ArtifactFileRef> scanCandidates =
        snapshots.stream()
            .map(
                snapshot -> {
                  try {
                    return ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath());
                  } catch (final IOException exception) {
                    throw new IllegalStateException(exception);
                  }
                })
            .toList();
    final NativeImageScanContext scanContext =
        NativeImageScanContext.create(scanCandidates, temporaryDirectory);
    final Map<Path, DependencyDynamicRoots.RootScan> scans = new ConcurrentHashMap<>();
    for (final ArtifactFileRef candidate : scanCandidates) {
      scans.put(
          candidate.filePath(), DependencyDynamicRoots.scan(candidate.filePath(), scanContext));
    }
    final DynamicRootInputs dynamicRoots =
        new DynamicRootInputs(
            Set.of(), Set.of(), Set.of(), Map.of(), Map.of(), scans, Map.of(), Set.of(), List.of());
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(),
            List.of(),
            List.of("fixture:banned"),
            null,
            null,
            new CompletenessOptions(true, false, false, true),
            new TrimOptions(
                true,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new DynamicRootOptions(false),
            environment);
    final ElisionDecision decision =
        new ElisionDecision(
            Set.of(
                MavenBanAuditTestSupport.coordinate(RIGHT),
                MavenBanAuditTestSupport.coordinate(SHARED)),
            Set.of(),
            Map.of(),
            Map.of(),
            0L);
    final PreparedAnalysis prepared =
        new PreparedAnalysis(
            project,
            options,
            snapshots,
            true,
            List.of(snapshots.getFirst()),
            decision,
            decision,
            null,
            Optional.empty(),
            scanCandidates,
            TraceData.empty(),
            new io.github.spockz.elider.scanner.JarIndexScanner().scan(scanCandidates),
            dynamicRoots,
            Set.of(),
            Set.of(),
            Set.of(),
            "production-output-fingerprint",
            "input-fingerprint",
            "direct-input-fingerprint",
            null,
            MavenElisionPolicyIdentity.normalize(options),
            null,
            null,
            MavenBanPlan.empty());
    final TrimAnalysisResult trimAnalysis =
        new TrimAnalysisResult(
            Map.of(
                MavenBanAuditTestSupport.coordinate(RIGHT),
                new io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis(
                    1, Set.of(), Set.of()),
                MavenBanAuditTestSupport.coordinate(SHARED),
                new io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis(
                    0, Set.of(), Set.of())),
            Map.of(),
            Set.of(
                MavenBanAuditTestSupport.coordinate(RIGHT),
                MavenBanAuditTestSupport.coordinate(SHARED)),
            1,
            17,
            17,
            Path.of(System.getProperty("java.home")),
            List.of(),
            List.of(17),
            Map.of(MavenBanAuditTestSupport.coordinate(RIGHT), Set.of("right/UpperOnly")));

    assertThatThrownBy(
            () ->
                MavenBanAuditContext.empty()
                    .verifyRetainedClosure(
                        prepared,
                        decision,
                        trimAnalysis,
                        Set.of(),
                        Map.of(
                            MavenBanAuditTestSupport.coordinate("banned"), Set.of("banned.Idle"))))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("retained archive")
        .hasMessageContaining("no retained provider for class banned.Idle");
  }

  private Path jar(final String artifactId) throws IOException {
    final Path path = temporaryDirectory.resolve(artifactId + ".jar");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(path))) {
      zip.putNextEntry(new ZipEntry("resource.txt"));
      zip.write(artifactId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      zip.closeEntry();
      if (RIGHT.equals(artifactId)) {
        zip.putNextEntry(new ZipEntry("META-INF/native-image/test/native-image.properties"));
        zip.write(
            "Args = -H:IncludeResources=original-only[.]txt\n"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        zip.closeEntry();
      }
      if (EXCLUDED.equals(artifactId)) {
        zip.putNextEntry(new ZipEntry("original-only.txt"));
        zip.write(new byte[] {1});
        zip.closeEntry();
      }
    }
    return path;
  }

  private Path multiReleaseJar(final String artifactId) throws IOException {
    final Path path = temporaryDirectory.resolve(artifactId + "-mr.jar");
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V17, Opcodes.ACC_PUBLIC, "right/UpperOnly", null, OBJECT_INTERNAL_NAME, null);
    writer.visitField(Opcodes.ACC_PRIVATE, "dependency", "Lbanned/Idle;", null, null).visitEnd();
    writer.visitEnd();
    try (JarOutputStream zip = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      zip.putNextEntry(new JarEntry("META-INF/versions/17/right/UpperOnly.class"));
      zip.write(writer.toByteArray());
      zip.closeEntry();
    }
    return path;
  }

  private static void verifyClasslessResourceClosure(
      final MavenAnalysisResolutionContext context,
      final List<ArtifactSnapshot> snapshots,
      final MavenBanAuditContext auditContext,
      final Path declaringJar,
      final Path projectBase)
      throws IOException, MojoFailureException {
    final List<ArtifactFileRef> scanCandidates =
        snapshots.stream()
            .map(
                snapshot -> {
                  try {
                    return ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath());
                  } catch (final IOException exception) {
                    throw new IllegalStateException(exception);
                  }
                })
            .toList();
    final DependencyDynamicRoots.RootScan rootScan =
        DependencyDynamicRoots.scan(
            declaringJar, NativeImageScanContext.create(scanCandidates, projectBase));
    final Map<Path, DependencyDynamicRoots.RootScan> scans = new ConcurrentHashMap<>();
    final NativeImageScanContext scanContext =
        NativeImageScanContext.create(scanCandidates, projectBase);
    final Path declaringRealPath = declaringJar.toRealPath();
    for (final ArtifactFileRef candidate : scanCandidates) {
      final DependencyDynamicRoots.RootScan candidateScan =
          candidate.filePath().toRealPath().equals(declaringRealPath)
              ? rootScan
              : DependencyDynamicRoots.scan(candidate.filePath(), scanContext);
      scans.put(candidate.filePath(), candidateScan);
    }
    final DynamicRootInputs dynamicRoots =
        new DynamicRootInputs(
            Set.of(), Set.of(), Set.of(), Map.of(), Map.of(), scans, Map.of(), Set.of(), List.of());
    final AnalysisEnvironment environment = context.environment();
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(),
            List.of(),
            List.of(),
            null,
            null,
            new CompletenessOptions(true, false, false, true),
            new TrimOptions(
                false,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new DynamicRootOptions(false),
            environment);
    final Set<ArtifactCoordinate> retained =
        Set.of(
            MavenBanAuditTestSupport.coordinate(RIGHT),
            MavenBanAuditTestSupport.coordinate(SHARED));
    final ElisionDecision decision =
        new ElisionDecision(retained, Set.of(), Map.of(), Map.of(), 0L);
    final PreparedAnalysis prepared =
        new PreparedAnalysis(
            context.project(),
            options,
            snapshots,
            true,
            List.of(snapshots.getFirst()),
            decision,
            decision,
            null,
            Optional.empty(),
            scanCandidates,
            TraceData.empty(),
            new ArtifactClassIndex(Map.of()),
            dynamicRoots,
            Set.of(),
            Set.of(),
            Set.of(),
            "production-output-fingerprint",
            "input-fingerprint",
            "direct-input-fingerprint",
            null,
            MavenElisionPolicyIdentity.normalize(options),
            null,
            context,
            MavenBanPlan.empty());
    final TrimAnalysisResult trimAnalysis =
        new TrimAnalysisResult(
            Map.of(),
            Map.of(),
            Set.of(),
            0,
            17,
            17,
            Path.of(System.getProperty("java.home")),
            List.of(),
            List.of(),
            Map.of());

    auditContext.verifyRetainedClosure(prepared, decision, trimAnalysis, Set.of(), Map.of());
  }
}
