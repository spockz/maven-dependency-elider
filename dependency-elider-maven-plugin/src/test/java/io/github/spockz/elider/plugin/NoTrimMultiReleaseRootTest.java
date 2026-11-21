/* WHY: Verifies no-trim analysis ignores MRJAR classes above targetRelease. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies no-trim analysis with MRJAR entries above the Java 21 target release. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.LawOfDemeter"
})
final class NoTrimMultiReleaseRootTest {
  private static final String MRJAR = "mrjar";
  private static final String UNUSED = "unused";
  private static final String BASE_CLASS = "mrjar/Base";
  private static final String BASE_BINARY_NAME = "mrjar.Base";
  private static final String JAVA22_ONLY = "mrjar/Java22Only";
  private static final String HELPER = "unused/Helper";
  @TempDir private Path tempDir;

  @Test
  void noTrimAnalysisSucceedsWhenRetainedMrjarHasClassOnlyAboveTargetRelease() throws Exception {
    final EffectiveAnalysis effective = runNoTrimAnalysis(false);
    final Analysis published = ElisionReachabilityEngine.finishEffectiveOutputs(effective);
    assertAll(
        () ->
            assertThat(effective.effectiveDecision().retainedArtifacts())
                .contains(MavenBanAuditTestSupport.coordinate(MRJAR)),
        () ->
            assertThat(effective.effectiveDecision().elidedArtifacts())
                .contains(MavenBanAuditTestSupport.coordinate(UNUSED)),
        () -> assertThat(published.decision().elidedArtifacts()).isNotEmpty());
  }

  @Test
  void noTrimAnalysisStillPromotesElidedDependencyReferencedAtTargetRelease() throws Exception {
    final EffectiveAnalysis effective = runNoTrimAnalysis(true);
    assertAll(
        () ->
            assertThat(effective.effectiveDecision().retainedArtifacts())
                .contains(
                    MavenBanAuditTestSupport.coordinate(MRJAR),
                    MavenBanAuditTestSupport.coordinate(UNUSED)),
        () -> assertThat(effective.effectiveDecision().elidedArtifacts()).isEmpty());
  }

  @Test
  void scansEachArchiveViewOnlyOnceEvenWithTwoPlatformsForOneRelease() throws Exception {
    final String object = "java/lang/Object";
    final String requiredInterface = "java/sql/Wrapper";
    final Set<String> references = Set.of(requiredInterface);
    final Path host = Path.of(System.getProperty("java.home"));
    final MavenRuntimePlatforms selected =
        MavenRuntimePlatforms.inspect(tempDir, List.of(host.toString()), null);
    final Path programPath =
        writeMultiReleaseJar(
            tempDir.resolve("program.jar"),
            Map.of(BASE_CLASS, classBytes(BASE_CLASS, HELPER, Opcodes.ACC_PUBLIC, references)),
            Map.of());
    final Path helperPath =
        writeMultiReleaseJar(
            tempDir.resolve("helper.jar"), Map.of(HELPER, classBytes(HELPER, null)), Map.of());
    final ElisionAnalysisModel.ArtifactSnapshot program =
        new ElisionAnalysisModel.ArtifactSnapshot(
            null, MavenBanAuditTestSupport.coordinate(MRJAR), programPath);
    final ElisionAnalysisModel.ArtifactSnapshot helper =
        new ElisionAnalysisModel.ArtifactSnapshot(
            null, MavenBanAuditTestSupport.coordinate(UNUSED), helperPath);
    final int release = Runtime.version().feature();
    final proguard.classfile.ClassPool full = new proguard.classfile.ClassPool();
    full.addClass(new proguard.classfile.LibraryClass(0, object, null));
    full.addClass(new proguard.classfile.LibraryClass(0, requiredInterface, object));
    final proguard.classfile.ClassPool reduced = new proguard.classfile.ClassPool();
    reduced.addClass(new proguard.classfile.LibraryClass(0, object, null));
    final TierArchiveProjector.TierContext view =
        new TierArchiveProjector.TierContext(
            release,
            release,
            Map.of(),
            Map.of(program, programPath, helper, helperPath),
            Map.of(program, Set.of(BASE_BINARY_NAME), helper, Set.of("unused.Helper")),
            Map.of(BASE_BINARY_NAME, List.of(program), "unused.Helper", List.of(helper)),
            Map.of(),
            Map.of(),
            full);
    final TrimRequest request =
        new TrimRequest(
            project(),
            null,
            null,
            List.of(program, helper),
            new TrimScanInputs(null, Map.of()),
            Set.of(program.coordinate()),
            new TrimEvidence(
                io.github.spockz.elider.model.TraceData.empty(),
                Set.of(),
                Set.of(BASE_BINARY_NAME),
                Set.of()),
            new TrimPolicy(List.of(), false, List.of(), false),
            java.util.Optional.empty(),
            selected);
    final MultiReleaseTrimContext operation =
        new MultiReleaseTrimContext(request, Map.of(), Set.of(), release, release);
    final TierRootPlanner.RootPlan roots =
        new TierRootPlanner.RootPlan(
            List.of(),
            Set.of(),
            Set.of(program),
            Map.of(),
            Map.of(),
            Set.of(),
            Set.of(BASE_BINARY_NAME));
    final TierClosureAnalyzer.ClosureResult closure =
        NoTrimClosureAnalyzer.analyze(operation, List.of(view, view.withPlatform(full)), roots);
    assertAll(
        () -> assertThat(closure.reachableArtifacts()).containsExactly(helper.coordinate()),
        () -> assertThat(closure.analysisRuns()).isEqualTo(1),
        () ->
            org.assertj.core.api.Assertions.assertThatThrownBy(
                    () ->
                        NoTrimClosureAnalyzer.analyze(
                            operation, List.of(view, view.withPlatform(reduced)), roots))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("java.sql.Wrapper")
                .hasMessageContaining(BASE_BINARY_NAME));
  }

  private EffectiveAnalysis runNoTrimAnalysis(final boolean baseReferencesUnused)
      throws IOException, MojoFailureException {
    final Path mrjarPath =
        writeMultiReleaseJar(
            tempDir.resolve("mrjar.jar"),
            Map.of(BASE_CLASS, classBytes(BASE_CLASS, baseReferencesUnused ? HELPER : null)),
            Map.of(22, Map.of(JAVA22_ONLY, classBytes(JAVA22_ONLY, null, 0))));
    final Path unusedPath =
        writeMultiReleaseJar(
            tempDir.resolve("unused.jar"), Map.of(HELPER, classBytes(HELPER, null)), Map.of());
    final MavenProject project = project();
    final Artifact mrjarArtifact = MavenBanAuditTestSupport.mavenArtifact(MRJAR, mrjarPath);
    final Artifact unusedArtifact = MavenBanAuditTestSupport.mavenArtifact(UNUSED, unusedPath);
    project.setArtifacts(new LinkedHashSet<>(List.of(mrjarArtifact, unusedArtifact)));
    final Path traceFile = tempDir.resolve("trace.lst");
    Files.writeString(traceFile, BASE_CLASS.replace('/', '.') + "\n");
    final MavenElisionService service = new MavenElisionService();
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(traceFile.toFile()),
            List.of(),
            List.of(),
            null,
            null,
            new CompletenessOptions(false, true, false, true),
            new TrimOptions(
                false,
                List.of(),
                false,
                List.of(),
                false,
                1,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                MavenPluginDescriptorFixtures.releasedProducerResolution()),
            new DynamicRootOptions(false),
            null,
            false);
    final PreparedAnalysis prepared = service.prepare(project, options);
    final DependencyNode root = MavenBanAuditTestSupport.root();
    root.setChildren(
        List.of(
            MavenBanAuditTestSupport.node(MRJAR, mrjarPath),
            MavenBanAuditTestSupport.node(UNUSED, unusedPath)));
    final ResolverArtifactGraphCapturePair pair =
        MavenBanAuditTestSupport.graphPair(
            project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion(),
            root);
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(pair, prepared.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            evaluation,
            prepared.graphBinding().inventoryFingerprint(),
            prepared.graphBinding().operationFingerprint(),
            pair);
    final PreparedAnalysis bound =
        MavenElisionServiceEffectiveAnalysisFixtures.withBinding(prepared, binding);
    return ElisionReachabilityEngine.finishAnalysis(bound);
  }

  private MavenProject project() throws IOException {
    final MavenProject project = MavenBanAuditTestSupport.project(tempDir);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path target = Files.createDirectories(tempDir.resolve("target"));
    final Path classes = Files.createDirectories(target.resolve("classes"));
    final Path seedClass = classes.resolve("consumer/Seed.class");
    Files.createDirectories(seedClass.getParent());
    Files.write(seedClass, classBytes("consumer/Seed", null));
    final Build build = new Build();
    build.setDirectory(target.toString());
    build.setOutputDirectory(classes.toString());
    project.setBuild(build);
    return project;
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static Path writeMultiReleaseJar(
      final Path path,
      final Map<String, byte[]> baseClasses,
      final Map<Integer, Map<String, byte[]>> versionedClasses)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    if (!versionedClasses.isEmpty()) {
      manifest.getMainAttributes().putValue("Multi-Release", "true");
    }
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      for (final Map.Entry<String, byte[]> entry : baseClasses.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
      for (final Map.Entry<Integer, Map<String, byte[]>> tier : versionedClasses.entrySet()) {
        for (final Map.Entry<String, byte[]> entry : tier.getValue().entrySet()) {
          output.putNextEntry(
              new JarEntry("META-INF/versions/" + tier.getKey() + "/" + entry.getKey() + ".class"));
          output.write(entry.getValue());
          output.closeEntry();
        }
      }
    }
    return path;
  }

  private static byte[] classBytes(final String name, final String reference) {
    return classBytes(name, reference, Opcodes.ACC_PUBLIC);
  }

  private static byte[] classBytes(final String name, final String reference, final int access) {
    return classBytes(name, reference, access, Set.of());
  }

  private static byte[] classBytes(
      final String name, final String reference, final int access, final Set<String> interfaces) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, access, name, null, "java/lang/Object", interfaces.toArray(String[]::new));
    if (reference != null) {
      final MethodVisitor method =
          writer.visitMethod(
              Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "use", "()L" + reference + ";", null, null);
      method.visitCode();
      method.visitInsn(Opcodes.ACONST_NULL);
      method.visitInsn(Opcodes.ARETURN);
      method.visitMaxs(1, 0);
      method.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }
}
