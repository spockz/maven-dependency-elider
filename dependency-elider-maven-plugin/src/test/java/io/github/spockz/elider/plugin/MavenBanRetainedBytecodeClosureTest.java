/* WHY: Verifies ban-closure scanning respects live-class liveness for pass-through JARs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.plugin.AnalysisEnvironment.JdkToolchainState;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots;
import io.github.spockz.elider.plugin.nativeimage.NativeImageScanContext;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies pass-through ban-closure scanning uses live program classes. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.ExcessiveImports",
  "PMD.CouplingBetweenObjects"
})
final class MavenBanRetainedBytecodeClosureTest {
  private static final String PASSTHROUGH = "passthrough";
  private static final String LIVE = "pass/Live";
  private static final String DEAD = "pass/Dead";
  private static final String BANNED = "banned/Absent";
  @TempDir private Path temporaryDirectory;

  @Test
  void passThroughJarScansOnlyLiveClassesWhenTrimIsEnabled() throws Exception {
    final Path jarPath =
        jarWithClasses(
            "pass-dead-banned.jar",
            Map.of(
                LIVE, classBytes(LIVE, null),
                DEAD, classBytes(DEAD, BANNED)));
    final Scenario scenario = scenario(jarPath);
    assertThatCode(
            () ->
                MavenBanAuditContext.empty()
                    .verifyRetainedClosure(
                        scenario.prepared(),
                        scenario.decision(),
                        scenario.trimAnalysis(),
                        Set.of(),
                        Map.of(
                            MavenBanAuditTestSupport.coordinate("banned"),
                            Set.of("banned.Absent"))))
        .doesNotThrowAnyException();
  }

  @Test
  void passThroughJarStillRejectsBannedReferenceFromLiveClass() throws Exception {
    final Path jarPath =
        jarWithClasses(
            "pass-live-banned.jar",
            Map.of(
                LIVE, classBytes(LIVE, BANNED),
                DEAD, classBytes(DEAD, null)));
    final Scenario scenario = scenario(jarPath);
    assertThatThrownBy(
            () ->
                MavenBanAuditContext.empty()
                    .verifyRetainedClosure(
                        scenario.prepared(),
                        scenario.decision(),
                        scenario.trimAnalysis(),
                        Set.of(),
                        Map.of(
                            MavenBanAuditTestSupport.coordinate("banned"),
                            Set.of("banned.Absent"))))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("retained archive")
        .hasMessageContaining("no retained provider for class banned.Absent");
  }

  private Scenario scenario(final Path jarPath) throws IOException, MojoFailureException {
    final MavenProject project = MavenBanAuditTestSupport.project(temporaryDirectory);
    final Artifact mavenArtifact = MavenBanAuditTestSupport.mavenArtifact(PASSTHROUGH, jarPath);
    project.setArtifacts(Set.of(mavenArtifact));
    final List<ArtifactSnapshot> snapshots =
        MavenArtifactInventory.snapshots(List.of(mavenArtifact));
    final ArtifactCoordinate coordinate = MavenBanAuditTestSupport.coordinate(PASSTHROUGH);
    final AnalysisEnvironment environment =
        new AnalysisEnvironment(
            Map.of(), Map.of(), temporaryDirectory, JdkToolchainState.UNSELECTED, null);
    final List<ArtifactFileRef> scanCandidates =
        List.of(ArtifactFileRef.fromPath(coordinate, jarPath));
    final NativeImageScanContext scanContext =
        NativeImageScanContext.create(scanCandidates, temporaryDirectory);
    final Map<Path, DependencyDynamicRoots.RootScan> scans = new ConcurrentHashMap<>();
    scans.put(jarPath, DependencyDynamicRoots.scan(jarPath, scanContext));
    final DynamicRootInputs dynamicRoots =
        new DynamicRootInputs(
            Set.of(), Set.of(), Set.of(), Map.of(), Map.of(), scans, Map.of(), Set.of(), List.of());
    final String passThroughIdentity = TrimPassThroughPlanner.artifactIdentity(coordinate);
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(),
            List.of(),
            List.of("fixture:banned"),
            null,
            null,
            new CompletenessOptions(false, false, false, true),
            new TrimOptions(
                true,
                List.of(),
                false,
                List.of(passThroughIdentity),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new DynamicRootOptions(false),
            environment);
    final ElisionDecision decision =
        new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0L);
    final TraceData trace = TraceData.of(Set.of("pass.Live"));
    final PreparedAnalysis prepared =
        new PreparedAnalysis(
            project,
            options,
            snapshots,
            true,
            List.of(),
            decision,
            decision,
            null,
            Optional.empty(),
            scanCandidates,
            trace,
            new JarIndexScanner().scan(scanCandidates),
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
    final TrimRequest request =
        TrimRequestFactory.fromPreparedAnalysis(prepared, decision.retainedArtifacts(), Set.of());
    final TrimAnalysisResult trimAnalysis =
        MultiReleaseJarTrimmer.analyzeInMemory(request, Map.of(), Set.of());
    return new Scenario(prepared, decision, trimAnalysis);
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Path jarWithClasses(final String name, final Map<String, byte[]> classes)
      throws IOException {
    final Path path = temporaryDirectory.resolve(name);
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return path;
  }

  private static byte[] classBytes(final String name, final String reference) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
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

  private record Scenario(
      PreparedAnalysis prepared, ElisionDecision decision, TrimAnalysisResult trimAnalysis) {}
}
