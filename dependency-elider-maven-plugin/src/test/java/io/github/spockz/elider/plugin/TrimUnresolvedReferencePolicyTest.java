/* WHY: Verifies trimPassThroughOnUnresolved between trimming and pass-through fallback. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies default absent-reference tolerance vs. pass-through demotion fallback. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class TrimUnresolvedReferencePolicyTest {
  private static final String LIVE = "candidate/Live";
  private static final String DELEGATE = "candidate/Delegate";
  private static final String DEAD = "candidate/Dead";
  private static final String DOWNSTREAM = "downstream/DeadTarget";
  private static final String ABSENT_OPTIONAL = "kotlin/coroutines/Continuation";
  @TempDir private Path tempDir;

  @Test
  void defaultToleratesAbsentOptionalReferenceWhileStillTrimmingCandidate() throws Exception {
    final Fixture fixture = fixture(false);
    fixture.mojo().execute();
    final TrimAnalysisResult trim = fixture.analysis().get().trimAnalysis();
    final ArtifactCoordinate candidate = coordinate("candidate");
    final ArtifactCoordinate downstream = coordinate("downstream");
    assertAll(
        () -> assertThat(trim.candidateAnalyses()).containsKey(candidate),
        () ->
            assertThat(trim.candidateAnalyses().get(candidate).retainedClasses())
                .contains(LIVE, DELEGATE)
                .doesNotContain(DEAD),
        () -> assertThat(trim.reachableArtifacts()).doesNotContain(downstream));
  }

  @Test
  void passThroughOnUnresolvedDemotesCandidateWhileExpandingFromLivenessRoots() throws Exception {
    final Fixture fixture = fixture(true);
    fixture.mojo().execute();
    final TrimAnalysisResult trim = fixture.analysis().get().trimAnalysis();
    final ArtifactCoordinate candidate = coordinate("candidate");
    final ArtifactCoordinate downstream = coordinate("downstream");
    assertAll(
        () -> assertThat(trim.candidateAnalyses()).doesNotContainKey(candidate),
        () -> assertThat(trim.reachableArtifacts()).doesNotContain(downstream));
  }

  private Fixture fixture(final boolean passThroughOnUnresolved)
      throws IOException, ReflectiveOperationException {
    final Path candidatePath = tempDir.resolve("candidate.jar");
    final Path downstreamPath = tempDir.resolve("downstream.jar");
    writeJar(
        candidatePath,
        Map.of(
            LIVE, classBytes(LIVE, DELEGATE),
            DELEGATE, classBytes(DELEGATE, ABSENT_OPTIONAL),
            DEAD, classBytes(DEAD, DOWNSTREAM)));
    writeJar(downstreamPath, Map.of(DOWNSTREAM, classBytes(DOWNSTREAM, null)));
    final Artifact candidate = artifact("candidate", candidatePath);
    final Artifact downstream = artifact("downstream", downstreamPath);
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "unresolved");
    project.setArtifacts(new LinkedHashSet<>(List.of(candidate, downstream)));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path trace = tempDir.resolve("trace.lst");
    Files.writeString(trace, LIVE.replace('/', '.') + "\n");
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, "trimJars", true);
    if (passThroughOnUnresolved) {
      AnalyzeMojoTestFieldSupport.set(mojo, "trimPassThroughOnUnresolved", true);
    }
    AnalyzeMojoTestFieldSupport.set(mojo, "reportFile", tempDir.resolve("report.json").toFile());
    final AtomicReference<ElisionAnalysisModel.EffectiveAnalysis> capture = new AtomicReference<>();
    AnalyzeMojoTestFieldSupport.set(
        mojo,
        "predictionService",
        (AnalyzePredictionService)
            (p, options, resolver) -> {
              final MavenElisionService service = new MavenElisionService();
              final ElisionAnalysisModel.PreparedAnalysis prepared = service.prepare(p, options);
              final ElisionAnalysisModel.EffectiveAnalysis effective =
                  ElisionReachabilityEngine.finishAnalysis(prepared);
              capture.set(effective);
              final String fingerprint =
                  MavenElisionGraphBinding.sha256(List.of("test-prediction"));
              return new AnalyzePrediction(
                  MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
                  prepared.resolvedSnapshots(),
                  List.copyOf(effective.effectiveDecision().retainedArtifacts()),
                  List.copyOf(effective.effectiveDecision().elidedArtifacts()),
                  List.of(),
                  ElisionAnalysisModel.evidence(prepared),
                  fingerprint,
                  ResolvedArtifactInventoryFingerprint.fingerprint(prepared.resolvedSnapshots()),
                  effective.operationFingerprint());
            });
    return new Fixture(mojo, capture);
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static void writeJar(final Path path, final Map<String, byte[]> classes)
      throws IOException {
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
  }

  private static Artifact artifact(final String artifactId, final Path path) {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(path.toFile());
    return artifact;
  }

  private static ArtifactCoordinate coordinate(final String artifactId) {
    return new ArtifactCoordinate("org.example", artifactId, "1.0", "jar", "", "runtime");
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

  private record Fixture(
      AnalyzeMojo mojo, AtomicReference<ElisionAnalysisModel.EffectiveAnalysis> analysis) {}
}
