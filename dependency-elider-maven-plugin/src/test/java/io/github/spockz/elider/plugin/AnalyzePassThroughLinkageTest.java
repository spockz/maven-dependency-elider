/* WHY: Exercises unresolved optional links and sibling closure through the Analyze goal. */

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
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Checks unchanged owner linkage and transformed sibling verification. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class AnalyzePassThroughLinkageTest {
  private static final String OWNER =
      "org/springframework/kafka/streams/KafkaStreamsMicrometerListener";
  private static final String MISSING = "org/apache/kafka/streams/KafkaStreams";
  private static final String LINKED = "sibling/Linked";
  private static final String DUPLICATE = "org/json/JSONObject";
  @TempDir private Path tempDir;

  @Test
  @SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.LawOfDemeter"})
  void unchangedOwnerToleratesMissingTypeAndRetainsResolvedSibling() throws Exception {
    final Fixture fixture = fixture(false);
    final byte[] original = Files.readAllBytes(fixture.owner().getFile().toPath());
    fixture.mojo().execute();
    final TrimAnalysisResult trim = fixture.analysis().get().trimAnalysis();
    final ArtifactCoordinate sibling =
        new ArtifactCoordinate("org.example", "sibling", "1.0", "jar", "", "runtime");
    final ArtifactCoordinate owner =
        new ArtifactCoordinate("org.example", "owner", "1.0", "jar", "", "runtime");
    assertAll(
        () -> assertThat(trim.candidateAnalyses()).doesNotContainKey(owner),
        () -> {
          assertThat(trim.candidateAnalyses()).containsKey(sibling);
          assertThat(trim.candidateAnalyses().get(sibling).retainedClasses())
              .contains(LINKED, DUPLICATE)
              .doesNotContain("sibling/Drop");
        },
        () -> {
          try (JarFile jar = new JarFile(fixture.owner().getFile())) {
            assertThat(jar.getEntry(DUPLICATE + ".class")).isNotNull();
          }
        },
        () ->
            assertThat(fixture.owner().getFile().toPath()).isEqualTo(tempDir.resolve("owner.jar")),
        () ->
            assertThat(Files.readAllBytes(fixture.owner().getFile().toPath())).isEqualTo(original));
  }

  @Test
  void transformedSiblingWithMissingReferenceFailsEvenFromUnchangedOwner() throws Exception {
    final Fixture fixture = fixture(true);
    fixture.mojo().execute();
    final TrimAnalysisResult trim = fixture.analysis().get().trimAnalysis();
    final ArtifactCoordinate sibling =
        new ArtifactCoordinate("org.example", "sibling", "1.0", "jar", "", "runtime");
    assertThat(trim.candidateAnalyses().get(sibling).retainedClasses())
        .contains(LINKED, DUPLICATE)
        .doesNotContain("sibling/Drop");
  }

  private Fixture fixture(final boolean brokenSibling)
      throws IOException, ReflectiveOperationException {
    final Path ownerPath = tempDir.resolve("owner.jar");
    final Path siblingPath = tempDir.resolve("sibling.jar");
    writeJar(
        ownerPath,
        Map.of(
            OWNER, classBytes(OWNER, List.of(MISSING, LINKED)),
            DUPLICATE, classBytes(DUPLICATE, List.of())));
    writeJar(
        siblingPath,
        Map.of(
            LINKED,
            classBytes(LINKED, brokenSibling ? List.of("missing/SiblingDependency") : List.of()),
            "sibling/Entry",
            classBytes("sibling/Entry", List.of()),
            DUPLICATE,
            classBytes(DUPLICATE, List.of()),
            "sibling/Drop",
            classBytes("sibling/Drop", List.of())));
    final Artifact owner = artifact("owner", ownerPath);
    final Artifact sibling = artifact("sibling", siblingPath);
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "pass-through");
    project.setArtifacts(new LinkedHashSet<>(List.of(owner, sibling)));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path trace = tempDir.resolve("trace.lst");
    Files.writeString(trace, OWNER.replace('/', '.') + "\nsibling.Entry\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(
        mojo, "trimSkipArtifacts", List.of("org.example:owner:1.0:jar:"));
    AnalyzeMojoTestFieldSupport.set(mojo, "trimDuplicateClassOwners", List.of("org.json.*"));
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
    return new Fixture(mojo, owner, capture);
  }

  private static Artifact artifact(final String name, final Path path) {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example", name, "1.0", "runtime", "jar", null, new DefaultArtifactHandler("jar"));
    artifact.setFile(path.toFile());
    return artifact;
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static void writeJar(final Path path, final Map<String, byte[]> classes)
      throws IOException {
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new ZipEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
  }

  private static byte[] classBytes(final String name, final List<String> references) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    if (references.contains("missing/SiblingDependency")) {
      writer
          .visitField(Opcodes.ACC_PUBLIC, "dependency", "Lmissing/SiblingDependency;", null, null)
          .visitEnd();
    }
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "use", "()V", null, null);
    method.visitCode();
    for (final String reference : references) {
      method.visitTypeInsn(Opcodes.NEW, reference);
      method.visitInsn(Opcodes.POP);
    }
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record Fixture(
      AnalyzeMojo mojo,
      Artifact owner,
      AtomicReference<ElisionAnalysisModel.EffectiveAnalysis> analysis) {}
}
