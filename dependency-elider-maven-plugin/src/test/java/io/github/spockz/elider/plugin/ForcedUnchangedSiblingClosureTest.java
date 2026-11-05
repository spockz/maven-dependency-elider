/* WHY: Protects sibling closure when graph policy retains an unchanged artifact. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Exercises graph-forced unchanged artifacts in sibling traversal. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class ForcedUnchangedSiblingClosureTest {
  private static final String FIRST = "first/Root";
  private static final String OWNER = "unchanged/OptionalOwner";
  private static final String LINKED = "candidate/Linked";
  @TempDir private Path tempDir;

  @Test
  void forcedUnchangedSiblingToleratesOptionalLinkAndRetainsResolvedClosure() throws Exception {
    final Fixture fixture = fixture(false, true);
    final TrimAnalysisResult result = fixture.analyze();
    assertAll(
        () -> assertThat(result.candidateAnalyses()).doesNotContainKey(fixture.unchanged()),
        () -> {
          assertThat(result.candidateAnalyses()).containsKey(fixture.candidate());
          assertThat(result.candidateAnalyses().get(fixture.candidate()).retainedClasses())
              .contains(LINKED)
              .doesNotContain("candidate/Drop");
        });
  }

  @Test
  void transformedSiblingStillFailsForItsMissingReference() throws Exception {
    final Fixture fixture = fixture(true, true);
    assertThatThrownBy(fixture::analyze)
        .isInstanceOf(IOException.class)
        .hasMessageContaining("candidate/Linked -> class missing/RequiredType");
  }

  @Test
  void transformedSiblingStillFailsDuringTierAnalysis() throws Exception {
    final Fixture fixture = fixture(true, true, true);
    assertThatThrownBy(fixture::analyze)
        .isInstanceOf(IOException.class)
        .hasMessageContaining("candidate/Linked -> class missing/RequiredType");
  }

  @Test
  void reachedDroppedSiblingCanBePromotedWithoutLosingItsResolvedClosure() throws Exception {
    assertAll(
        () -> assertReachedDroppedSibling(fixture(false, false)),
        () -> assertPromotedClosure(fixture(false, true)));
  }

  @Test
  void reachedDroppedSiblingCanBePromotedDuringTierAnalysis() throws Exception {
    assertAll(
        () -> assertReachedDroppedSibling(fixture(false, false, true)),
        () -> assertPromotedClosure(fixture(false, true, true)));
  }

  private static void assertReachedDroppedSibling(final Fixture fixture)
      throws IOException, MojoFailureException {
    final TrimAnalysisResult result = fixture.analyze();
    assertThat(result.reachableArtifacts()).contains(fixture.unchanged());
  }

  private static void assertPromotedClosure(final Fixture fixture)
      throws IOException, MojoFailureException {
    final TrimAnalysisResult result = fixture.analyze();
    assertThat(result.candidateAnalyses().get(fixture.candidate()).retainedClasses())
        .contains(LINKED)
        .doesNotContain("candidate/Drop");
  }

  private Fixture fixture(final boolean brokenCandidate, final boolean retainUnchanged)
      throws IOException {
    return fixture(brokenCandidate, retainUnchanged, false);
  }

  private Fixture fixture(
      final boolean brokenCandidate, final boolean retainUnchanged, final boolean tiered)
      throws IOException {
    final Artifact first = artifact("first", Map.of(FIRST, classBytes(FIRST, null, OWNER)));
    final Artifact unchanged =
        artifact("unchanged", Map.of(OWNER, classBytes(OWNER, "missing/OptionalType", LINKED)));
    final Artifact candidate =
        artifact(
            "candidate",
            Map.of(
                LINKED,
                classBytes(LINKED, brokenCandidate ? "missing/RequiredType" : null, null),
                "candidate/Entry",
                classBytes("candidate/Entry", null, null),
                "candidate/Drop",
                classBytes("candidate/Drop", null, null)),
            tiered);
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        MavenArtifactInventory.snapshots(List.of(first, unchanged, candidate));
    final MavenProject project = new MavenProject();
    project.setGroupId("example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setArtifacts(Set.of(first, unchanged, candidate));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("target").toString());
    project.setBuild(build);
    final List<ArtifactFileRef> refs = new java.util.ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : snapshots) {
      refs.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
    }
    final Map<Path, DependencyDynamicRoots.RootScan> scans =
        snapshots.stream()
            .collect(
                java.util.stream.Collectors.toMap(
                    ElisionAnalysisModel.ArtifactSnapshot::filePath,
                    snapshot -> new DependencyDynamicRoots.RootScan(Set.of(), true)));
    final Set<ArtifactCoordinate> retained =
        snapshots.stream()
            .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
            .filter(coordinate -> retainUnchanged || !coordinate.equals(coordinate("unchanged")))
            .collect(java.util.stream.Collectors.toSet());
    final TrimRequest request =
        new TrimRequest(
            project,
            null,
            snapshots,
            new TrimScanInputs(new JarIndexScanner().scan(refs), scans),
            retained,
            new TrimEvidence(TraceData.of(Set.of("candidate.Entry")), Set.of(), Set.of(), Set.of()),
            new TrimPolicy(
                List.of(),
                false,
                List.of("example:first:1.0:jar:"),
                false,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                true,
                true,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                DuplicateClassPolicy.NONE));
    return new Fixture(request, coordinate("unchanged"), coordinate("candidate"), retainUnchanged);
  }

  private Artifact artifact(final String name, final Map<String, byte[]> classes)
      throws IOException {
    return artifact(name, classes, false);
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Artifact artifact(
      final String name, final Map<String, byte[]> classes, final boolean tiered)
      throws IOException {
    final Path path = tempDir.resolve(name + ".jar");
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    if (tiered) {
      manifest.getMainAttributes().putValue("Multi-Release", "true");
    }
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
      if (tiered) {
        output.putNextEntry(new JarEntry("META-INF/versions/21/" + LINKED + ".class"));
        output.write(classes.get(LINKED));
        output.closeEntry();
      }
    }
    final Artifact artifact =
        new DefaultArtifact(
            "example", name, "1.0", "runtime", "jar", null, new DefaultArtifactHandler("jar"));
    artifact.setFile(path.toFile());
    return artifact;
  }

  private static ArtifactCoordinate coordinate(final String name) {
    return new ArtifactCoordinate("example", name, "1.0", "jar", "", "runtime");
  }

  private static byte[] classBytes(
      final String name, final String fieldType, final String reference) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    if (fieldType != null) {
      writer
          .visitField(Opcodes.ACC_PUBLIC, "dependency", "L" + fieldType + ";", null, null)
          .visitEnd();
    }
    if (reference != null) {
      final MethodVisitor method =
          writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "use", "()V", null, null);
      method.visitCode();
      method.visitTypeInsn(Opcodes.NEW, reference);
      method.visitInsn(Opcodes.POP);
      method.visitInsn(Opcodes.RETURN);
      method.visitMaxs(1, 0);
      method.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record Fixture(
      TrimRequest request,
      ArtifactCoordinate unchanged,
      ArtifactCoordinate candidate,
      boolean retainUnchanged) {
    /* package */ TrimAnalysisResult analyze() throws IOException, MojoFailureException {
      return MavenDependencyTrimmer.analyzeInMemory(
          request, Map.of(), retainUnchanged ? Set.of(unchanged) : Set.of());
    }
  }
}
