/* WHY: Verifies duplicate variants keep closure and transformed owners remain strict. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Exercises both pass-through orderings for the same duplicate class. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class DuplicatePassThroughOwnershipTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  private static final String DUPLICATE = "closure.a.Extra";
  private static final String ENTRY = "closure/a/Extra.class";
  private static final DuplicateClassPolicy POLICY =
      new DuplicateClassPolicy(List.of(), List.of(DUPLICATE));

  @ParameterizedTest
  @ValueSource(strings = {"a", "b"})
  void eachVariantRetainsItsOwnSiblingClosure(final String unchanged) throws Exception {
    final Fixture fixture = fixtureWithDistinctDuplicateDependencies();
    final Set<ArtifactCoordinate> retained = all(fixture);
    final TrimAnalysisResult result =
        fixture.analyzeDuplicateRoot(retained, POLICY, List.of("fixture:" + unchanged + ":1.0"));
    final String transformed = "a".equals(unchanged) ? "b" : "a";
    assertAll(
        () ->
            assertThat(result.candidateAnalyses()).doesNotContainKey(fixture.coordinate(unchanged)),
        () ->
            assertThat(
                    result
                        .candidateAnalyses()
                        .get(fixture.coordinate(transformed))
                        .retainedClasses())
                .contains("closure/a/Extra"),
        () ->
            assertThat(result.candidateAnalyses().get(fixture.coordinate("c")).retainedClasses())
                .contains("closure/c/Leaf"),
        () ->
            assertThat(result.candidateAnalyses().get(fixture.coordinate("e")).retainedClasses())
                .contains("closure/e/Leaf"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"a", "b"})
  void transformedDuplicateWithMissingLinkFails(final String unchanged) throws Exception {
    final Fixture fixture = fixtureWithDistinctDuplicateDependencies();
    final String transformed = "a".equals(unchanged) ? "b" : "a";
    replaceDuplicate(fixture.snapshot(transformed).filePath());
    assertThatThrownBy(
            () ->
                fixture.analyzeDuplicateRoot(
                    all(fixture), POLICY, List.of("fixture:" + unchanged + ":1.0")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("closure/a/Extra -> class missing/Required");
  }

  @ParameterizedTest
  @ValueSource(strings = {"a", "b"})
  void transformedDuplicateRemainsStrictWhenOtherOwnerIsDropped(final String dropped)
      throws Exception {
    final Fixture fixture = fixtureWithDistinctDuplicateDependencies();
    assertTransformedDuplicateRemainsStrict(fixture, dropped);
  }

  @ParameterizedTest
  @ValueSource(strings = {"a", "b"})
  void transformedDuplicateRemainsStrictDuringTierAnalysis(final String dropped) throws Exception {
    final Fixture fixture = fixtureWithDistinctDuplicateDependencies();
    fixture.addVersionedClassToC();
    assertTransformedDuplicateRemainsStrict(fixture, dropped);
  }

  private void assertTransformedDuplicateRemainsStrict(final Fixture fixture, final String dropped)
      throws IOException {
    final String transformed = "a".equals(dropped) ? "b" : "a";
    replaceDuplicate(fixture.snapshot(transformed).filePath());
    final Set<ArtifactCoordinate> retained = new java.util.LinkedHashSet<>(all(fixture));
    retained.remove(fixture.coordinate(dropped));
    assertThatThrownBy(() -> fixture.analyzeDuplicateRoot(retained, POLICY))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("closure/a/Extra -> class missing/Required");
  }

  private static Set<ArtifactCoordinate> all(final Fixture fixture) {
    return fixture.allSnapshots().stream()
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toSet());
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private void replaceDuplicate(final Path path) throws IOException {
    final Path outputPath = temporaryDirectory.resolve("replaced.jar");
    try (JarFile input = new JarFile(path.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(outputPath))) {
      final java.util.Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        output.putNextEntry(new JarEntry(entry.getName()));
        if (ENTRY.equals(entry.getName())) {
          final ClassWriter writer = new ClassWriter(0);
          writer.visit(
              Opcodes.V21, Opcodes.ACC_PUBLIC, "closure/a/Extra", null, "java/lang/Object", null);
          writer
              .visitField(Opcodes.ACC_PUBLIC, "missing", "Lmissing/Required;", null, null)
              .visitEnd();
          writer.visitEnd();
          output.write(writer.toByteArray());
        } else {
          try (InputStream content = input.getInputStream(entry)) {
            content.transferTo(output);
          }
        }
        output.closeEntry();
      }
    }
    Files.move(outputPath, path, StandardCopyOption.REPLACE_EXISTING);
  }
}
