/* WHY: Ensures duplicate policy applies when another archive requires tier-aware analysis. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Exercises duplicate policy across release projections and dropped owners. */
final class DuplicateClassMultiReleaseTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** The duplicate exists in both ordinary and release-specific views. */
  private static final String DUPLICATE_CLASS = "closure.a.Extra";

  /** Creates this group of tier-policy regressions. */
  /* package */ DuplicateClassMultiReleaseTest() {
    super();
  }

  @Test
  void preservesDuplicateClassesOrWholeOwnersDuringTierAnalysis() throws Exception {
    final Fixture fixture = fixture(true);
    fixture.addVersionedClassToC();
    final Set<ArtifactCoordinate> retained =
        Set.of(fixture.coordinate("a"), fixture.coordinate("b"), fixture.coordinate("c"));
    final TrimAnalysisResult trimmed =
        fixture.analyze(retained, new DuplicateClassPolicy(List.of(), List.of(DUPLICATE_CLASS)));
    final TrimAnalysisResult whole =
        fixture.analyze(retained, new DuplicateClassPolicy(List.of(DUPLICATE_CLASS), List.of()));

    assertAll(
        () ->
            assertThat(trimmed.candidateRoots().get(fixture.coordinate("a")))
                .contains(DUPLICATE_CLASS),
        () ->
            assertThat(trimmed.candidateRoots().get(fixture.coordinate("b")))
                .contains(DUPLICATE_CLASS),
        () ->
            assertThat(whole.candidateAnalyses())
                .doesNotContainKeys(fixture.coordinate("a"), fixture.coordinate("b")),
        () -> assertThat(whole.candidateAnalyses()).containsKey(fixture.coordinate("c")));
  }

  @Test
  void promotesEveryDuplicateProviderInEveryTier() throws Exception {
    final Fixture fixture = fixture(true);
    fixture.addVersionedClassToC();
    final TrimAnalysisResult result =
        fixture.analyzeDuplicateRoot(
            Set.of(fixture.coordinate("b"), fixture.coordinate("c")),
            new DuplicateClassPolicy(List.of(DUPLICATE_CLASS), List.of()));

    assertThat(result.reachableArtifacts()).contains(fixture.coordinate("a"));
  }

  @Test
  void ignoresDuplicateEntriesUnavailableInTheAnalyzedReleases() throws Exception {
    final Fixture fixture = fixture(true);
    final Path original = fixture.snapshot("b").filePath();
    final int future = Runtime.version().feature() + 1;
    final DuplicateClassPolicy policy =
        new DuplicateClassPolicy(List.of(DUPLICATE_CLASS), List.of());
    final OwnerEntries entries = readOwner(original);
    writeVersionedOwner(original, entries.duplicate(), entries.middle(), future, true);
    final List<DuplicateClasses.ToleratedDuplicate> futureDuplicates =
        DuplicateClasses.resolve(policy, fixture.allSnapshots(), Runtime.version().feature());
    writeVersionedOwner(original, entries.duplicate(), entries.middle(), 9, false);
    final List<DuplicateClasses.ToleratedDuplicate> inactiveDuplicates =
        DuplicateClasses.resolve(policy, fixture.allSnapshots(), Runtime.version().feature());
    writeVersionedOwner(original, entries.duplicate(), entries.middle(), 9, true);
    final List<DuplicateClasses.ToleratedDuplicate> activeDuplicates =
        DuplicateClasses.resolve(policy, fixture.allSnapshots(), Runtime.version().feature());
    assertAll(
        () ->
            assertThat(futureDuplicates)
                .as("a class only available above the runtime is not an effective duplicate")
                .isEmpty(),
        () ->
            assertThat(inactiveDuplicates)
                .as("versioned entries require the Multi-Release manifest attribute")
                .isEmpty(),
        () ->
            assertThat(activeDuplicates)
                .singleElement()
                .satisfies(
                    row ->
                        assertThat(row.owners())
                            .containsExactlyInAnyOrder(
                                fixture.coordinate("a"), fixture.coordinate("b"))));
  }

  @Test
  void duplicateIntroducedAtAnUpperTierKeepsTheOtherOwnersTargetClass() throws Exception {
    final Fixture fixture = fixture(true, false, false, false, 9);
    final Path original = fixture.snapshot("b").filePath();
    final OwnerEntries entries = readOwner(original);
    final ClassWriter writer = new ClassWriter(0);
    new ClassReader(entries.duplicate())
        .accept(
            new ClassVisitor(Opcodes.ASM9, writer) {
              @Override
              public void visit(
                  final int version,
                  final int access,
                  final String name,
                  final String signature,
                  final String superName,
                  final String[] interfaces) {
                super.visit(
                    version, access & ~Opcodes.ACC_PUBLIC, name, signature, superName, interfaces);
              }
            },
            0);
    writeVersionedOwner(original, writer.toByteArray(), entries.middle(), 21, true);
    final TrimAnalysisResult result =
        fixture.analyze(
            Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            new DuplicateClassPolicy(List.of(), List.of(DUPLICATE_CLASS)));
    assertAll(
        () ->
            assertThat(result.candidateRoots().get(fixture.coordinate("a")))
                .contains(DUPLICATE_CLASS),
        () ->
            assertThat(result.candidateAnalyses().get(fixture.coordinate("a")).retainedClasses())
                .contains("closure/a/Extra"));
  }

  /** Class payloads remain isolated from later archive rewrites. */
  private record OwnerEntries(byte[] duplicate, byte[] middle) {}

  private static OwnerEntries readOwner(final Path source) throws IOException {
    try (JarFile input = new JarFile(source.toFile());
        InputStream duplicate = input.getInputStream(input.getJarEntry("closure/a/Extra.class"));
        InputStream middle = input.getInputStream(input.getJarEntry("closure/b/Middle.class"))) {
      return new OwnerEntries(duplicate.readAllBytes(), middle.readAllBytes());
    }
  }

  private static void writeVersionedOwner(
      final Path target,
      final byte[] duplicate,
      final byte[] middle,
      final int release,
      final boolean multiRelease)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", Boolean.toString(multiRelease));
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(target), manifest)) {
      output.putNextEntry(new JarEntry("closure/b/Middle.class"));
      output.write(middle);
      output.closeEntry();
      output.putNextEntry(new JarEntry("META-INF/versions/" + release + "/closure/a/Extra.class"));
      output.write(duplicate);
      output.closeEntry();
    }
  }
}
