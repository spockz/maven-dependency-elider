/* WHY: Proves tolerated duplicate classes flow through direct trimming with the chosen action. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.JarIndexScanner;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies retain and trim handling of one class shipped by two retained JARs. */
final class DuplicateClassDirectTrimTest {
  /** Class shipped by both fixture JARs. */
  private static final String SHARED_CLASS = "dup.Shared";

  /** Entry name of the shared class inside each JAR. */
  private static final String SHARED_ENTRY = "dup/Shared.class";

  /** Temporary workspace for compiled JAR fixtures. */
  @TempDir private Path tempDir;

  /** Creates the duplicate-class direct-trim fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  DuplicateClassDirectTrimTest() {}

  @Test
  @SuppressWarnings("PMD.LawOfDemeter")
  void retainKeepsBothOwnersWholeAndTrimKeepsOnlyTheDuplicateInEach() throws Exception {
    final Fixture fixture = fixture();

    final TrimResult retained =
        fixture.trim(new DuplicateClassPolicy(List.of("dup.**"), List.of()));
    final TrimResult trimmed = fixture.trim(new DuplicateClassPolicy(List.of(), List.of("dup.*")));

    assertAll(
        () ->
            assertThat(retained.configuredPassThroughArtifacts())
                .as("every owner of a retained duplicate is kept whole")
                .containsExactlyInAnyOrder(fixture.one.coordinate(), fixture.two.coordinate()),
        () -> assertThat(retained.records()).isEmpty(),
        () ->
            assertThat(retained.toleratedDuplicates())
                .as("tolerated duplicates are surfaced with the chosen action and owners")
                .singleElement()
                .satisfies(
                    duplicate -> {
                      assertAll(
                          () -> assertThat(duplicate.className()).isEqualTo(SHARED_CLASS),
                          () ->
                              assertThat(duplicate.action())
                                  .isEqualTo(DuplicateClassPolicy.Action.RETAIN_JARS),
                          () ->
                              assertThat(duplicate.owners())
                                  .containsExactlyInAnyOrder(
                                      fixture.one.coordinate(), fixture.two.coordinate()));
                    }),
        () ->
            assertThat(trimmed.toleratedDuplicates())
                .singleElement()
                .extracting(DuplicateClasses.ToleratedDuplicate::action)
                .isEqualTo(DuplicateClassPolicy.Action.TRIM_OTHER_CLASSES),
        () -> assertThat(trimmed.configuredPassThroughArtifacts()).isEmpty(),
        () ->
            assertThat(trimmed.records())
                .extracting(ArtifactTrimRecord::coordinate)
                .containsExactlyInAnyOrder(fixture.one.coordinate(), fixture.two.coordinate()),
        () ->
            assertThat(entries(trimmed, fixture.one))
                .contains(SHARED_ENTRY, "one/Keep.class", "one/Helper.class")
                .doesNotContain("one/Drop.class"),
        () ->
            assertThat(entries(trimmed, fixture.two))
                .contains(SHARED_ENTRY, "two/Keep.class", "two/Helper.class")
                .doesNotContain("two/Drop.class"));
  }

  @Test
  void unmatchedDuplicateStillFailsClosed() throws Exception {
    final Fixture fixture = fixture();

    assertThatThrownBy(() -> fixture.trim(new DuplicateClassPolicy(List.of("other.**"), List.of())))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate class")
        .hasMessageContaining(SHARED_CLASS);
  }

  private static Set<String> entries(final TrimResult result, final Held held) throws IOException {
    final ArtifactTrimRecord record =
        result.records().stream()
            .filter(candidate -> candidate.coordinate().equals(held.coordinate()))
            .findFirst()
            .orElseThrow();
    final Set<String> names = new java.util.TreeSet<>();
    try (JarFile jar = new JarFile(record.trimmedPath().toFile())) {
      jar.stream().forEach(entry -> names.add(entry.getName()));
    }
    return names;
  }

  private Fixture fixture() throws IOException {
    final Held one = held("one");
    final Held two = held("two");
    return new Fixture(one, two);
  }

  private Held held(final String name) throws IOException {
    final Path jar =
        io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
            tempDir.resolve(name + ".jar"),
            tempDir.resolve(name + "-sources"),
            Map.of(
                "dup/Shared.java",
                "package dup; public class Shared { public Object owner() { return new "
                    + name
                    + ".Helper(); } }\n",
                name + "/Helper.java",
                "package " + name + "; public class Helper {}\n",
                name + "/Keep.java",
                "package "
                    + name
                    + "; public class Keep { "
                    + "public Object shared() { return new dup.Shared(); } }\n",
                name + "/Drop.java",
                "package " + name + "; public class Drop {}\n"),
            null);
    final Path normalized = jar.toAbsolutePath().normalize();
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", name, "1.0", "jar", "", "runtime");
    final Artifact artifact =
        new DefaultArtifact(
            "org.example", name, "1.0", "runtime", "jar", null, new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return new Held(
        artifact,
        coordinate,
        new ElisionAnalysisModel.ArtifactSnapshot(artifact, coordinate, normalized));
  }

  /** One generated JAR with its Maven identity. */
  private record Held(
      Artifact artifact,
      ArtifactCoordinate coordinate,
      ElisionAnalysisModel.ArtifactSnapshot snapshot) {}

  /** Two JARs that both ship {@code dup.Shared}. */
  private final class Fixture {
    /** First duplicate owner. */
    private final Held one;

    /** Second duplicate owner. */
    private final Held two;

    private Fixture(final Held one, final Held two) {
      this.one = one;
      this.two = two;
    }

    @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
    private TrimResult trim(final DuplicateClassPolicy duplicates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      final MavenProject project = new MavenProject();
      project.setArtifacts(Set.of(one.artifact(), two.artifact()));
      project.setGroupId("org.example");
      project.setArtifactId("consumer");
      project.setVersion("1.0");
      project.getProperties().setProperty("maven.compiler.release", "21");
      final Build build = new Build();
      build.setDirectory(tempDir.resolve("build").toString());
      project.setBuild(build);
      final List<ArtifactFileRef> refs = new ArrayList<>();
      final Map<Path, DependencyDynamicRoots.RootScan> scans = new HashMap<>();
      for (final Held held : List.of(one, two)) {
        refs.add(ArtifactFileRef.fromPath(held.coordinate(), held.snapshot().filePath()));
        scans.put(held.snapshot().filePath(), new DependencyDynamicRoots.RootScan(Set.of(), true));
      }
      return MavenDependencyTrimmer.trim(
          new TrimRequest(
              project,
              null,
              List.of(one.snapshot(), two.snapshot()),
              new TrimScanInputs(new JarIndexScanner().scan(refs), scans),
              Set.of(one.coordinate(), two.coordinate()),
              new TrimEvidence(
                  TraceData.of(Set.of("one.Keep", "two.Keep")), Set.of(), Set.of(), Set.of()),
              new TrimPolicy(
                  List.of(),
                  false,
                  List.of(),
                  false,
                  MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                  true,
                  true,
                  MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                  duplicates)));
    }
  }
}
