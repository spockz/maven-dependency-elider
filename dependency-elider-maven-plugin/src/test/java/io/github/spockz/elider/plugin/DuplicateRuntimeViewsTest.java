/* WHY: Verifies that tolerated duplicate declarations follow supplied MRJAR release views. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired"})
final class DuplicateRuntimeViewsTest {
  @Test
  void reportsOnlyDuplicateClassesThatOccurInSelectedViews(@TempDir final Path directory)
      throws IOException {
    final int selectedRelease = Runtime.version().feature();
    final int futureRelease = selectedRelease + 1;
    final List<ElisionAnalysisModel.ArtifactSnapshot> jars =
        List.of(jar(directory, "first", futureRelease), jar(directory, "second", futureRelease));
    final MavenProject project = new MavenProject();
    project.getProperties().setProperty("maven.compiler.release", Integer.toString(futureRelease));
    final MavenRuntimePlatforms selected =
        MavenRuntimePlatforms.inspect(directory, List.of(System.getProperty("java.home")), null);
    final DuplicateClassPolicy policy =
        new DuplicateClassPolicy(List.of("fixture.Future", "fixture.Present"), List.of());
    final TrimRequest request =
        new TrimRequest(
            project,
            null,
            null,
            jars,
            new TrimScanInputs(null, Map.of()),
            Set.of(),
            new TrimEvidence(null, Set.of(), Set.of(), Set.of()),
            new TrimPolicy(
                List.of(), false, List.of(), false, "vertical-shading", false, true, 1, policy),
            Optional.empty(),
            selected);
    final List<DuplicateClasses.ToleratedDuplicate> duplicates =
        DuplicateClasses.resolve(request, jars);
    assertAll(
        () ->
            assertThat(duplicates)
                .extracting(DuplicateClasses.ToleratedDuplicate::className)
                .containsExactly("fixture.Present"),
        () ->
            assertThat(duplicates.getFirst().owners())
                .containsExactlyInAnyOrder(
                    jars.getFirst().coordinate(), jars.getLast().coordinate()));
  }

  private static ElisionAnalysisModel.ArtifactSnapshot jar(
      final Path directory, final String name, final int futureRelease) throws IOException {
    final Path jar = directory.resolve(name + ".jar");
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(Attributes.Name.MULTI_RELEASE, "true");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
      output.putNextEntry(new JarEntry("fixture/Present.class"));
      output.write(1);
      output.closeEntry();
      output.putNextEntry(
          new JarEntry("META-INF/versions/" + futureRelease + "/fixture/Future.class"));
      output.write(1);
      output.closeEntry();
    }
    return new ElisionAnalysisModel.ArtifactSnapshot(
        null, ArtifactCoordinate.of("fixture", name, "1"), jar);
  }
}
