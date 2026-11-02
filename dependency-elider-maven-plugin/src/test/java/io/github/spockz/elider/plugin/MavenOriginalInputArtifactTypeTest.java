// WHY: Prevents Resolver jar extensions and missing scope evidence from masquerading as supported
// Maven artifacts.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.Dependency;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises type evidence at the Resolver-to-policy boundary. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired"
})
final class MavenOriginalInputArtifactTypeTest {
  private static final String PROVIDER = "provider";
  private static final String JAR = "jar";
  @TempDir Path directory;

  @Test
  void separatesMavenTypeFromGraphExtensionAndIncludesItInPolicy() throws Exception {
    final Path jar = directory.resolve("provider.jar");
    Files.writeString(jar, PROVIDER);
    final DefaultArtifact plain = new DefaultArtifact("example", PROVIDER, "", JAR, "1");
    final Artifact testJar = plain.setProperties(Map.of("type", "test-jar")).setFile(jar.toFile());
    final List<MavenOriginalInputAudit.AuditArtifact> artifacts =
        MavenOriginalInputArtifacts.resolved(
            List.of(
                new Dependency(plain.setFile(jar.toFile()), "compile"),
                new Dependency(testJar, "runtime")));

    assertAll(
        () ->
            assertThat(artifacts).extracting(value -> value.coordinate().type()).containsOnly(JAR),
        () ->
            assertThat(artifacts)
                .extracting(MavenOriginalInputAudit.AuditArtifact::mavenType)
                .containsExactly(JAR, "test-jar"),
        () ->
            assertThatThrownBy(
                    () ->
                        BanishedDependencyOriginalAuditPolicy.resolve(
                            List.of("example:provider"), artifacts))
                .hasMessageContaining("unsupported resolved artifact")
                .hasMessageContaining("Maven type: test-jar"));
  }

  @Test
  void rejectsMissingScopeAndExplicitlyBlankTypeInsteadOfApplyingCoordinateDefaults()
      throws IOException {
    final Path jar = directory.resolve("incomplete.jar");
    Files.writeString(jar, PROVIDER);
    final Artifact artifact =
        new DefaultArtifact("example", PROVIDER, "", JAR, "1").setFile(jar.toFile());
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        MavenOriginalInputArtifacts.resolved(List.of(new Dependency(artifact, ""))))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("no effective Maven scope"),
        () ->
            assertThatThrownBy(
                    () ->
                        MavenOriginalInputArtifacts.resolved(
                            List.of(
                                new Dependency(
                                    artifact.setProperties(Map.of("type", "")), "compile"))))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("no Maven artifact type"));
  }
}
