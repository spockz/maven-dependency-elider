/* WHY: Binds transcript advisory data to the installed plugin's cache identity. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.scanner.AdvisoryEvidenceReader;
import io.github.spockz.elider.scanner.AdvisoryEvidenceWriter;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.jar.JarFile;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.repository.layout.DefaultRepositoryLayout;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugin.descriptor.PluginDescriptorBuilder;
import org.junit.jupiter.api.Test;

/** Builds the producer-bound transcript fixture. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class TranscriptCachePreparationTest {
  /** System property selecting the producer-free advisory fixture. */
  private static final String INPUT_PROPERTY = "elide.transcriptCacheFixtureInput";

  /** System property selecting the producer-bound cache output. */
  private static final String OUTPUT_PROPERTY = "elide.transcriptCacheFixtureOutput";

  /** System property identifying Maven's local repository. */
  private static final String LOCAL_REPOSITORY_PROPERTY = "elide.transcriptCacheLocalRepository";

  /** System property identifying the installed plugin group. */
  private static final String GROUP_ID_PROPERTY = "elide.transcriptPluginGroupId";

  /** System property identifying the installed plugin artifact. */
  private static final String ARTIFACT_ID_PROPERTY = "elide.transcriptPluginArtifactId";

  /** System property identifying the installed plugin version. */
  private static final String VERSION_PROPERTY = "elide.transcriptPluginVersion";

  /** Core artifact loaded alongside the installed plugin. */
  private static final String CORE_ARTIFACT_ID = "elider-core";

  @Test
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.UnitTestContainsTooManyAsserts"})
  // Independent setup and round-trip checks should report together.
  void writesEnvelopeUsingInstalledPluginArtifactsWhenRequested() throws Exception {
    final String inputSetting = System.getProperty(INPUT_PROPERTY);
    final String outputSetting = System.getProperty(OUTPUT_PROPERTY);
    assumeTrue(
        inputSetting != null || outputSetting != null, "Transcript preparation not requested");
    assertAll(
        "transcript cache preparation requires both fixture paths",
        () -> assertThat(inputSetting).isNotBlank(),
        () -> assertThat(outputSetting).isNotBlank());

    final Path repository = Path.of(requiredProperty(LOCAL_REPOSITORY_PROPERTY));
    final String groupId = requiredProperty(GROUP_ID_PROPERTY);
    final String artifactId = requiredProperty(ARTIFACT_ID_PROPERTY);
    final String version = requiredProperty(VERSION_PROPERTY);
    final Path pluginJar = installedArtifact(repository, groupId, artifactId, version);
    final Path coreJar = installedArtifact(repository, groupId, CORE_ARTIFACT_ID, version);
    final PluginDescriptor descriptor = readDescriptor(pluginJar, coreJar);
    final PluginCacheProducerIdentityResolver.Resolution resolution =
        PluginCacheProducerIdentityResolver.resolve(descriptor);
    final CacheProducerIdentity producer =
        resolution
            .identity()
            .orElseThrow(
                () ->
                    new IOException(
                        resolution
                            .diagnostic()
                            .orElse("Installed plugin cache identity is unavailable")));
    final List<OsvAdvisoryRecord> records = readFixture(Path.of(inputSetting));
    final byte[] encoded = new VulnerabilityCacheEnvelopeWriter().encode(producer, records);
    verifyEnvelope(encoded, producer, records);
    final Path output = Path.of(outputSetting);
    Files.createDirectories(output.toAbsolutePath().getParent());
    Files.write(output, encoded);
  }

  private static Path installedArtifact(
      final Path repository, final String groupId, final String artifactId, final String version)
      throws IOException {
    final Artifact artifact = artifact(groupId, artifactId, version);
    final Path file = repository.resolve(new DefaultRepositoryLayout().pathOf(artifact));
    if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
      throw new IOException("Installed transcript artifact is unavailable: " + artifactId);
    }
    artifact.setFile(file.toFile());
    return file;
  }

  private static PluginDescriptor readDescriptor(final Path pluginJar, final Path coreJar)
      throws IOException {
    try (JarFile jar = new JarFile(pluginJar.toFile())) {
      final java.util.jar.JarEntry entry = jar.getJarEntry("META-INF/maven/plugin.xml");
      if (entry == null) {
        throw new IOException("Installed plugin JAR has no META-INF/maven/plugin.xml");
      }
      try (InputStream input = jar.getInputStream(entry);
          InputStreamReader descriptorXml = new InputStreamReader(input, StandardCharsets.UTF_8)) {
        final PluginDescriptor descriptor = new PluginDescriptorBuilder().build(descriptorXml);
        final Artifact pluginArtifact =
            artifact(descriptor.getGroupId(), descriptor.getArtifactId(), descriptor.getVersion());
        pluginArtifact.setFile(pluginJar.toFile());
        final Artifact coreArtifact =
            artifact(descriptor.getGroupId(), CORE_ARTIFACT_ID, descriptor.getVersion());
        coreArtifact.setFile(coreJar.toFile());
        descriptor.setPluginArtifact(pluginArtifact);
        descriptor.setArtifacts(List.of(coreArtifact));
        return descriptor;
      } catch (final org.codehaus.plexus.configuration.PlexusConfigurationException exception) {
        throw new IOException("Could not parse installed plugin descriptor", exception);
      }
    }
  }

  private static Artifact artifact(
      final String groupId, final String artifactId, final String version) {
    return new DefaultArtifact(
        groupId, artifactId, version, "runtime", "jar", null, new DefaultArtifactHandler("jar"));
  }

  private static List<OsvAdvisoryRecord> readFixture(final Path input) throws IOException {
    try (InputStream stream = Files.newInputStream(input)) {
      return new AdvisoryEvidenceReader().read(stream);
    }
  }

  private static void verifyEnvelope(
      final byte[] encoded,
      final CacheProducerIdentity producer,
      final List<OsvAdvisoryRecord> expectedRecords)
      throws IOException {
    try (ByteArrayInputStream input = new ByteArrayInputStream(encoded)) {
      final io.github.spockz.elider.scanner.VulnerabilityCacheEnvelope decoded =
          new VulnerabilityCacheEnvelopeReader().read(input, producer);
      assertAll(
          "generated transcript envelope is bound to the installed producer",
          () -> assertThat(decoded.producer()).isEqualTo(producer),
          () ->
              assertThat(new AdvisoryEvidenceWriter().encode(decoded.records()))
                  .containsExactly(new AdvisoryEvidenceWriter().encode(expectedRecords)));
    }
  }

  private static String requiredProperty(final String propertyName) {
    final String value = System.getProperty(propertyName);
    return Objects.requireNonNull(value, propertyName + " must be provided by transcript setup");
  }
}
