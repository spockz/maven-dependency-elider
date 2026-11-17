/* WHY: Binds transcript advisory data to the installed plugin's cache identity. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.spockz.elider.advisory.CveListFindingIndexer;
import io.github.spockz.elider.advisory.FindingSource;
import io.github.spockz.elider.advisory.FindingSourceSnapshot;
import io.github.spockz.elider.advisory.GenericFindingCacheEnvelope;
import io.github.spockz.elider.advisory.GenericFindingCacheEnvelopeReader;
import io.github.spockz.elider.advisory.GenericFindingCacheEnvelopeWriter;
import io.github.spockz.elider.advisory.OsvSnapshotIndexer;
import io.github.spockz.elider.advisory.OsvVulnerabilityFindingAdapter;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.GenericFindingReconciler;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
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
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.ExcessiveImports"})
class TranscriptCachePreparationTest {
  /** System property selecting the pinned OSV Maven archive. */
  private static final String INPUT_PROPERTY = "elide.transcriptCacheFixtureInput";

  /** System property selecting the extracted pinned CVE List archive. */
  private static final String CVE_INPUT_PROPERTY = "elide.transcriptCveListDirectory";

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

  /** Stable source timestamp for the generated transcript cache metadata. */
  private static final Instant FIXTURE_TIMESTAMP = Instant.parse("2026-11-05T22:38:17Z");

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
    final Path cveInput = Path.of(requiredProperty(CVE_INPUT_PROPERTY));
    final OsvSnapshotIndexer.PartialIndex osv;
    try (InputStream input = Files.newInputStream(Path.of(inputSetting))) {
      osv = new OsvSnapshotIndexer().indexZipIsolated(input);
    }
    final CveListFindingIndexer.IndexResult cve = new CveListFindingIndexer().index(cveInput);
    assertAll(
        "complete upstream snapshots are indexed",
        () -> assertThat(osv.records()).hasSizeGreaterThan(5_000),
        () -> assertThat(cve.sourceRecordCount()).isGreaterThan(400_000));
    final OsvVulnerabilityFindingAdapter adapter = new OsvVulnerabilityFindingAdapter();
    final List<VulnerabilityFindingContribution> contributions =
        osv.records().stream().flatMap(record -> adapter.contributions(record).stream()).toList();
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            producer,
            java.util.Map.of(
                FindingSource.OSV,
                    new FindingSourceSnapshot(
                        FindingSource.OSV,
                        "83f0acd183479c7199ec8fc47c48a4676ceb9239fb603295ddeda36444081156",
                        FIXTURE_TIMESTAMP,
                        status(osv.skippedCount()),
                        diagnostic("OSV", osv.skippedCount()),
                        contributions,
                        osv.skippedRows()),
                FindingSource.CVE_LIST,
                    new FindingSourceSnapshot(
                        FindingSource.CVE_LIST,
                        "8683d0fedac9baee8b745555aebad828cceaaa90",
                        FIXTURE_TIMESTAMP,
                        status(cve.skippedRows()),
                        diagnostic("CVE List", cve.skippedRows()),
                        cve.contributions(),
                        cve.observationDiagnostics())));
    final byte[] encoded = new GenericFindingCacheEnvelopeWriter().encode(envelope);
    verifyEnvelope(encoded, producer);
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

  private static FindingSourceSnapshot.Status status(final int skippedRows) {
    return skippedRows == 0
        ? FindingSourceSnapshot.Status.CURRENT
        : FindingSourceSnapshot.Status.PARTIAL;
  }

  private static String diagnostic(final String source, final int skippedRows) {
    return skippedRows == 0 ? null : "Skipped " + skippedRows + " " + source + " source row(s)";
  }

  private static void verifyEnvelope(final byte[] encoded, final CacheProducerIdentity producer)
      throws IOException {
    try (ByteArrayInputStream input = new ByteArrayInputStream(encoded)) {
      final GenericFindingCacheEnvelope decoded =
          new GenericFindingCacheEnvelopeReader().read(input, producer);
      final List<GenericVulnerabilityFinding> findings =
          GenericFindingReconciler.reconcile(decoded.contributions()).findings();
      assertAll(
          "generated transcript envelope is bound to the installed producer",
          () -> assertThat(decoded.producer()).isEqualTo(producer),
          () ->
              assertThat(decoded.sources())
                  .containsOnlyKeys(FindingSource.OSV, FindingSource.CVE_LIST),
          () ->
              assertThat(decoded.sources().get(FindingSource.CVE_LIST).contributions())
                  .isNotEmpty(),
          () ->
              assertThat(findings)
                  .extracting(GenericVulnerabilityFinding::vulnerabilityId)
                  .contains("CVE-2024-50379", "CVE-2026-18401", "CVE-2026-77310"));
    }
  }

  private static String requiredProperty(final String propertyName) {
    final String value = System.getProperty(propertyName);
    return Objects.requireNonNull(value, propertyName + " must be provided by transcript setup");
  }
}
