/* WHY: Resolves cache identity from the installed plugin realm, never the consuming project. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CacheProducerIdentity;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.descriptor.PluginDescriptor;

/** Resolves the exact installed plugin producer for plugin-owned caches. */
public final class PluginCacheProducerIdentityResolver {
  /** Maven group identifying the core artifact in the installed plugin realm. */
  private static final String CORE_GROUP_ID = "io.github.spockz";

  /** Artifact identifier for the core artifact in the installed plugin realm. */
  private static final String CORE_ARTIFACT_ID = "elider-core";

  /** A snapshot identity is safe only with one matching core artifact. */
  private static final int EXPECTED_CORE_ARTIFACT_COUNT = 1;

  /** Private constructor prevents utility instances. */
  private PluginCacheProducerIdentityResolver() {}

  /** Resolves the installed producer or a cache-disable diagnostic. */
  public static Resolution resolve(final PluginDescriptor descriptor) {
    if (descriptor == null) {
      return unavailable("Maven did not inject the installed plugin descriptor");
    }
    final Artifact pluginArtifact = descriptor.getPluginArtifact();
    if (!matchesDescriptor(pluginArtifact, descriptor)) {
      return unavailable("Installed plugin artifact does not match its descriptor GAV");
    }
    final String version = descriptor.getVersion();
    if (version == null || version.isBlank()) {
      return unavailable("Installed plugin descriptor has no version");
    }
    if (version.endsWith("-SNAPSHOT")) {
      return resolveSnapshot(descriptor, pluginArtifact, version);
    }
    return resolveRelease(descriptor, version);
  }

  private static Resolution resolveRelease(
      final PluginDescriptor descriptor, final String version) {
    try {
      return available(
          new CacheProducerIdentity(
              descriptor.getGroupId(), descriptor.getArtifactId(), version, null));
    } catch (final IllegalArgumentException exception) {
      return unavailable("Installed plugin descriptor has invalid GAV: " + exception.getMessage());
    }
  }

  private static Resolution resolveSnapshot(
      final PluginDescriptor descriptor, final Artifact pluginArtifact, final String version) {
    final List<Artifact> installedArtifacts = descriptor.getArtifacts();
    if (installedArtifacts == null) {
      return unavailable("Installed SNAPSHOT plugin descriptor has no artifact list");
    }
    final List<Artifact> coreArtifacts =
        installedArtifacts.stream()
            .filter(
                artifact ->
                    CORE_GROUP_ID.equals(artifact.getGroupId())
                        && CORE_ARTIFACT_ID.equals(artifact.getArtifactId()))
            .toList();
    if (coreArtifacts.size() != EXPECTED_CORE_ARTIFACT_COUNT) {
      return unavailable(
          "Installed plugin realm does not identify exactly one elider-core artifact");
    }
    try {
      final Path pluginJar = readableJar(pluginArtifact, "plugin");
      final Path coreJar = readableJar(coreArtifacts.getFirst(), "elider-core");
      final String buildIdentity = hashPluginAndCore(pluginJar, coreJar);
      return available(
          new CacheProducerIdentity(
              descriptor.getGroupId(), descriptor.getArtifactId(), version, buildIdentity));
    } catch (final IOException | IllegalArgumentException exception) {
      return unavailable(
          "Installed SNAPSHOT plugin bytes are unavailable: " + exception.getMessage());
    }
  }

  private static boolean matchesDescriptor(
      final Artifact artifact, final PluginDescriptor descriptor) {
    return artifact != null
        && Objects.equals(descriptor.getGroupId(), artifact.getGroupId())
        && Objects.equals(descriptor.getArtifactId(), artifact.getArtifactId())
        && Objects.equals(descriptor.getVersion(), artifact.getBaseVersion());
  }

  /** Maven Artifact exposes its resolved local file through this getter. */
  @SuppressWarnings("PMD.LawOfDemeter")
  private static Path readableJar(final Artifact artifact, final String label) throws IOException {
    final File jarFile = artifact.getFile();
    final Path jarPath = jarFile == null ? null : jarFile.toPath();
    if (jarPath == null || !Files.isRegularFile(jarPath) || !Files.isReadable(jarPath)) {
      throw new IOException(label + " JAR is not a readable regular file");
    }
    return jarPath;
  }

  private static String hashPluginAndCore(final Path pluginJar, final Path coreJar)
      throws IOException {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      updateFileDigest(digest, pluginJar);
      updateFileDigest(digest, coreJar);
      return HexFormat.of().formatHex(digest.digest());
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is not available", exception);
    }
  }

  private static void updateFileDigest(final MessageDigest digest, final Path file)
      throws IOException {
    final long size = Files.size(file);
    digest.update(ByteBuffer.allocate(Long.BYTES).putLong(size).array());
    try (InputStream input = Files.newInputStream(file)) {
      final byte[] buffer = new byte[8192];
      while (true) {
        final int read = input.read(buffer);
        if (read == -1) {
          break;
        }
        digest.update(buffer, 0, read);
      }
    }
  }

  private static Resolution available(final CacheProducerIdentity identity) {
    return new Resolution(Optional.of(identity), Optional.empty());
  }

  private static Resolution unavailable(final String diagnostic) {
    return new Resolution(Optional.empty(), Optional.of(diagnostic));
  }

  /** Producer identity or the reason persistent cache use is disabled. */
  public record Resolution(Optional<CacheProducerIdentity> identity, Optional<String> diagnostic) {
    /** Enforces exactly one resolution outcome. */
    public Resolution {
      Objects.requireNonNull(identity, "identity");
      Objects.requireNonNull(diagnostic, "diagnostic");
      if (identity.isPresent() == diagnostic.isPresent()) {
        throw new IllegalArgumentException("Resolution requires either identity or diagnostic");
      }
    }
  }
}
