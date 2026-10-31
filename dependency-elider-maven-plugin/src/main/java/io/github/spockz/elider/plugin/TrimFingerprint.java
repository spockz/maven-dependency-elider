/* WHY: Preserves the cache key's exact canonical input order and platform
 * identities across analysis refactoring. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.CacheProducerIdentity.CompatibilityIdentity;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/** Builds canonical fingerprints from archive and platform identities. */
final class TrimFingerprint {
  /** Serializes the normalized producer as structured fingerprint input. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /* package */
  /** Invalidates keys when the underlying trimming engine changes. */
  static final String ENGINE_VERSION = "proguard-core-9.4.0";

  private TrimFingerprint() {}

  /* package */ record FingerprintSnapshot(
      String value,
      Map<Path, ArtifactDigests> inputDigests,
      List<JdkPlatformContext.PlatformSnapshot> platformSnapshots) {}

  /* package */ record FingerprintOptions(
      int runtimeRelease,
      int release,
      int schemaVersion,
      String engineVersion,
      JdkPlatformContext platformContext,
      List<Integer> analyzedTiers,
      String outputContext,
      Optional<CompatibilityIdentity> producerIdentity) {
    FingerprintOptions {
      Objects.requireNonNull(producerIdentity, "producerIdentity");
    }
  }

  /* package */ static FingerprintSnapshot fingerprint(
      final List<TrimCandidate> candidates,
      final List<Path> allRetainedInputs,
      final Set<String> skippedArtifactIdentities,
      final FingerprintOptions options)
      throws IOException {
    final List<String> candidateIdentities = new ArrayList<>();
    final Set<String> roots = new TreeSet<>();
    for (final TrimCandidate candidate : candidates) {
      candidateIdentities.add(
          candidate.archive().snapshot().coordinate()
              + ":"
              + candidate.archive().snapshot().filePath().toAbsolutePath().normalize());
      roots.addAll(candidate.roots());
    }
    candidateIdentities.addAll(
        skippedArtifactIdentities.stream()
            .sorted()
            .map(identity -> "trim-skip:" + identity)
            .toList());
    if (options.outputContext() != null) {
      candidateIdentities.add("effective-output-context:" + options.outputContext());
    }
    candidateIdentities.add("runtime-release:" + options.runtimeRelease());
    final Set<Integer> tiers = new TreeSet<>(options.analyzedTiers());
    tiers.add(options.release());
    tiers.add(options.runtimeRelease());
    final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots = new ArrayList<>();
    for (final int tier : tiers) {
      platformSnapshots.add(options.platformContext().snapshot(tier));
    }
    platformSnapshots.sort(
        Comparator.comparingInt(JdkPlatformContext.PlatformSnapshot::effectiveRelease));
    final Map<Path, ArtifactDigests> inputDigests =
        TrimInputDigests.inputDigests(allRetainedInputs);
    final String value =
        fingerprintForPlatformSnapshots(
            candidateIdentities,
            allRetainedInputs,
            roots,
            platformSnapshots,
            options.release(),
            options.schemaVersion(),
            options.engineVersion(),
            options.producerIdentity(),
            inputDigests);
    return new FingerprintSnapshot(value, inputDigests, List.copyOf(platformSnapshots));
  }

  /* package */ static String fingerprintForInputs(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<Path> platformInputs,
      final int release,
      final int schemaVersion,
      final String engineVersion)
      throws IOException {
    return fingerprintForInputs(
        candidateIdentities,
        orderedLibraries,
        roots,
        platformInputs,
        release,
        schemaVersion,
        engineVersion,
        Optional.empty(),
        TrimInputDigests.inputDigests(orderedLibraries));
  }

  /* package */ static String fingerprintForInputs(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<Path> platformInputs,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final Optional<CompatibilityIdentity> producerIdentity,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final List<String> platformIdentities = new ArrayList<>(platformInputs.size());
    for (final Path platformInput : platformInputs) {
      platformIdentities.add(
          platformInput.toAbsolutePath().normalize().getFileName()
              + ":"
              + TrimInputDigests.sha256(platformInput));
    }
    return fingerprintForPlatformIdentities(
        candidateIdentities,
        orderedLibraries,
        roots,
        platformIdentities,
        release,
        schemaVersion,
        engineVersion,
        producerIdentity,
        inputDigests);
  }

  private static String fingerprintForPlatformSnapshots(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final Optional<CompatibilityIdentity> producerIdentity,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final List<String> platformIdentities =
        platformSnapshots.stream().map(JdkPlatformContext.PlatformSnapshot::identity).toList();
    return fingerprintForPlatformIdentities(
        candidateIdentities,
        orderedLibraries,
        roots,
        platformIdentities,
        release,
        schemaVersion,
        engineVersion,
        producerIdentity,
        inputDigests);
  }

  private static String fingerprintForPlatformIdentities(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<String> platformIdentities,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final Optional<CompatibilityIdentity> producerIdentity,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final StringBuilder input =
        new StringBuilder(128)
            .append("release=")
            .append(release)
            .append("\nschema=")
            .append(schemaVersion)
            .append("\nengine=")
            .append(engineVersion)
            .append("\nproducer=")
            .append(encodeProducerIdentity(producerIdentity))
            .append('\n');
    for (final String candidateIdentity : candidateIdentities) {
      input.append("candidate=").append(candidateIdentity).append('\n');
    }
    for (final String root : new TreeSet<>(roots)) {
      input.append("root=").append(root).append('\n');
    }
    for (int index = 0; index < orderedLibraries.size(); index++) {
      final Path library = orderedLibraries.get(index);
      input
          .append("library[")
          .append(index)
          .append("]=")
          .append(library.toAbsolutePath().normalize())
          .append(':')
          .append(TrimInputDigests.requiredInputDigest(inputDigests, library).sha256())
          .append('\n');
    }
    for (int index = 0; index < platformIdentities.size(); index++) {
      input
          .append("platform[")
          .append(index)
          .append("]=")
          .append(platformIdentities.get(index))
          .append('\n');
    }
    return TrimInputDigests.hash(
        input.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static String encodeProducerIdentity(
      final Optional<CompatibilityIdentity> producerIdentity) throws IOException {
    try {
      return JSON.writeValueAsString(producerIdentity.orElse(null));
    } catch (final JsonProcessingException exception) {
      throw new IOException("Could not serialize trim cache producer identity", exception);
    }
  }
}
