// WHY: Gives configured policy and its operation one report identity.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;
import java.util.Objects;
import org.apache.maven.plugin.MojoFailureException;

/** Canonical policy and producing-operation identity for persisted reports. */
record MavenElisionPolicyIdentity(
    List<String> retainedArtifacts,
    List<String> banishedDependencies,
    String operationFingerprint) {
  MavenElisionPolicyIdentity {
    retainedArtifacts = List.copyOf(Objects.requireNonNull(retainedArtifacts, "retainedArtifacts"));
    banishedDependencies =
        List.copyOf(Objects.requireNonNull(banishedDependencies, "banishedDependencies"));
    Objects.requireNonNull(operationFingerprint, "operationFingerprint");
    if (!operationFingerprint.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("operationFingerprint must be a lowercase SHA-256 value");
    }
    try {
      final List<String> normalizedRetained =
          ElisionArtifactPolicy.parseRetentionCoordinates(retainedArtifacts).stream()
              .map(MavenElisionPolicyIdentity::retentionCoordinate)
              .sorted()
              .toList();
      final List<String> normalizedBanished =
          BanishedDependencyPolicy.normalize(banishedDependencies).stream()
              .map(Object::toString)
              .toList();
      if (!retainedArtifacts.equals(normalizedRetained)
          || !banishedDependencies.equals(normalizedBanished)) {
        throw new IllegalArgumentException("policy coordinates must be canonical and ordered");
      }
    } catch (final MojoFailureException exception) {
      throw new IllegalArgumentException("policy coordinates are invalid", exception);
    }
  }

  /* package */ static Options normalize(final ElisionAnalysisModel.AnalysisOptions options)
      throws MojoFailureException {
    final List<String> retained =
        ElisionArtifactPolicy.parseRetentionCoordinates(options.retainedArtifacts()).stream()
            .map(MavenElisionPolicyIdentity::retentionCoordinate)
            .sorted()
            .toList();
    final List<String> bans =
        BanishedDependencyPolicy.normalize(options.banishedDependencies()).stream()
            .map(Object::toString)
            .toList();
    return new Options(retained, bans);
  }

  /* package */ static String retentionCoordinate(final ArtifactCoordinate coordinate) {
    return String.join(
        ":",
        coordinate.groupId(),
        coordinate.artifactId(),
        coordinate.version() == null ? "" : coordinate.version(),
        coordinate.type(),
        coordinate.classifier());
  }

  /* package */ record Options(List<String> retainedArtifacts, List<String> banishedDependencies) {
    Options {
      retainedArtifacts =
          List.copyOf(Objects.requireNonNull(retainedArtifacts, "retainedArtifacts"));
      banishedDependencies =
          List.copyOf(Objects.requireNonNull(banishedDependencies, "banishedDependencies"));
    }

    /* package */ MavenElisionPolicyIdentity withOperationFingerprint(final String fingerprint) {
      return new MavenElisionPolicyIdentity(retainedArtifacts, banishedDependencies, fingerprint);
    }
  }
}
