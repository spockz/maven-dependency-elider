// WHY: Validates original resolved matches before collection exclusions can hide unsupported types
// or scopes.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;

/** Keeps original-audit matches distinct from successful removal outcomes. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class BanishedDependencyOriginalAuditPolicy {
  private BanishedDependencyOriginalAuditPolicy() {}

  static Resolution resolve(
      final List<String> configured,
      final List<MavenOriginalInputAudit.AuditArtifact> originalArtifacts)
      throws MojoFailureException {
    final List<Match> matches = new ArrayList<>();
    for (final BanishedDependency request : BanishedDependencyPolicy.normalize(configured)) {
      final List<MavenOriginalInputAudit.AuditArtifact> artifacts =
          originalArtifacts.stream()
              .filter(
                  artifact ->
                      request.groupId().equals(artifact.coordinate().groupId())
                          && request.artifactId().equals(artifact.coordinate().artifactId()))
              .toList();
      for (final MavenOriginalInputAudit.AuditArtifact artifact : artifacts) {
        BanishedDependencyPolicy.validateSupportedMatch(
            request, artifact.coordinate(), artifact.mavenType(), artifact.filePath() != null);
      }
      matches.add(new Match(request, artifacts));
    }
    return new Resolution(matches);
  }

  record Resolution(List<Match> matches) {
    Resolution {
      matches = List.copyOf(matches);
    }

    List<BanishedDependency> unmatched() {
      return matches.stream()
          .filter(match -> match.artifacts().isEmpty())
          .map(Match::dependency)
          .toList();
    }
  }

  record Match(
      BanishedDependency dependency, List<MavenOriginalInputAudit.AuditArtifact> artifacts) {
    Match {
      artifacts = List.copyOf(artifacts);
    }
  }
}
