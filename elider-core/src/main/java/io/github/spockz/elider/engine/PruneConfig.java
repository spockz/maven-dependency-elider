// WHY: Keeps safety overrides explicit and immutable at the core policy boundary so all callers
// apply the same conservative scope and artifact retention rules.

package io.github.spockz.elider.engine;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.Objects;
import java.util.Set;

/**
 * Only compile/runtime are candidates by default.
 *
 * <p>Other scopes may serve build/test paths; explicit overrides always win.
 *
 * @param retainedArtifacts user global retention overrides; scope is ignored
 */
public record PruneConfig(
    Set<String> keepScopes,
    Set<ArtifactCoordinate> keepArtifacts,
    Set<String> eligibleScopes,
    Set<ArtifactCoordinate> retainedArtifacts) {
  /** Default scopes whose artifacts are part of the runtime application. */
  private static final Set<String> DEFAULT_ELIGIBLE_SCOPES = Set.of("compile", "runtime");

  /** Freezes the policy inputs so concurrent caller changes cannot alter a decision. */
  public PruneConfig {
    keepScopes = Set.copyOf(Objects.requireNonNull(keepScopes, "keepScopes must not be null"));
    keepArtifacts =
        Set.copyOf(Objects.requireNonNull(keepArtifacts, "keepArtifacts must not be null"));
    eligibleScopes =
        Set.copyOf(Objects.requireNonNull(eligibleScopes, "eligibleScopes must not be null"));
    retainedArtifacts =
        Set.copyOf(Objects.requireNonNull(retainedArtifacts, "retainedArtifacts must not be null"));
  }

  /** Keeps existing overrides while using an empty global retention list. */
  public PruneConfig(
      final Set<String> keepScopes,
      final Set<ArtifactCoordinate> keepArtifacts,
      final Set<String> eligibleScopes) {
    this(keepScopes, keepArtifacts, eligibleScopes, Set.of());
  }

  /** Uses compile and runtime as the default candidate scopes. */
  public PruneConfig() {
    this(Set.of(), Set.of(), DEFAULT_ELIGIBLE_SCOPES, Set.of());
  }

  /** Creates configuration with retention overrides and default scopes. */
  public PruneConfig(final Set<String> keepScopes, final Set<ArtifactCoordinate> keepArtifacts) {
    this(keepScopes, keepArtifacts, DEFAULT_ELIGIBLE_SCOPES, Set.of());
  }

  /** Tests explicit retention overrides; global retention ignores scope. */
  public boolean keeps(final ArtifactCoordinate coordinate) {
    return keepArtifacts.contains(coordinate)
        || retainedArtifacts.stream()
            .anyMatch(retained -> sameArtifactIdentity(retained, coordinate))
        || keepScopes.contains(coordinate.scope());
  }

  /** Returns whether this artifact's scope is allowed to be considered for elision. */
  public boolean canPrune(final ArtifactCoordinate coordinate) {
    return eligibleScopes.contains(coordinate.scope());
  }

  private static boolean sameArtifactIdentity(
      final ArtifactCoordinate first, final ArtifactCoordinate second) {
    return first.groupId().equals(second.groupId())
        && first.artifactId().equals(second.artifactId())
        && (first.version() == null || Objects.equals(first.version(), second.version()))
        && first.type().equals(second.type())
        && first.classifier().equals(second.classifier());
  }
}
