/* WHY: Rejects cache decisions that contradict their artifact inventory. */

package io.github.spockz.elider.cache;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.util.HashSet;
import java.util.Set;

/** Validates artifact and class partitions before a cache result is accepted. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ElisionDecisionValidator {
  private ElisionDecisionValidator() {}

  static void validate(final ElisionDecision decision, final Set<ArtifactCoordinate> inventory) {
    if (decision.elapsedNanos() < 0) {
      throw new IllegalArgumentException("elapsed time must not be negative");
    }
    validateArtifactPartitions(decision, inventory);
    validateClassMaps(decision, inventory);
  }

  private static void validateArtifactPartitions(
      final ElisionDecision decision, final Set<ArtifactCoordinate> inventory) {
    if (!java.util.Collections.disjoint(decision.retainedArtifacts(), decision.elidedArtifacts())) {
      throw new IllegalArgumentException("overlapping artifact partitions");
    }
    final Set<ArtifactCoordinate> union = new HashSet<>(decision.retainedArtifacts());
    union.addAll(decision.elidedArtifacts());
    if (!union.equals(inventory)) {
      throw new IllegalArgumentException("incomplete artifact partition");
    }
  }

  private static void validateClassMaps(
      final ElisionDecision decision, final Set<ArtifactCoordinate> inventory) {
    if (!decision.retainedClassesPerArtifact().keySet().equals(inventory)
        || !decision.unusedClassesPerArtifact().keySet().equals(inventory)) {
      throw new IllegalArgumentException("class maps must cover the complete inventory");
    }
    for (final ArtifactCoordinate coordinate : inventory) {
      final Set<String> used =
          decision.retainedClassesPerArtifact().getOrDefault(coordinate, Set.of());
      final Set<String> unused =
          decision.unusedClassesPerArtifact().getOrDefault(coordinate, Set.of());
      if (!java.util.Collections.disjoint(used, unused)) {
        throw new IllegalArgumentException("used and unused classes overlap");
      }
    }
  }
}
