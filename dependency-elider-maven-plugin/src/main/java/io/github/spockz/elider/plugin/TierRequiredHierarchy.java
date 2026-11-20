/* WHY: Checks required unchanged classes against every runtime sharing their archive view. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierRootPlanner.MissingRequiredLinkage;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Shares class-loading requirements among runtimes with the same archive view. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class TierRequiredHierarchy {
  /** Names stay in JVM form for the selected class table. */
  private final Map<String, Set<String>> supertypes;

  /** Avoids decoding a prepared header again for another image of this release. */
  private final Set<String> preparedNames = new HashSet<>();

  TierRequiredHierarchy() {
    supertypes = new HashMap<>();
  }

  void record(final String type, final String supertype) {
    supertypes.computeIfAbsent(type, ignored -> new LinkedHashSet<>()).add(supertype);
  }

  static void addToRelease(
      final Map<Integer, TierRequiredHierarchy> releases,
      final int release,
      final TierRequiredHierarchy hierarchy) {
    releases.merge(release, hierarchy, TierRequiredHierarchy::merge);
  }

  private TierRequiredHierarchy merge(final TierRequiredHierarchy other) {
    other.supertypes.forEach(
        (type, parents) ->
            supertypes.merge(
                type,
                parents,
                (existing, added) -> {
                  existing.addAll(added);
                  return existing;
                }));
    return this;
  }

  // Verification runs serially and adds at most one new hierarchy per release.
  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
  static void verify(
      final TrimRequest request,
      final List<TierContext> views,
      final Set<String> linkageRoots,
      final Map<Integer, TierRequiredHierarchy> releases,
      final TrimAnalysisSession session)
      throws IOException {
    final MavenRuntimePlatforms selected = request.runtimePlatforms();
    if (selected == null) {
      return;
    }
    final List<String> roots = linkageRoots.stream().map(root -> root.replace('.', '/')).toList();
    final Map<Integer, TierRequiredHierarchy> shared = new HashMap<>(releases);
    for (final TierContext view : views) {
      shared
          .computeIfAbsent(view.release(), ignored -> new TierRequiredHierarchy())
          .verifyView(view, roots, request.evidence().projectOutputClasses(), selected, session);
    }
  }

  private void verifyView(
      final TierContext view,
      final List<String> roots,
      final Set<String> projectClasses,
      final MavenRuntimePlatforms selected,
      final TrimAnalysisSession session)
      throws IOException {
    final Set<String> visited = new HashSet<>();
    final Deque<String> pending = new ArrayDeque<>(roots);
    while (!pending.isEmpty()) {
      final String type = pending.removeFirst();
      if (!visited.add(type)) {
        continue;
      }
      for (final String parent : directSupertypes(view, type, session)) {
        final String binaryName = parent.replace('/', '.');
        if (view.jdkClassTable().getClass(parent) == null
            && view.ownerOf(binaryName) == null
            && !projectClasses.contains(binaryName)) {
          throw new MissingRequiredLinkage(
              "Required supertype " + binaryName + " of " + type.replace('/', '.') + " is missing",
              TierRootPlanner.runtimePath(selected, view));
        }
        pending.addLast(parent);
      }
    }
  }

  private Set<String> directSupertypes(
      final TierContext view, final String type, final TrimAnalysisSession session)
      throws IOException {
    if (session != null && preparedNames.add(type)) {
      for (final ElisionAnalysisModel.ArtifactSnapshot owner :
          view.ownersOf(type.replace('/', '.'))) {
        if (view.candidatePrepared().containsKey(owner)
            || view.programPrepared().containsKey(owner)) {
          session
              .directSupertypes(view.pathFor(owner), type)
              .forEach(parent -> record(type, parent));
        }
      }
    }
    return supertypes.getOrDefault(type, Set.of());
  }
}
