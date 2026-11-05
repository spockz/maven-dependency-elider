/* WHY: Resolves aliases once before component-scoped merging without joining ambiguous CVEs. */

package io.github.spockz.elider.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Reconciles the complete original contribution set before candidate assessment. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.UseConcurrentHashMap"})
public final class GenericFindingReconciler {
  private static final int MAX_UNAMBIGUOUS_CVES = 1;

  private GenericFindingReconciler() {}

  /** Groups exact components while retaining ambiguous identities. */
  // Each identity group and component key needs its own mutable collection.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  public static Result reconcile(final List<VulnerabilityFindingContribution> contributions) {
    Objects.requireNonNull(contributions, "contributions");
    final AliasIndex index = new AliasIndex();
    for (final VulnerabilityFindingContribution contribution : contributions) {
      Objects.requireNonNull(contribution, "contribution");
      index.add(contribution.vulnerabilityId());
      for (final String alias : contribution.aliases()) {
        index.join(contribution.vulnerabilityId(), alias);
      }
    }
    final Map<String, Set<String>> identities = index.identities();
    final Map<FindingKey, List<VulnerabilityFindingContribution>> groups = new HashMap<>();
    final Set<String> diagnostics = new TreeSet<>();
    for (final VulnerabilityFindingContribution contribution : contributions) {
      final Set<String> aliases = identities.get(index.root(contribution.vulnerabilityId()));
      final List<String> cves =
          aliases.stream().filter(GenericVulnerabilityFinding::isCveIdentifier).toList();
      final String canonical;
      if (cves.size() > MAX_UNAMBIGUOUS_CVES) {
        canonical = contribution.vulnerabilityId();
        diagnostics.add("Ambiguous vulnerability aliases: " + String.join(", ", aliases));
      } else {
        canonical = cves.isEmpty() ? aliases.iterator().next() : cves.getFirst();
      }
      final FindingKey key =
          new FindingKey(
              canonical,
              contribution.groupId(),
              contribution.artifactId(),
              contribution.type(),
              contribution.classifier());
      groups.computeIfAbsent(key, ignored -> new ArrayList<>()).add(contribution);
    }
    final List<GenericVulnerabilityFinding> findings =
        groups.entrySet().stream()
            .sorted(
                Map.Entry.comparingByKey(
                    Comparator.comparing(FindingKey::vulnerabilityId)
                        .thenComparing(FindingKey::groupId)
                        .thenComparing(FindingKey::artifactId)
                        .thenComparing(FindingKey::type)
                        .thenComparing(FindingKey::classifier)))
            .map(
                entry -> {
                  final VulnerabilityFindingContribution original = entry.getValue().getFirst();
                  return GenericVulnerabilityFinding.mergeResolvedIdentity(
                      entry.getKey().vulnerabilityId(),
                      identities.get(index.root(original.vulnerabilityId())),
                      entry.getValue());
                })
            .toList();
    return new Result(findings, List.copyOf(diagnostics));
  }

  /** Immutable common findings and identity diagnostics. */
  public record Result(List<GenericVulnerabilityFinding> findings, List<String> diagnostics) {
    /** Freezes findings and diagnostics for assessment and reporting. */
    public Result {
      findings = List.copyOf(findings);
      diagnostics = List.copyOf(diagnostics);
    }
  }

  private record FindingKey(
      String vulnerabilityId, String groupId, String artifactId, String type, String classifier) {}

  private static final class AliasIndex {
    private final Map<String, String> parents = new HashMap<>();

    private void add(final String identity) {
      parents.putIfAbsent(identity, identity);
    }

    private void join(final String first, final String second) {
      add(first);
      add(second);
      final String firstRoot = root(first);
      final String secondRoot = root(second);
      if (firstRoot.compareTo(secondRoot) < 0) {
        parents.put(secondRoot, firstRoot);
      } else {
        parents.put(firstRoot, secondRoot);
      }
    }

    private String root(final String identity) {
      String result = identity;
      while (!parents.get(result).equals(result)) {
        result = parents.get(result);
      }
      String current = identity;
      while (!current.equals(result)) {
        final String next = parents.put(current, result);
        current = next;
      }
      return result;
    }

    // Each alias root owns a separate set.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private Map<String, Set<String>> identities() {
      final Map<String, Set<String>> result = new TreeMap<>();
      for (final String identity : parents.keySet()) {
        result.computeIfAbsent(root(identity), ignored -> new TreeSet<>()).add(identity);
      }
      return result;
    }
  }
}
