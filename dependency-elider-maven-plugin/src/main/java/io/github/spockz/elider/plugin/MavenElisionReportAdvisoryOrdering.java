// WHY: Defines total advisory-row order without increasing report snapshot validation complexity.

package io.github.spockz.elider.plugin;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Total deterministic ordering for saved advisory rows. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionReportAdvisoryOrdering {
  private MavenElisionReportAdvisoryOrdering() {}

  static int comparePackageFindings(
      final MavenElisionReportSnapshot.PackageAdvisoryFinding left,
      final MavenElisionReportSnapshot.PackageAdvisoryFinding right) {
    return compareInOrder(
        left.coordinate().compareTo(right.coordinate()),
        left.osvId().compareTo(right.osvId()),
        left.ecosystem().compareTo(right.ecosystem()),
        left.packageName().compareTo(right.packageName()),
        left.applicability().compareTo(right.applicability()),
        compareStrings(left.affectedVersions(), right.affectedVersions()),
        compareRanges(left.ranges(), right.ranges()),
        left.applicabilityRationale().compareTo(right.applicabilityRationale()),
        left.inventoryDisposition().compareTo(right.inventoryDisposition()),
        compareStrings(left.aliases(), right.aliases()),
        compareNullable(left.sourceRecordSha256(), right.sourceRecordSha256()));
  }

  static int compareHeuristicFindings(
      final MavenElisionReportSnapshot.HeuristicAdvisoryFinding left,
      final MavenElisionReportSnapshot.HeuristicAdvisoryFinding right) {
    return compareInOrder(
        left.coordinate().compareTo(right.coordinate()),
        left.osvId().compareTo(right.osvId()),
        left.sourceRecordId().compareTo(right.sourceRecordId()),
        left.origin().compareTo(right.origin()),
        compareNullable(left.cveId(), right.cveId()),
        compareStrings(left.aliases(), right.aliases()),
        left.ecosystem().compareTo(right.ecosystem()),
        left.packageName().compareTo(right.packageName()),
        left.versionRangeSpec().compareTo(right.versionRangeSpec()),
        left.applicability().compareTo(right.applicability()),
        left.applicabilityRationale().compareTo(right.applicabilityRationale()),
        left.inventoryDisposition().compareTo(right.inventoryDisposition()),
        compareNullable(left.sourceUrl(), right.sourceUrl()),
        compareNullable(left.sourceRecordSha256(), right.sourceRecordSha256()),
        left.confidence().compareTo(right.confidence()),
        compareStrings(left.candidateClasses(), right.candidateClasses()),
        compareStrings(left.candidateDependencies(), right.candidateDependencies()));
  }

  private static int compareRanges(
      final List<MavenElisionReportSnapshot.AffectedRange> left,
      final List<MavenElisionReportSnapshot.AffectedRange> right) {
    final int common = Math.min(left.size(), right.size());
    for (int index = 0; index < common; index++) {
      final int rangeComparison = compareRange(left.get(index), right.get(index));
      if (rangeComparison != 0) {
        return rangeComparison;
      }
    }
    return Integer.compare(left.size(), right.size());
  }

  private static int compareRange(
      final MavenElisionReportSnapshot.AffectedRange left,
      final MavenElisionReportSnapshot.AffectedRange right) {
    return compareInOrder(
        left.type().compareTo(right.type()),
        compareNullable(left.repo(), right.repo()),
        compareEvents(left.events(), right.events()));
  }

  private static int compareEvents(
      final List<Map<String, String>> left, final List<Map<String, String>> right) {
    final int common = Math.min(left.size(), right.size());
    for (int index = 0; index < common; index++) {
      final int eventComparison = compareEvent(left.get(index), right.get(index));
      if (eventComparison != 0) {
        return eventComparison;
      }
    }
    return Integer.compare(left.size(), right.size());
  }

  private static int compareEvent(final Map<String, String> left, final Map<String, String> right) {
    final Iterator<Map.Entry<String, String>> leftEntries =
        new TreeMap<>(left).entrySet().iterator();
    final Iterator<Map.Entry<String, String>> rightEntries =
        new TreeMap<>(right).entrySet().iterator();
    while (leftEntries.hasNext() && rightEntries.hasNext()) {
      final Map.Entry<String, String> leftEntry = leftEntries.next();
      final Map.Entry<String, String> rightEntry = rightEntries.next();
      final int entryComparison =
          compareInOrder(
              leftEntry.getKey().compareTo(rightEntry.getKey()),
              leftEntry.getValue().compareTo(rightEntry.getValue()));
      if (entryComparison != 0) {
        return entryComparison;
      }
    }
    return Boolean.compare(leftEntries.hasNext(), rightEntries.hasNext());
  }

  private static int compareStrings(final List<String> left, final List<String> right) {
    final int common = Math.min(left.size(), right.size());
    for (int index = 0; index < common; index++) {
      final int comparison = left.get(index).compareTo(right.get(index));
      if (comparison != 0) {
        return comparison;
      }
    }
    return Integer.compare(left.size(), right.size());
  }

  private static int compareNullable(final String left, final String right) {
    if (left == null) {
      return right == null ? 0 : -1;
    }
    return right == null ? 1 : left.compareTo(right);
  }

  private static int compareInOrder(final int... comparisons) {
    for (final int comparison : comparisons) {
      if (comparison != 0) {
        return comparison;
      }
    }
    return 0;
  }
}
