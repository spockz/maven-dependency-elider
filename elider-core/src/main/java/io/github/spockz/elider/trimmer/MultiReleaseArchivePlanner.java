/* WHY: Keeps release selection and versioned-entry policy out of the immutable plan model. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;

/** Builds deterministic target-release class and entry selections. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MultiReleaseArchivePlanner {
  private MultiReleaseArchivePlanner() {}

  /* WHY: Ordered maps preserve deterministic ZIP selection. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static MultiReleaseArchivePlan.ClassSelection selectClasses(
      final Map<String, MultiReleaseArchivePlan.ClassVariant> rootClasses,
      final Map<String, NavigableMap<Integer, MultiReleaseArchivePlan.ClassVariant>>
          versionedClasses,
      final Set<String> normalizedRetained,
      final int targetRelease)
      throws IOException {
    final Set<String> targetClasses = new HashSet<>(rootClasses.keySet());
    final Set<String> logicalClasses = new HashSet<>(rootClasses.keySet());
    final Map<String, String> selectedEntries = new LinkedHashMap<>();
    for (final String name : rootClasses.keySet()) {
      selectedEntries.put(name, name + MultiReleaseArchivePlan.CLASS_SUFFIX);
    }
    final Set<String> rootRequired = new HashSet<>();
    for (final Map.Entry<String, NavigableMap<Integer, MultiReleaseArchivePlan.ClassVariant>>
        entry : versionedClasses.entrySet()) {
      validateClassVariants(
          entry.getKey(),
          entry.getValue(),
          rootClasses,
          selectedEntries,
          targetClasses,
          logicalClasses,
          rootRequired,
          targetRelease,
          normalizedRetained);
    }
    validateRetainedClasses(normalizedRetained, targetClasses);
    final Set<String> retainedTarget = new HashSet<>(normalizedRetained);
    retainedTarget.addAll(rootRequired);
    final Set<String> retainedLogical = new HashSet<>(retainedTarget);
    for (final Map.Entry<String, NavigableMap<Integer, MultiReleaseArchivePlan.ClassVariant>>
        entry : versionedClasses.entrySet()) {
      if (entry.getValue().higherKey(targetRelease) != null) {
        retainedLogical.add(entry.getKey());
      }
    }
    return new MultiReleaseArchivePlan.ClassSelection(
        selectedEntries,
        targetClasses,
        logicalClasses,
        rootRequired,
        retainedTarget,
        retainedLogical);
  }

  private static void validateClassVariants(
      final String className,
      final NavigableMap<Integer, MultiReleaseArchivePlan.ClassVariant> variants,
      final Map<String, MultiReleaseArchivePlan.ClassVariant> rootClasses,
      final Map<String, String> selectedEntries,
      final Set<String> targetClasses,
      final Set<String> logicalClasses,
      final Set<String> rootRequired,
      final int targetRelease,
      final Set<String> normalizedRetained)
      throws IOException {
    logicalClasses.add(className);
    final Map.Entry<Integer, MultiReleaseArchivePlan.ClassVariant> selected =
        variants.floorEntry(targetRelease);
    final MultiReleaseArchivePlan.ClassVariant selectedTarget =
        selected == null ? rootClasses.get(className) : selected.getValue();
    if (selected != null) {
      targetClasses.add(className);
      selectedEntries.put(className, selected.getValue().entryName());
    }
    for (final MultiReleaseArchivePlan.ClassVariant variant : variants.values()) {
      MultiReleaseClassFile.validateRelease(variant);
    }
    final List<MultiReleaseArchivePlan.ClassVariant> upperApiVariants =
        variants.values().stream()
            .filter(variant -> variant.release() > targetRelease)
            .filter(variant -> variant.accessVisibility() != 0)
            .toList();
    if (selected == null
        && selectedTarget != null
        && (normalizedRetained.contains(className) || !upperApiVariants.isEmpty())) {
      MultiReleaseClassFile.validateTargetRelease(selectedTarget, targetRelease);
    }
    if (!upperApiVariants.isEmpty()) {
      validateUpperApi(selectedTarget, upperApiVariants);
      rootRequired.add(className);
    }
  }

  private static void validateUpperApi(
      final MultiReleaseArchivePlan.ClassVariant targetVariant,
      final List<MultiReleaseArchivePlan.ClassVariant> upperApiVariants)
      throws IOException {
    if (targetVariant == null) {
      throw new IOException(
          "Upper-tier public or protected class has no target-release counterpart: "
              + upperApiVariants.get(0).entryName());
    }
    for (final MultiReleaseArchivePlan.ClassVariant variant : upperApiVariants) {
      if (targetVariant.accessVisibility() != variant.accessVisibility()
          || !targetVariant.apiShape().equals(variant.apiShape())) {
        throw new IOException(
            "Upper-tier public API differs from its target-release class: " + variant.entryName());
      }
    }
  }

  private static void validateRetainedClasses(
      final Set<String> retainedClasses, final Set<String> targetClasses) throws IOException {
    if (!targetClasses.containsAll(retainedClasses)) {
      final Set<String> missing = new HashSet<>(retainedClasses);
      missing.removeAll(targetClasses);
      throw new IOException(
          "Trim analysis references classes absent at target release: " + missing);
    }
  }

  /* WHY: This map preserves input order for deterministic plan construction. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static Map<String, MultiReleaseArchivePlan.VersionedEntry> buildVersionedEntryPlan(
      final Set<String> versionedFiles,
      final Map<String, NavigableMap<Integer, String>> versionedResources,
      final Map<String, String> selectedClassEntries,
      final Set<String> retainedTarget,
      final int targetRelease)
      throws IOException {
    final Map<String, MultiReleaseArchivePlan.VersionedEntry> versionedEntries =
        new LinkedHashMap<>();
    for (final String entryName : versionedFiles) {
      final MultiReleaseArchivePlan.VersionedPath path =
          MultiReleaseVersionedPath.parse(entryName, false);
      if (path == null) {
        throw new IOException("Invalid indexed versioned file: " + entryName);
      }
      final MultiReleaseArchivePlan.VersionedEntry action =
          entryName.endsWith(MultiReleaseArchivePlan.CLASS_SUFFIX)
              ? planVersionedClass(
                  entryName, path, selectedClassEntries, retainedTarget, targetRelease)
              : planVersionedResource(entryName, path, versionedResources, targetRelease);
      versionedEntries.put(entryName, action);
    }
    return versionedEntries;
  }

  private static MultiReleaseArchivePlan.VersionedEntry planVersionedClass(
      final String entryName,
      final MultiReleaseArchivePlan.VersionedPath path,
      final Map<String, String> selectedClassEntries,
      final Set<String> retainedTarget,
      final int targetRelease) {
    final String className =
        path.logicalName()
            .substring(
                0, path.logicalName().length() - MultiReleaseArchivePlan.CLASS_SUFFIX.length());
    if (MultiReleaseArchivePlan.MODULE_INFO.equals(className)
        || className.endsWith("/" + MultiReleaseArchivePlan.MODULE_INFO)) {
      return MultiReleaseArchivePlan.VersionedEntry.drop();
    }
    if (path.release() > targetRelease) {
      return MultiReleaseArchivePlan.VersionedEntry.preserved(entryName);
    }
    if (entryName.equals(selectedClassEntries.get(className))
        && retainedTarget.contains(className)) {
      return MultiReleaseArchivePlan.VersionedEntry.elevated(path.logicalName());
    }
    return MultiReleaseArchivePlan.VersionedEntry.drop();
  }

  private static MultiReleaseArchivePlan.VersionedEntry planVersionedResource(
      final String entryName,
      final MultiReleaseArchivePlan.VersionedPath path,
      final Map<String, NavigableMap<Integer, String>> versionedResources,
      final int targetRelease) {
    if (path.release() > targetRelease) {
      return MultiReleaseArchivePlan.VersionedEntry.preserved(entryName);
    }
    final NavigableMap<Integer, String> resources = versionedResources.get(path.logicalName());
    final Map.Entry<Integer, String> selected = resources.floorEntry(targetRelease);
    return selected != null && selected.getValue().equals(entryName)
        ? MultiReleaseArchivePlan.VersionedEntry.elevated(path.logicalName())
        : MultiReleaseArchivePlan.VersionedEntry.drop();
  }
}
