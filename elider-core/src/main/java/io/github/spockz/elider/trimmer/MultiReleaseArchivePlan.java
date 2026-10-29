/* WHY: Binds a target-release selection to physical entries for safe MRJAR elevation. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/** Immutable mapping from an MRJAR's target-release view to its output entries. */
/* WHY: The plan binds source identity to its immutable entry mappings. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidFieldNameMatchingMethodName",
  "PMD.TooManyMethods",
  "PMD.DataClass"
})
/* WHY: The immutable plan exposes named facts consumed by the writer and plugin. */
public final class MultiReleaseArchivePlan {
  static final String VERSIONS_PREFIX = "META-INF/versions/";
  static final String CLASS_SUFFIX = ".class";
  static final String MODULE_INFO = "module-info";
  private static final int MINIMUM_RELEASE = 1;

  private final Path sourcePath;
  private final String sourceSha256;
  private final int targetRelease;
  private final int inputPhysicalEntries;
  private final Map<String, VersionedEntry> versionedEntries;
  private final Map<String, String> selectedClassEntries;
  private final Set<String> targetClasses;
  private final Set<String> retainedTargetClasses;
  private final Set<String> rootClassesRequiredByUpperTiers;
  private final Set<String> logicalClasses;
  private final Set<String> retainedLogicalClasses;
  private final Set<String> rootResourcesOverridden;
  private final Set<String> removedServiceProviders;
  private final boolean hasVersionedOutput;

  private MultiReleaseArchivePlan(
      final Path sourcePath,
      final String sourceSha256,
      final int targetRelease,
      final int inputPhysicalEntries,
      final Map<String, VersionedEntry> versionedEntries,
      final Map<String, String> selectedClassEntries,
      final Set<String> targetClasses,
      final Set<String> retainedTargetClasses,
      final Set<String> rootClassesRequiredByUpperTiers,
      final Set<String> logicalClasses,
      final Set<String> retainedLogicalClasses,
      final Set<String> rootResourcesOverridden,
      final Set<String> removedServiceProviders,
      final boolean hasVersionedOutput) {
    this.sourcePath = sourcePath;
    this.sourceSha256 = sourceSha256;
    this.targetRelease = targetRelease;
    this.inputPhysicalEntries = inputPhysicalEntries;
    this.versionedEntries = Map.copyOf(versionedEntries);
    this.selectedClassEntries = Map.copyOf(selectedClassEntries);
    this.targetClasses = Set.copyOf(targetClasses);
    this.retainedTargetClasses = Set.copyOf(retainedTargetClasses);
    this.rootClassesRequiredByUpperTiers = Set.copyOf(rootClassesRequiredByUpperTiers);
    this.logicalClasses = Set.copyOf(logicalClasses);
    this.retainedLogicalClasses = Set.copyOf(retainedLogicalClasses);
    this.rootResourcesOverridden = Set.copyOf(rootResourcesOverridden);
    this.removedServiceProviders = Set.copyOf(removedServiceProviders);
    this.hasVersionedOutput = hasVersionedOutput;
  }

  /** Creates and validates a target-release elevation plan. */
  public static MultiReleaseArchivePlan create(
      final Path source,
      final int targetRelease,
      final Collection<String> retainedClasses,
      final Collection<String> removedServiceProviders)
      throws IOException {
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(retainedClasses, "retainedClasses");
    Objects.requireNonNull(removedServiceProviders, "removedServiceProviders");
    if (targetRelease < MINIMUM_RELEASE) {
      throw new IllegalArgumentException("targetRelease must be positive");
    }
    if (!java.nio.file.Files.isRegularFile(source)) {
      throw new IOException("Original dependency is not a regular JAR file: " + source);
    }
    final Path sourcePath = source.toRealPath();
    final ArtifactDigests sourceDigests = ArtifactDigests.read(sourcePath);
    final Set<String> normalizedRetained = normalizeClassNames(retainedClasses);
    final Set<String> normalizedRemovedProviders = normalizeBinaryNames(removedServiceProviders);
    return assemble(
        sourcePath,
        sourceDigests.sha256(),
        targetRelease,
        normalizedRetained,
        normalizedRemovedProviders);
  }

  private static MultiReleaseArchivePlan assemble(
      final Path sourcePath,
      final String sourceSha256,
      final int targetRelease,
      final Set<String> normalizedRetained,
      final Set<String> normalizedRemovedProviders)
      throws IOException {
    final MultiReleaseArchiveInventory.ArchiveIndex index =
        MultiReleaseArchiveInventory.read(sourcePath);
    final Map<String, ClassVariant> rootClasses = index.rootClasses();
    final Map<String, NavigableMap<Integer, ClassVariant>> versionedClasses =
        index.versionedClasses();
    final Map<String, NavigableMap<Integer, String>> versionedResources =
        index.versionedResources();
    final Set<String> versionedFiles = index.versionedFiles();
    final List<String> names = index.names();
    final Manifest manifest = index.manifest();
    if (!versionedFiles.isEmpty() && !hasMultiReleaseManifest(manifest)) {
      throw new IOException("Versioned entries require Multi-Release: true: " + sourcePath);
    }
    final ClassSelection selection =
        MultiReleaseArchivePlanner.selectClasses(
            rootClasses, versionedClasses, normalizedRetained, targetRelease);
    final Map<String, VersionedEntry> versionedEntries =
        MultiReleaseArchivePlanner.buildVersionedEntryPlan(
            versionedFiles,
            versionedResources,
            selection.selectedEntries(),
            selection.retainedTargetClasses(),
            targetRelease);
    final Set<String> rootResourcesOverridden = new HashSet<>();
    for (final Map.Entry<String, NavigableMap<Integer, String>> entry :
        versionedResources.entrySet()) {
      if (entry.getValue().floorEntry(targetRelease) != null) {
        rootResourcesOverridden.add(entry.getKey());
      }
    }
    final boolean hasVersionedOutput =
        versionedEntries.values().stream().anyMatch(VersionedEntry::preserved);
    return new MultiReleaseArchivePlan(
        sourcePath,
        sourceSha256,
        targetRelease,
        names.size(),
        versionedEntries,
        selection.selectedEntries(),
        selection.targetClasses(),
        selection.retainedTargetClasses(),
        selection.rootRequiredClasses(),
        selection.logicalClasses(),
        selection.retainedLogicalClasses(),
        rootResourcesOverridden,
        normalizedRemovedProviders,
        hasVersionedOutput);
  }

  record ClassSelection(
      Map<String, String> selectedEntries,
      Set<String> targetClasses,
      Set<String> logicalClasses,
      Set<String> rootRequiredClasses,
      Set<String> retainedTargetClasses,
      Set<String> retainedLogicalClasses) {}

  Path sourcePath() {
    return sourcePath;
  }

  String sourceSha256() {
    return sourceSha256;
  }

  int targetRelease() {
    return targetRelease;
  }

  int inputPhysicalEntries() {
    return inputPhysicalEntries;
  }

  Map<String, VersionedEntry> versionedEntries() {
    return versionedEntries;
  }

  Map<String, String> selectedClassEntries() {
    return selectedClassEntries;
  }

  Set<String> targetClasses() {
    return targetClasses;
  }

  Set<String> retainedTargetClasses() {
    return retainedTargetClasses;
  }

  Set<String> rootClassesRequiredByUpperTiers() {
    return rootClassesRequiredByUpperTiers;
  }

  Set<String> logicalClasses() {
    return logicalClasses;
  }

  Set<String> retainedLogicalClasses() {
    return retainedLogicalClasses;
  }

  Set<String> rootResourcesOverridden() {
    return rootResourcesOverridden;
  }

  Set<String> removedServiceProviders() {
    return removedServiceProviders;
  }

  boolean hasVersionedOutput() {
    return hasVersionedOutput;
  }

  boolean matches(final Path source, final String sha256) {
    return source.toAbsolutePath().normalize().equals(sourcePath) && sourceSha256.equals(sha256);
  }

  private static boolean hasMultiReleaseManifest(final Manifest manifest) {
    if (manifest == null) {
      return false;
    }
    final String value = manifest.getMainAttributes().getValue(Attributes.Name.MULTI_RELEASE);
    return value != null && "true".equalsIgnoreCase(value);
  }

  static VersionedPath parseVersionedPath(final String entryName, final boolean directory)
      throws IOException {
    return MultiReleaseVersionedPath.parse(entryName, directory);
  }

  private static Set<String> normalizeClassNames(final Collection<String> names) {
    final Set<String> result = new HashSet<>();
    for (final String name : names) {
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException("Retained classes must not contain null or blank names");
      }
      final String normalized = name.replace('.', '/');
      if (normalized.startsWith("[") || normalized.endsWith(".class") || normalized.contains(";")) {
        throw new IllegalArgumentException("Retained class is not a class name: " + name);
      }
      result.add(normalized);
    }
    return Set.copyOf(result);
  }

  private static Set<String> normalizeBinaryNames(final Collection<String> names) {
    final Set<String> result = new HashSet<>();
    for (final String name : names) {
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException(
            "Removed service providers must not contain blank names");
      }
      result.add(name.replace('/', '.'));
    }
    return Set.copyOf(result);
  }

  record VersionedEntry(String outputName, boolean omitted, boolean preserved) {
    static VersionedEntry drop() {
      return new VersionedEntry(null, true, false);
    }

    static VersionedEntry preserved(final String outputName) {
      return new VersionedEntry(outputName, false, true);
    }

    static VersionedEntry elevated(final String outputName) {
      return new VersionedEntry(outputName, false, false);
    }
  }

  record VersionedPath(int release, String logicalName) {}

  record ClassVariant(
      String name,
      String entryName,
      int release,
      int access,
      int accessVisibility,
      int majorVersion,
      ApiShape apiShape) {}

  record ApiShape(String header, List<String> members, List<String> records) {}
}
