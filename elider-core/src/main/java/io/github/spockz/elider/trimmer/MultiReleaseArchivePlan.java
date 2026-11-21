/* WHY: Binds a target-release selection to physical entries for safe MRJAR elevation. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.model.MultiReleaseEntryPath;
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
  "PMD.GodClass"
})
/* WHY: The immutable plan exposes named facts consumed by the writer and plugin. */
public final class MultiReleaseArchivePlan {
  static final String VERSIONS_PREFIX = "META-INF/versions/";
  static final String CLASS_SUFFIX = ".class";
  static final String MODULE_INFO = "module-info";
  private static final int MINIMUM_RELEASE = 1;

  private final Path sourcePath;
  private final ArtifactDigests sourceDigests;
  private final int targetRelease;
  private final int inputPhysicalEntries;
  private final Set<String> requestedRetainedClasses;
  private final List<Integer> versionedClassReleases;
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
      final ArtifactDigests sourceDigests,
      final int targetRelease,
      final int inputPhysicalEntries,
      final Set<String> requestedRetainedClasses,
      final List<Integer> versionedClassReleases,
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
    this.sourceDigests = sourceDigests;
    this.targetRelease = targetRelease;
    this.inputPhysicalEntries = inputPhysicalEntries;
    this.requestedRetainedClasses = Set.copyOf(requestedRetainedClasses);
    this.versionedClassReleases = versionedClassReleases.stream().distinct().sorted().toList();
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

  /** Immutable source inventory and digests shared across MRJAR stages. */
  public static final class SourceData {
    private final Path sourcePath;
    private final ArtifactDigests digests;
    private final MultiReleaseArchiveInventory.ArchiveIndex index;

    private SourceData(
        final Path sourcePath,
        final ArtifactDigests digests,
        final MultiReleaseArchiveInventory.ArchiveIndex index) {
      this.sourcePath = sourcePath;
      this.digests = digests;
      this.index = index;
    }

    /** Normalized path of the inspected source archive. */
    public Path sourcePath() {
      return sourcePath;
    }

    /** Precomputed source archive digests. */
    public ArtifactDigests digests() {
      return digests;
    }
  }

  /** Reads immutable MRJAR inventory and digests once for reuse across stages. */
  public static SourceData inspectSource(final Path source) throws IOException {
    return inspectSource(source, null);
  }

  /** Reads immutable MRJAR inventory once, reusing precomputed source digests. */
  public static SourceData inspectSource(final Path source, final ArtifactDigests digests)
      throws IOException {
    Objects.requireNonNull(source, "source");
    if (!java.nio.file.Files.isRegularFile(source)) {
      throw new IOException("Original dependency is not a regular JAR file: " + source);
    }
    final Path sourcePath = source.toAbsolutePath().normalize();
    final ArtifactDigests resolvedDigests = resolveSourceDigests(sourcePath, digests);
    final MultiReleaseArchiveInventory.ArchiveIndex index =
        MultiReleaseArchiveInventory.read(sourcePath);
    if (!index.versionedFiles().isEmpty() && !hasMultiReleaseManifest(index.manifest())) {
      throw new IOException("Versioned entries require Multi-Release: true: " + sourcePath);
    }
    return new SourceData(sourcePath, resolvedDigests, index);
  }

  private static ArtifactDigests resolveSourceDigests(
      final Path sourcePath, final ArtifactDigests digests) throws IOException {
    if (digests == null) {
      return ArtifactDigests.read(sourcePath);
    }
    if (!digests.matchesPath(sourcePath)) {
      throw new IOException(
          "Captured original dependency digests belong to a different path: " + sourcePath);
    }
    return digests;
  }

  /** Creates and validates a target-release elevation plan. */
  public static MultiReleaseArchivePlan create(
      final Path source,
      final int targetRelease,
      final Collection<String> retainedClasses,
      final Collection<String> removedServiceProviders)
      throws IOException {
    return create(inspectSource(source), targetRelease, retainedClasses, removedServiceProviders);
  }

  /** Creates and validates a target-release elevation plan from shared source data. */
  public static MultiReleaseArchivePlan create(
      final SourceData sourceData,
      final int targetRelease,
      final Collection<String> retainedClasses,
      final Collection<String> removedServiceProviders)
      throws IOException {
    Objects.requireNonNull(sourceData, "sourceData");
    Objects.requireNonNull(retainedClasses, "retainedClasses");
    Objects.requireNonNull(removedServiceProviders, "removedServiceProviders");
    if (targetRelease < MINIMUM_RELEASE) {
      throw new IllegalArgumentException("targetRelease must be positive");
    }
    final Set<String> normalizedRetained = normalizeClassNames(retainedClasses);
    final Set<String> normalizedRemovedProviders = normalizeBinaryNames(removedServiceProviders);
    return assemble(
        sourceData.sourcePath,
        sourceData.digests,
        sourceData.index,
        targetRelease,
        normalizedRetained,
        normalizedRemovedProviders);
  }

  private static MultiReleaseArchivePlan assemble(
      final Path sourcePath,
      final ArtifactDigests sourceDigests,
      final MultiReleaseArchiveInventory.ArchiveIndex index,
      final int targetRelease,
      final Set<String> normalizedRetained,
      final Set<String> normalizedRemovedProviders)
      throws IOException {
    final Map<String, ClassVariant> rootClasses = index.rootClasses();
    final Map<String, NavigableMap<Integer, ClassVariant>> versionedClasses =
        index.versionedClasses();
    final Map<String, NavigableMap<Integer, String>> versionedResources =
        index.versionedResources();
    final Set<String> versionedFiles = index.versionedFiles();
    final List<String> names = index.names();
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
        sourceDigests,
        targetRelease,
        names.size(),
        normalizedRetained,
        versionedClasses.values().stream()
            .flatMap(variants -> variants.navigableKeySet().stream())
            .distinct()
            .sorted()
            .toList(),
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
    return sourceDigests.sha256();
  }

  ArtifactDigests sourceDigests() {
    return sourceDigests;
  }

  int targetRelease() {
    return targetRelease;
  }

  int inputPhysicalEntries() {
    return inputPhysicalEntries;
  }

  Set<String> requestedRetainedClasses() {
    return requestedRetainedClasses;
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

  /** Maps retained physical source class entries to their exact output paths. */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // The result is frozen before use.
  public Map<String, String> classEntryProjection() {
    final Map<String, String> entries = new java.util.HashMap<>();
    for (final String owner : retainedTargetClasses) {
      final String selected = selectedClassEntries.get(owner);
      if (!selected.startsWith(MultiReleaseEntryPath.PREFIX)) {
        entries.put(selected, selected);
      }
    }
    versionedEntries.forEach(
        (path, action) -> {
          if (!action.omitted() && action.outputName().endsWith(".class")) {
            entries.put(path, action.outputName());
          }
        });
    return Map.copyOf(entries);
  }

  /** Returns immutable release and closure facts for plugin candidate analysis. */
  public PluginView pluginView() {
    return new PluginView(
        targetRelease,
        targetClasses,
        rootClassesRequiredByUpperTiers,
        requestedRetainedClasses,
        targetClasses.size(),
        logicalClasses.size(),
        retainedLogicalClasses.size(),
        inputPhysicalEntries,
        versionedClassReleases,
        hasVersionedOutput);
  }

  boolean matches(final Path source, final String sha256) {
    return source.toAbsolutePath().normalize().equals(sourcePath)
        && sourceDigests.sha256().equals(sha256);
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
    final MultiReleaseEntryPath parsed = MultiReleaseEntryPath.parse(entryName, directory);
    return parsed == null ? null : new VersionedPath(parsed.release(), parsed.logicalName());
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

  /**
   * Immutable plugin facts; class names use JVM internal slash form.
   *
   * @param targetPresentClasses target-present names (internal slash form)
   * @param requiredRootClasses forced root names (internal slash form)
   * @param requestedRetainedClasses requested names (internal slash form)
   * @param versionedClassReleases ascending implementation-class release breakpoints
   */
  public record PluginView(
      int targetRelease,
      Set<String> targetPresentClasses,
      Set<String> requiredRootClasses,
      Set<String> requestedRetainedClasses,
      int targetClassCount,
      int logicalClassCount,
      int retainedLogicalClassCount,
      int inputPhysicalEntries,
      List<Integer> versionedClassReleases,
      boolean hasHigherReleaseEntries) {
    /** Creates a defensive immutable view of the plan facts. */
    public PluginView {
      targetPresentClasses = Set.copyOf(targetPresentClasses);
      requiredRootClasses = Set.copyOf(requiredRootClasses);
      requestedRetainedClasses = Set.copyOf(requestedRetainedClasses);
      versionedClassReleases = versionedClassReleases.stream().distinct().sorted().toList();
    }

    @Override
    public List<Integer> versionedClassReleases() {
      return List.copyOf(versionedClassReleases);
    }
  }

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
