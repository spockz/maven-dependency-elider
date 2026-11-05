/* WHY: Proves prerequisite absence only against the complete, digest-bound build inventory. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;

/** Proves required-class absence within a complete Maven inventory. */
/* The coupled gates recheck each declared input before the proof creates evidence. */
@SuppressWarnings({
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.TooManyMethods",
  "PMD.LawOfDemeter"
})
public final class PreconditionProof {
  /** Suffix recognized for raw class-file providers. */
  private static final String CLASS_SUFFIX = ".class";

  /** Prefix used to distinguish multi-release archive variants. */
  private static final String VERSIONED_PREFIX = "META-INF/versions/";

  /** Descriptor basename for javac plugins not disabled by proc=none. */
  private static final String JAVAC_PLUGIN_SERVICE_FILE_NAME = "com.sun.source.util.Plugin";

  /** Classpath service descriptor path checked in archives. */
  private static final String JAVAC_PLUGIN_SERVICE_ENTRY =
      "META-INF/services/" + JAVAC_PLUGIN_SERVICE_FILE_NAME;

  /** First legal multi-release JAR version. */
  private static final int MINIMUM_MULTI_RELEASE_VERSION = 9;

  /** Exactly one retained affected artifact must bind the mapping to a file. */
  private static final int EXACTLY_ONE_PROVIDER = 1;

  /** Required number of colon-delimited prerequisite coordinate parts. */
  private static final int REQUIRED_DEPENDENCY_PARTS = 2;

  /** Bytes needed to identify a class file by magic. */
  private static final int CLASS_FILE_HEADER_LENGTH = 4;

  private record RequiredDependency(String groupId, String artifactId) {}

  private record ArchiveClass(String internalName, int release) {}

  private PreconditionProof() {}

  /** Returns precondition evidence or fails closed when any proof gate is unmet. */
  public static VexAttestation prove(
      final ExplicitPrerequisiteEvidence evidence, final PreconditionClassInventory inventory)
      throws IOException {
    final VulnerabilitySymbolMapping mapping = requireEvidence(evidence);
    return prove(
        mapping.cveId(),
        mapping.affectedCoordinate(),
        Set.of(new PrerequisiteClaim(mapping.requiresDependency(), mapping.requiresClass())),
        inspect(inventory),
        null);
  }

  /** Checks effective prerequisites for the exact candidate. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final PreconditionClassInventory inventory)
      throws IOException {
    return prove(finding, candidate, inspect(inventory));
  }

  /** Checks every effective prerequisite using a previously verified inventory. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final InventoryInspection inspection)
      throws IOException {
    FindingVerification.requireEligible(finding, candidate);
    if (finding.prerequisiteGroupStatusFor(candidate.version()) != ClaimGroupStatus.DECLARED) {
      throw new IllegalArgumentException("Precondition proof requires declared prerequisite pairs");
    }
    return prove(
        finding.vulnerabilityId(),
        candidate,
        Set.copyOf(finding.effectivePrerequisitesFor(candidate.version())),
        inspection,
        finding);
  }

  private static VexAttestation prove(
      final String vulnerabilityId,
      final ArtifactCoordinate candidate,
      final Set<PrerequisiteClaim> prerequisites,
      final InventoryInspection inspection,
      final GenericVulnerabilityFinding finding)
      throws IOException {
    Objects.requireNonNull(inspection, "inspection");
    if (candidate.version() == null || candidate.version().isBlank()) {
      throw new IllegalArgumentException(
          "Precondition proof requires an exact affected Maven version");
    }
    if (prerequisites.isEmpty()) {
      throw new IllegalArgumentException("Precondition proof requires prerequisite declarations");
    }
    final Provider affected = findAffectedProvider(candidate, inspection.inventory.providers());
    final Set<String> availableClasses = inspection.availableClasses;
    final Set<RequiredDependency> availableDependencies = inspection.availableDependencies;
    for (final PrerequisiteClaim prerequisite : new TreeSet<>(prerequisites)) {
      if (availableDependencies.contains(
          parseRequiredDependency(prerequisite.requiresDependency()))) {
        throw new IllegalArgumentException(
            "Required dependency is present in the complete inventory: "
                + prerequisite.requiresDependency());
      }
      if (availableClasses.contains(prerequisite.requiresClass())) {
        throw new IllegalArgumentException(
            "Required class is present in an inventoried provider: "
                + prerequisite.requiresClass());
      }
    }
    final String impactDetail =
        "Required prerequisite pairs "
            + prerequisites.stream()
                .sorted()
                .map(value -> value.requiresDependency() + " / " + value.requiresClass())
                .collect(java.util.stream.Collectors.joining("; "))
            + " are absent from the complete declared Maven inventory. The proof does not cover "
            + "providers introduced outside that inventory.";
    if (finding != null) {
      return VexAttestation.genericPrecondition(
          finding,
          affected.coordinate(),
          impactDetail,
          prerequisites,
          affected.path(),
          affected.sha256(),
          inspection.inventory.fingerprint());
    }
    return VexAttestation.precondition(
        vulnerabilityId,
        affected.coordinate(),
        impactDetail,
        prerequisites,
        affected.path(),
        affected.sha256(),
        inspection.inventory.fingerprint());
  }

  /** Captures and validates a complete provider inventory for reuse across findings. */
  public static InventoryInspection inspect(final PreconditionClassInventory inventory)
      throws IOException {
    Objects.requireNonNull(inventory, "inventory");
    if (inventory.status() == PreconditionClassInventory.Status.INCOMPLETE) {
      throw new IllegalArgumentException(
          "Precondition inventory is incomplete: " + inventory.detail());
    }
    if (inventory.status() == PreconditionClassInventory.Status.INSPECTION_FAILED) {
      throw new IOException("Precondition inventory inspection failed: " + inventory.detail());
    }
    if (inventory.status() != PreconditionClassInventory.Status.COMPLETE) {
      throw new IllegalArgumentException("Precondition inventory status is unsupported");
    }

    verifyProviderDigests(inventory.providers());
    final Set<String> availableClasses = new HashSet<>();
    final Set<RequiredDependency> availableDependencies = new HashSet<>();
    for (final Provider provider : inventory.providers()) {
      if (provider.kind() == ProviderKind.DEPENDENCY_ARCHIVE) {
        availableDependencies.add(
            new RequiredDependency(
                provider.coordinate().groupId(), provider.coordinate().artifactId()));
      }
      availableClasses.addAll(readClasses(provider));
    }
    return new InventoryInspection(inventory, availableClasses, availableDependencies);
  }

  /** Immutable, proof-controlled snapshot of a verified provider inventory. */
  @SuppressWarnings("PMD.CommentRequired")
  public static final class InventoryInspection {
    private final PreconditionClassInventory inventory;
    private final Set<String> availableClasses;
    private final Set<RequiredDependency> availableDependencies;

    private InventoryInspection(
        final PreconditionClassInventory inventory,
        final Set<String> availableClasses,
        final Set<RequiredDependency> availableDependencies) {
      this.inventory = inventory;
      this.availableClasses = Set.copyOf(availableClasses);
      this.availableDependencies = Set.copyOf(availableDependencies);
    }
  }

  private static VulnerabilitySymbolMapping requireEvidence(
      final ExplicitPrerequisiteEvidence evidence) {
    if (evidence == null) {
      throw new IllegalArgumentException("Explicit prerequisite evidence is required");
    }
    return evidence.mapping();
  }

  private static RequiredDependency parseRequiredDependency(final String value) {
    if (!VulnerabilitySymbolMapping.isValidRequiredDependency(value)) {
      throw new IllegalArgumentException(
          "Precondition requiresDependency must be an exact group:artifact value");
    }
    final String[] parts = value.split(":", -1);
    if (parts.length != REQUIRED_DEPENDENCY_PARTS) {
      throw new IllegalArgumentException(
          "Precondition requiresDependency must be an exact group:artifact value");
    }
    return new RequiredDependency(parts[0], parts[1]);
  }

  private static Provider findAffectedProvider(
      final ArtifactCoordinate candidate, final List<Provider> providers) {
    final List<Provider> affectedProviders = new ArrayList<>();
    for (final Provider provider : providers) {
      if (provider.kind() == ProviderKind.DEPENDENCY_ARCHIVE
          && sameArtifactIdentity(candidate, provider.coordinate())) {
        affectedProviders.add(provider);
      }
    }
    if (affectedProviders.size() != EXACTLY_ONE_PROVIDER) {
      throw new IllegalArgumentException(
          "Complete inventory must contain exactly one retained affected artifact: "
              + candidate.toId());
    }
    return affectedProviders.getFirst();
  }

  private static boolean sameArtifactIdentity(
      final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && Objects.equals(left.version(), right.version())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }

  private static void verifyProviderDigests(final List<Provider> providers) throws IOException {
    for (final Provider provider : providers) {
      if (!Files.isRegularFile(provider.path())) {
        throw new IOException("Class provider is not a readable regular file: " + provider.path());
      }
      if (!ArtifactDigests.read(provider.path()).sha256().equals(provider.sha256())) {
        throw new IOException("Class provider digest changed: " + provider.path());
      }
    }
  }

  private static Set<String> readClasses(final Provider provider) throws IOException {
    return switch (provider.kind()) {
      case DEPENDENCY_ARCHIVE -> readArchiveClasses(provider.path());
      case APPLICATION_CLASS_FILE -> readApplicationClass(provider.path());
      case APPLICATION_RESOURCE_FILE -> readApplicationResource(provider.path());
      case APPLICATION_SOURCE_FILE -> provider.discoveredClassNames();
    };
  }

  private static Set<String> readApplicationClass(final Path path) throws IOException {
    final byte[] header;
    try (InputStream input = Files.newInputStream(path)) {
      header = input.readNBytes(CLASS_FILE_HEADER_LENGTH);
    }
    if (isClassFile(header)) {
      return readSingleClass(path);
    }
    throw new IOException("Unrecognized application class provider: " + path);
  }

  private static Set<String> readApplicationResource(final Path path) throws IOException {
    final Path fileNamePath = path.getFileName();
    if (fileNamePath == null) {
      throw new IOException("Application resource path has no filename: " + path);
    }
    if (JAVAC_PLUGIN_SERVICE_FILE_NAME.equals(fileNamePath.toString())) {
      throw new IOException(
          "Javac plugin service provider can generate classes during compilation");
    }
    final byte[] header;
    try (InputStream input = Files.newInputStream(path)) {
      header = input.readNBytes(CLASS_FILE_HEADER_LENGTH);
    }
    if (isClassFile(header)) {
      return readSingleClass(path);
    }
    if (isZipFile(header)) {
      return readArchiveClasses(path);
    }
    final String fileName = fileNamePath.toString().toLowerCase(Locale.ROOT);
    if (fileName.endsWith(CLASS_SUFFIX) || fileName.endsWith(".jar") || fileName.endsWith(".zip")) {
      throw new IOException("Unrecognized application class/resource provider: " + path);
    }
    return Set.of();
  }

  private static Set<String> readSingleClass(final Path path) throws IOException {
    try (InputStream input = Files.newInputStream(path)) {
      final String name = new ClassReader(input).getClassName();
      if (isModuleInfo(name)) {
        return Set.of();
      }
      return Set.of(name.replace('/', '.'));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unreadable application class file: " + path, exception);
    }
  }

  private static Set<String> readArchiveClasses(final Path path) throws IOException {
    final Set<String> classes = new TreeSet<>();
    final Set<String> providerEntries = new HashSet<>();
    try (ZipFile zip = new ZipFile(path.toFile())) {
      final Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        inspectArchiveEntry(zip, entries.nextElement(), providerEntries, classes);
      }
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unreadable class provider archive: " + path, exception);
    }
    return Set.copyOf(classes);
  }

  private static void inspectArchiveEntry(
      final ZipFile archive,
      final ZipEntry entry,
      final Set<String> providerEntries,
      final Set<String> classes)
      throws IOException {
    if (entry.isDirectory()) {
      return;
    }
    final String entryName = entry.getName();
    if (JAVAC_PLUGIN_SERVICE_ENTRY.equals(entryName)) {
      throw new IOException(
          "Javac plugin service provider can generate classes during compilation");
    }
    final byte[] header = readArchiveEntryHeader(archive, entry);
    if (entryName.endsWith(CLASS_SUFFIX)) {
      if (!isClassFile(header)) {
        throw new IOException("Malformed class entry: " + entryName);
      }
      final ArchiveClass archiveClass = archiveClass(entryName);
      final String className = readArchiveClass(archive, entry, archiveClass.internalName());
      recordArchiveClass(className, archiveClass.release(), providerEntries, classes);
    } else if (isClassFile(header)) {
      final String className = readArchiveClass(archive, entry);
      recordArchiveClass(className, 0, providerEntries, classes);
    } else if (isZipFile(header) || hasNestedArchiveSuffix(entryName)) {
      throw new IOException("Nested archive provider is not supported: " + entryName);
    }
  }

  private static boolean hasNestedArchiveSuffix(final String entryName) {
    final String normalizedName = entryName.toLowerCase(Locale.ROOT);
    return normalizedName.endsWith(".jar") || normalizedName.endsWith(".zip");
  }

  private static byte[] readArchiveEntryHeader(final ZipFile archive, final ZipEntry entry)
      throws IOException {
    try (InputStream input = archive.getInputStream(entry)) {
      return input.readNBytes(CLASS_FILE_HEADER_LENGTH);
    }
  }

  private static String readArchiveClass(
      final ZipFile archive, final ZipEntry entry, final String expectedName) throws IOException {
    final String actualName = readArchiveClass(archive, entry);
    if (!expectedName.equals(actualName)) {
      throw new IOException("Class entry name does not match its bytecode: " + entry.getName());
    }
    return actualName;
  }

  private static String readArchiveClass(final ZipFile archive, final ZipEntry entry)
      throws IOException {
    try (InputStream input = archive.getInputStream(entry)) {
      return new ClassReader(input).getClassName();
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unreadable class entry: " + entry.getName(), exception);
    }
  }

  private static void recordArchiveClass(
      final String internalName,
      final int release,
      final Set<String> providerEntries,
      final Set<String> classes)
      throws IOException {
    final String className = internalName.replace('/', '.');
    if (isModuleInfo(className)) {
      return;
    }
    if (!providerEntries.add(internalName + "@" + release)) {
      throw new IOException("Duplicate class provider entry: " + className);
    }
    classes.add(className);
  }

  private static ArchiveClass archiveClass(final String entryName) throws IOException {
    String name = entryName.substring(0, entryName.length() - CLASS_SUFFIX.length());
    int release = 0;
    if (name.startsWith(VERSIONED_PREFIX)) {
      final int releaseEnd = name.indexOf('/', VERSIONED_PREFIX.length());
      if (releaseEnd < 0
          || !name.substring(VERSIONED_PREFIX.length(), releaseEnd).matches("[1-9][0-9]*")) {
        throw new IOException("Malformed multi-release class entry: " + entryName);
      }
      try {
        release = Integer.parseInt(name.substring(VERSIONED_PREFIX.length(), releaseEnd));
      } catch (final NumberFormatException exception) {
        throw new IOException("Malformed multi-release class entry: " + entryName, exception);
      }
      if (release < MINIMUM_MULTI_RELEASE_VERSION) {
        throw new IOException("Malformed multi-release class release: " + entryName);
      }
      name = name.substring(releaseEnd + 1);
    }
    if (name.isBlank() || name.startsWith("/") || name.contains("\\")) {
      throw new IOException("Malformed class entry: " + entryName);
    }
    return new ArchiveClass(name, release);
  }

  private static boolean isClassFile(final byte[] header) {
    return header.length == 4
        && header[0] == (byte) 0xca
        && header[1] == (byte) 0xfe
        && header[2] == (byte) 0xba
        && header[3] == (byte) 0xbe;
  }

  private static boolean isZipFile(final byte[] header) {
    return header.length >= 2 && header[0] == 0x50 && header[1] == 0x4b;
  }

  private static boolean isModuleInfo(final String name) {
    return "module-info".equals(name) || name.endsWith(".module-info");
  }
}
