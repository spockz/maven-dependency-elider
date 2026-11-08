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
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
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
  "PMD.LawOfDemeter",
  // This boundary joins verified bytes with proof and explanation.
  "PMD.CouplingBetweenObjects"
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

  private record PrerequisiteState(PrerequisiteClaim claim, boolean classPresent) {}

  private record PrerequisiteGroupState(PrerequisiteGroup group, List<PrerequisiteState> members) {}

  /** Keeps baseline refusal testable without weakening final inspection. */
  /* package */
  @FunctionalInterface
  interface InventoryInspector {
    /** Inspects one inventory using the production scan boundary. */
    InventoryInspection inspect(PreconditionClassInventory inventory) throws IOException;
  }

  private PreconditionProof() {}

  /** Checks effective prerequisites for the exact candidate. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final PreconditionClassInventory inventory)
      throws IOException {
    return proveWithAttribution(finding, candidate, inspectPair(inventory, inventory))
        .attestation();
  }

  /** Checks every effective prerequisite using a previously verified inventory. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final InventoryInspection inspection)
      throws IOException {
    return proveWithAttribution(finding, candidate, new InventoryPair(inspection, inspection, null))
        .attestation();
  }

  /** Proves absence in final bytes and attributes it against baseline providers. */
  public static PrerequisiteProofResult proveWithAttribution(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final PreconditionClassInventory baseline,
      final PreconditionClassInventory actualFinal)
      throws IOException {
    return proveWithAttribution(finding, candidate, inspectPair(baseline, actualFinal));
  }

  /** Reuses one immutable inspection pair across findings. */
  public static PrerequisiteProofResult proveWithAttribution(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final InventoryPair inventoryPair)
      throws IOException {
    Objects.requireNonNull(inventoryPair, "inventoryPair");
    return evaluatePrerequisites(
        finding,
        candidate,
        inventoryPair.baselineInspection,
        inventoryPair.actualFinalInspection,
        inventoryPair.baselineDetail());
  }

  /** Inspects final bytes and captures baseline evidence when complete. */
  public static InventoryPair inspectPair(
      final PreconditionClassInventory baseline, final PreconditionClassInventory actualFinal)
      throws IOException {
    return inspectPair(baseline, actualFinal, PreconditionProof::inspect);
  }

  /* package */ static InventoryPair inspectPair(
      final PreconditionClassInventory baseline,
      final PreconditionClassInventory actualFinal,
      final InventoryInspector inspector)
      throws IOException {
    Objects.requireNonNull(baseline, "baseline");
    Objects.requireNonNull(actualFinal, "actualFinal");
    Objects.requireNonNull(inspector, "inspector");
    final InventoryInspection finalInspection = inspector.inspect(actualFinal);
    if (baseline.status() != PreconditionClassInventory.Status.COMPLETE) {
      return new InventoryPair(null, finalInspection, baseline.detail());
    }
    if (baseline.fingerprint().equals(actualFinal.fingerprint())) {
      return new InventoryPair(finalInspection, finalInspection, null);
    }
    try {
      return new InventoryPair(inspector.inspect(baseline), finalInspection, null);
    } catch (final IOException | IllegalArgumentException | SecurityException exception) {
      return new InventoryPair(
          null,
          finalInspection,
          Objects.toString(exception.getMessage(), exception.getClass().getSimpleName()));
    }
  }

  private static PrerequisiteProofResult evaluatePrerequisites(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate candidate,
      final InventoryInspection baselineInspection,
      final InventoryInspection finalInspection,
      final String baselineDetail)
      throws IOException {
    FindingVerification.requireEligible(finding, candidate);
    if (finding.prerequisiteGroupStatusFor(candidate.version()) != ClaimGroupStatus.DECLARED) {
      throw new IllegalArgumentException("Precondition proof requires declared prerequisite pairs");
    }
    return evaluatePrerequisites(
        candidate,
        Set.copyOf(finding.effectivePrerequisiteGroupsFor(candidate.version())),
        baselineInspection,
        finalInspection,
        finding,
        baselineDetail);
  }

  // Each group gets its own immutable outcome for the final attestation.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static PrerequisiteProofResult evaluatePrerequisites(
      final ArtifactCoordinate candidate,
      final Set<PrerequisiteGroup> groups,
      final InventoryInspection baselineInspection,
      final InventoryInspection finalInspection,
      final GenericVulnerabilityFinding finding,
      final String baselineDetail)
      throws IOException {
    Objects.requireNonNull(finalInspection, "finalInspection");
    if (candidate.version() == null || candidate.version().isBlank()) {
      throw new IllegalArgumentException(
          "Precondition proof requires an exact affected Maven version");
    }
    if (groups.isEmpty()) {
      throw new IllegalArgumentException("Precondition proof requires prerequisite declarations");
    }
    final Provider affected =
        findAffectedProvider(candidate, finalInspection.inventory.providers());
    final List<PrerequisiteGroupState> groupStates = new ArrayList<>();
    final Set<PrerequisiteMemberObservation> memberObservations = new TreeSet<>();
    for (final PrerequisiteGroup group : new TreeSet<>(groups)) {
      final List<PrerequisiteState> states = prerequisiteStates(group, finalInspection);
      if (!isDisarmed(group.operator(), states)) {
        throw new IllegalArgumentException(
            "Required class is present in an inventoried provider, so prerequisite group remains "
                + "present in the complete inventory: "
                + group.operator());
      }
      groupStates.add(new PrerequisiteGroupState(group, states));
      states.stream()
          .map(
              state ->
                  new PrerequisiteMemberObservation(
                      state.claim(),
                      state.classPresent()
                          ? PrerequisiteMemberObservation.State.PRESENT
                          : PrerequisiteMemberObservation.State.ABSENT))
          .forEach(memberObservations::add);
    }
    final String impactDetail =
        "Required prerequisite groups were disarmed in the complete declared Maven inventory: "
            + groupStates.stream()
                .map(PreconditionProof::describeGroup)
                .collect(java.util.stream.Collectors.joining("; "))
            + ". The proof does not cover "
            + "providers introduced outside that inventory.";
    final VexAttestation attestation =
        VexAttestation.genericPrecondition(
            finding,
            affected.coordinate(),
            impactDetail,
            Set.copyOf(groups),
            Set.copyOf(memberObservations),
            affected.path(),
            affected.sha256(),
            finalInspection.inventory.fingerprint());
    return PrerequisiteProviderAttributor.result(
        attestation, groups, baselineInspection, finalInspection, baselineDetail);
  }

  private static List<PrerequisiteState> prerequisiteStates(
      final PrerequisiteGroup group, final InventoryInspection inspection) {
    return group.members().stream()
        .sorted()
        .map(
            claim -> {
              parseRequiredDependency(claim.requiresDependency());
              return new PrerequisiteState(
                  claim, !inspection.providersForClass(claim.requiresClass()).isEmpty());
            })
        .toList();
  }

  private static boolean isDisarmed(
      final PrerequisiteOperator operator, final List<PrerequisiteState> states) {
    return switch (operator) {
      case ANY_OF -> states.stream().noneMatch(PrerequisiteState::classPresent);
      case ALL_OF -> states.stream().anyMatch(state -> !state.classPresent());
    };
  }

  private static String describeGroup(final PrerequisiteGroupState state) {
    final String disarmingCondition =
        state.group().operator() == PrerequisiteOperator.ANY_OF
            ? "every member is absent"
            : "at least one member is absent";
    return state.group().operator()
        + " is disarmed because "
        + disarmingCondition
        + ": "
        + state.members().stream()
            .sorted(java.util.Comparator.comparing(PrerequisiteState::claim))
            .map(
                value ->
                    value.claim().requiresDependency()
                        + " / "
                        + value.claim().requiresClass()
                        + "="
                        + (value.classPresent() ? "PRESENT" : "ABSENT"))
            .collect(java.util.stream.Collectors.joining(", "));
  }

  /** Builds a reusable index from a complete provider inventory. */
  // This private index has one writer and is immutable after publication.
  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
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
    final Map<String, List<Provider>> providersByClass = new TreeMap<>();
    // One inspection thread builds this private index before immutable publication.
    for (final Provider provider : inventory.providers()) {
      for (final String className : readClasses(provider)) {
        providersByClass.computeIfAbsent(className, unused -> new ArrayList<>()).add(provider);
      }
    }
    return new InventoryInspection(inventory, providersByClass);
  }

  /** Immutable, proof-controlled snapshot of a verified provider inventory. */
  @SuppressWarnings("PMD.CommentRequired")
  public static final class InventoryInspection {
    private final PreconditionClassInventory inventory;
    private final Map<String, List<Provider>> providersByClass;

    // This defensive copy is local and becomes immutable before publication.
    @SuppressWarnings("PMD.UseConcurrentHashMap")
    private InventoryInspection(
        final PreconditionClassInventory inventory,
        final Map<String, List<Provider>> providersByClass) {
      this.inventory = inventory;
      final Map<String, List<Provider>> copy = new TreeMap<>();
      providersByClass.forEach(
          (className, providers) -> copy.put(className, List.copyOf(providers)));
      this.providersByClass = Map.copyOf(copy);
    }

    /** Returns every physically inspected provider containing this exact class. */
    public List<Provider> providersForClass(final String className) {
      return providersByClass.getOrDefault(
          Objects.requireNonNull(className, "className"), List.of());
    }

    /** Returns the immutable providers whose bytes were checked for this inspection. */
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    List<Provider> providers() {
      return inventory.providers();
    }
  }

  /** Private-construction pair of verified provider observations. */
  @SuppressWarnings("PMD.CommentRequired")
  public static final class InventoryPair {
    private final InventoryInspection baselineInspection;
    private final InventoryInspection actualFinalInspection;
    private final String baselineRefusal;

    private InventoryPair(
        final InventoryInspection baselineInspection,
        final InventoryInspection actualFinalInspection,
        final String baselineDetail) {
      this.baselineInspection = baselineInspection;
      this.actualFinalInspection =
          Objects.requireNonNull(actualFinalInspection, "actualFinalInspection");
      this.baselineRefusal = baselineDetail;
    }

    /** Returns why complete baseline attribution was unavailable, or {@code null}. */
    public String baselineDetail() {
      return baselineRefusal;
    }

    /** Returns the digest-bound actual final inventory fingerprint used by proof. */
    public String actualFinalFingerprint() {
      return actualFinalInspection.inventory.fingerprint();
    }
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
