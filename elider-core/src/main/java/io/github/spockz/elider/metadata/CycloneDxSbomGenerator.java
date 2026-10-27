// WHY: Emits an inventory of the artifacts Maven actually retained after whole-artifact elision.

package io.github.spockz.elider.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

/** Generates a deterministic CycloneDX 1.6 component inventory for an applied elision decision. */
@SuppressWarnings({
  "PMD.AssignmentInOperand",
  "PMD.AvoidDuplicateLiterals",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CognitiveComplexity",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CommentSize",
  "PMD.CouplingBetweenObjects",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.ConsecutiveAppendsShouldReuse",
  "PMD.LawOfDemeter",
  "PMD.LocalVariableCouldBeFinal",
  "PMD.LooseCoupling",
  "PMD.MethodArgumentCouldBeFinal",
  "PMD.ShortVariable",
  "PMD.UseExplicitTypes",
  "PMD.TooManyMethods"
})
public final class CycloneDxSbomGenerator {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String SERIAL_NUMBER_PATTERN =
      "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
  private static final String PURL_SAFE =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_~";

  private final AtomicReplacer atomicReplacer;

  /** Creates a generator that uses an atomic filesystem replacement. */
  public CycloneDxSbomGenerator() {
    this(CycloneDxSbomGenerator::atomicReplace);
  }

  CycloneDxSbomGenerator(AtomicReplacer atomicReplacer) {
    this.atomicReplacer = Objects.requireNonNull(atomicReplacer, "atomicReplacer must not be null");
  }

  /** Required metadata for the generated BOM. */
  public record DocumentMetadata(
      String serialNumber, int version, Instant timestamp, String toolName, String toolVersion) {
    /** Validates required metadata values. */
    public DocumentMetadata {
      if (serialNumber == null || !serialNumber.matches(SERIAL_NUMBER_PATTERN)) {
        throw new IllegalArgumentException(
            "serialNumber must match lowercase urn:uuid:<UUID> format");
      }
      requireText(toolName, "toolName");
      requireText(toolVersion, "toolVersion");
      Objects.requireNonNull(timestamp, "timestamp must not be null");
      if (version < 1) {
        throw new IllegalArgumentException("version must be positive");
      }
    }
  }

  /** Maven identity and display name for the application. */
  public record RootIdentity(String groupId, String artifactId, String version, String name) {
    /** Validates required application identity values. */
    public RootIdentity {
      requireText(groupId, "root groupId");
      requireText(artifactId, "root artifactId");
      requireText(version, "root version");
      requireText(name, "root name");
    }
  }

  /**
   * Builds JSON first, then atomically replaces the destination so failures never leave partial
   * output.
   */
  public void write(
      Path output,
      RootIdentity root,
      Collection<ArtifactFileRef> appliedRetainedInventory,
      ElisionDecision decision,
      DocumentMetadata metadata)
      throws IOException {
    write(output, root, appliedRetainedInventory, decision, metadata, Set.of());
  }

  /** Writes an inventory with provenance records for any trimmed dependency artifacts. */
  public void write(
      Path output,
      RootIdentity root,
      Collection<ArtifactFileRef> appliedRetainedInventory,
      ElisionDecision decision,
      DocumentMetadata metadata,
      Collection<ArtifactTrimRecord> trimRecords)
      throws IOException {
    Objects.requireNonNull(output, "output must not be null");
    byte[] bytes = generate(root, appliedRetainedInventory, decision, metadata, trimRecords);
    writeBytes(output, bytes);
  }

  /** Writes a retained inventory with evidence-backed CycloneDX VEX statements. */
  public void write(
      Path output,
      RootIdentity root,
      Collection<ArtifactFileRef> appliedRetainedInventory,
      ElisionDecision decision,
      DocumentMetadata metadata,
      Collection<ArtifactTrimRecord> trimRecords,
      Collection<VexAttestation> attestations)
      throws IOException {
    Objects.requireNonNull(output, "output must not be null");
    writeBytes(
        output,
        generate(root, appliedRetainedInventory, decision, metadata, trimRecords, attestations));
  }

  /** Writes a baseline inventory before whole-artifact elision has been applied. */
  public void writeBaseline(
      Path output,
      RootIdentity root,
      Collection<ArtifactFileRef> baselineInventory,
      DocumentMetadata metadata)
      throws IOException {
    Objects.requireNonNull(output, "output must not be null");
    writeBytes(output, generateBaseline(root, baselineInventory, metadata));
  }

  /** Generates a baseline inventory before whole-artifact elision has been applied. */
  public byte[] generateBaseline(
      RootIdentity root, Collection<ArtifactFileRef> baselineInventory, DocumentMetadata metadata)
      throws IOException {
    return generateInventory(
        root, baselineInventory, metadata, Set.of(), List.of(), Optional.empty());
  }

  private void writeBytes(Path output, byte[] bytes) throws IOException {
    Path absolute = output.toAbsolutePath();
    Path parent = absolute.getParent();
    if (parent == null) {
      throw new IOException("Output path must have a parent directory: " + absolute);
    }
    Files.createDirectories(parent);
    Path temporary =
        parent.resolve("." + absolute.getFileName() + "." + UUID.randomUUID() + ".tmp");
    try {
      Files.write(temporary, bytes);
      atomicReplacer.replace(temporary, absolute);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  byte[] generate(
      RootIdentity root,
      Collection<ArtifactFileRef> inventory,
      ElisionDecision decision,
      DocumentMetadata metadata)
      throws IOException {
    return generate(root, inventory, decision, metadata, Set.of());
  }

  byte[] generate(
      RootIdentity root,
      Collection<ArtifactFileRef> inventory,
      ElisionDecision decision,
      DocumentMetadata metadata,
      Collection<ArtifactTrimRecord> trimRecords)
      throws IOException {
    return generate(root, inventory, decision, metadata, trimRecords, List.of());
  }

  byte[] generate(
      RootIdentity root,
      Collection<ArtifactFileRef> inventory,
      ElisionDecision decision,
      DocumentMetadata metadata,
      Collection<ArtifactTrimRecord> trimRecords,
      Collection<VexAttestation> attestations)
      throws IOException {
    Objects.requireNonNull(decision, "decision must not be null");
    return generateInventory(
        root, inventory, metadata, trimRecords, attestations, Optional.of(decision));
  }

  private byte[] generateInventory(
      RootIdentity root,
      Collection<ArtifactFileRef> inventory,
      DocumentMetadata metadata,
      Collection<ArtifactTrimRecord> trimRecords,
      Collection<VexAttestation> attestations,
      Optional<ElisionDecision> decision)
      throws IOException {
    Objects.requireNonNull(root, "root must not be null");
    Objects.requireNonNull(inventory, "inventory must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    Objects.requireNonNull(trimRecords, "trimRecords must not be null");
    Objects.requireNonNull(attestations, "attestations must not be null");
    Objects.requireNonNull(decision, "decision must not be null");
    TreeMap<String, ComponentEntry> components = componentEntries(inventory, decision);
    final Map<String, ArtifactTrimRecord> trimsByIdentity =
        validateTrimRecords(trimRecords, components);

    ObjectNode bom = JSON.createObjectNode();
    bom.put("$schema", "http://cyclonedx.org/schema/bom-1.6.schema.json");
    bom.put("bomFormat", "CycloneDX");
    bom.put("specVersion", "1.6");
    bom.put("serialNumber", metadata.serialNumber());
    bom.put("version", metadata.version());
    ObjectNode meta = bom.putObject("metadata");
    meta.put("timestamp", metadata.timestamp().toString());
    meta.putArray("tools")
        .addObject()
        .put("vendor", "io.github.spockz")
        .put("name", metadata.toolName())
        .put("version", metadata.toolVersion());
    ObjectNode rootComponent = meta.putObject("component");
    rootComponent.put("type", "application");
    rootComponent.put("bom-ref", rootBomRef(root));
    rootComponent.put("group", root.groupId());
    rootComponent.put("name", root.name());
    rootComponent.put("version", root.version());
    rootComponent.put("purl", rootComponent.path("bom-ref").asText());
    ArrayNode outComponents = bom.putArray("components");
    for (ComponentEntry entry : components.values()) {
      outComponents.add(component(entry, trimsByIdentity.get(identity(entry.ref.coordinate()))));
    }
    if (!attestations.isEmpty()) {
      bom.set("vulnerabilities", vulnerabilities(attestations, components, trimsByIdentity));
    }
    return JSON.writeValueAsBytes(bom);
  }

  private static TreeMap<String, ComponentEntry> componentEntries(
      Collection<ArtifactFileRef> inventory, Optional<ElisionDecision> decision) {
    TreeMap<String, ComponentEntry> components = new TreeMap<>();
    Set<ArtifactCoordinate> coordinates = new HashSet<>();
    for (ArtifactFileRef ref : inventory) {
      Objects.requireNonNull(ref, "inventory item must not be null");
      ArtifactCoordinate coordinate = ref.coordinate();
      if (coordinate.version() == null || coordinate.version().isBlank()) {
        throw new IllegalArgumentException("Cannot emit unresolved version for " + coordinate);
      }
      if (decision.isPresent()
          && (!decision.get().isRetained(coordinate) || decision.get().isElided(coordinate))) {
        throw new IllegalArgumentException(
            "Applied retained inventory conflicts with decision for " + coordinate);
      }
      coordinates.add(coordinate);
      String key = identity(coordinate);
      ComponentEntry previous = components.get(key);
      if (previous != null
          && (!previous.ref.filePath().equals(ref.filePath())
              || !previous.ref.coordinate().version().equals(coordinate.version()))) {
        throw new IllegalArgumentException(
            "Conflicting scope variants for artifact identity " + key);
      }
      if (previous == null) {
        components.put(key, new ComponentEntry(ref));
      }
      components.get(key).addScope(coordinate.scope());
    }
    decision.ifPresent(value -> validateDecisionInventory(value, coordinates, components));
    return components;
  }

  private static void validateDecisionInventory(
      ElisionDecision decision,
      Set<ArtifactCoordinate> inventoryCoordinates,
      Map<String, ComponentEntry> components) {
    for (ArtifactCoordinate retained : decision.retainedArtifacts()) {
      if (!inventoryCoordinates.contains(retained)) {
        throw new IllegalArgumentException(
            "Decision retains scope variant missing from applied inventory: " + retained);
      }
    }
    for (ArtifactCoordinate elided : decision.elidedArtifacts()) {
      if (components.containsKey(identity(elided))) {
        throw new IllegalArgumentException("Applied inventory contains elided artifact: " + elided);
      }
    }
  }

  private static ArrayNode vulnerabilities(
      Collection<VexAttestation> attestations,
      Map<String, ComponentEntry> components,
      Map<String, ArtifactTrimRecord> trimsByIdentity) {
    TreeMap<String, VexAttestation> unique = new TreeMap<>();
    for (VexAttestation attestation : attestations) {
      Objects.requireNonNull(attestation, "VEX attestation must not be null");
      requireText(attestation.cveId(), "VEX vulnerability id");
      requireText(attestation.impactDetail(), "VEX impact detail");
      if (!"vulnerable_code_not_present".equals(attestation.justification())) {
        throw new IllegalArgumentException(
            "VEX attestation justification must be vulnerable_code_not_present");
      }
      if (attestation.evidenceSymbols() == null || attestation.evidenceSymbols().isEmpty()) {
        throw new IllegalArgumentException("VEX attestation has no purged symbol evidence");
      }
      String identity = identity(attestation.coordinate());
      ComponentEntry component = components.get(identity);
      ArtifactTrimRecord trim = trimsByIdentity.get(identity);
      if (component == null || trim == null) {
        throw new IllegalArgumentException(
            "VEX attestation does not match a trimmed retained component: " + identity);
      }
      if (!trim.originalSha256().equals(attestation.originalSha256())
          || !trim.trimmedSha256().equals(attestation.trimmedSha256())) {
        throw new IllegalArgumentException(
            "VEX attestation digests do not match trim record: " + identity);
      }
      String key = attestation.cveId() + "\u0000" + componentPurl(attestation.coordinate());
      VexAttestation prior = unique.putIfAbsent(key, attestation);
      if (prior != null && !OpenVexGenerator.sameEvidence(prior, attestation)) {
        throw new IllegalArgumentException("Conflicting duplicate VEX attestation for " + key);
      }
    }
    ArrayNode result = JSON.createArrayNode();
    for (VexAttestation attestation : unique.values()) {
      ObjectNode vulnerability = result.addObject();
      vulnerability.put("id", attestation.cveId());
      ObjectNode analysis = vulnerability.putObject("analysis");
      analysis.put("state", "not_affected");
      analysis.put("justification", "code_not_present");
      analysis.put("detail", attestation.impactDetail());
      vulnerability
          .putArray("affects")
          .addObject()
          .put("ref", componentPurl(attestation.coordinate()));
    }
    return result;
  }

  private static ObjectNode component(ComponentEntry entry, ArtifactTrimRecord trimRecord)
      throws IOException {
    ArtifactCoordinate c = entry.ref.coordinate();
    ObjectNode node = JSON.createObjectNode();
    node.put("type", "library");
    String purl = componentPurl(c);
    node.put("bom-ref", purl);
    node.put("group", c.groupId());
    node.put("name", c.artifactId());
    node.put("version", c.version());
    node.put("purl", purl);
    ArrayNode hashes = node.putArray("hashes");
    hashes.addObject().put("alg", "SHA-256").put("content", sha256(entry.ref.filePath()));
    ArrayNode properties = node.putArray("properties");
    properties.addObject().put("name", "maven:scope").put("value", String.join(",", entry.scopes));
    properties.addObject().put("name", "maven:type").put("value", c.type());
    if (!c.classifier().isEmpty()) {
      properties.addObject().put("name", "maven:classifier").put("value", c.classifier());
    }
    if (trimRecord != null) {
      properties.addObject().put("name", "elider:status").put("value", "trimmed");
      properties
          .addObject()
          .put("name", "elider:retainedClasses")
          .put("value", Integer.toString(trimRecord.retainedClasses()));
      properties
          .addObject()
          .put("name", "elider:totalClasses")
          .put("value", Integer.toString(trimRecord.totalClasses()));
      addPedigree(node, entry, trimRecord);
    }
    return node;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, ArtifactTrimRecord> validateTrimRecords(
      Collection<ArtifactTrimRecord> trimRecords, TreeMap<String, ComponentEntry> components)
      throws IOException {
    Map<String, ArtifactTrimRecord> records = new HashMap<>();
    for (ArtifactTrimRecord record : trimRecords) {
      Objects.requireNonNull(record, "trim record must not be null");
      String key = identity(record.coordinate());
      ComponentEntry component = components.get(key);
      if (component == null) {
        throw new IllegalArgumentException(
            "Trim record has no retained inventory component: " + key);
      }
      if (!component.scopes.contains(record.coordinate().scope())) {
        throw new IllegalArgumentException(
            "Trim record scope is missing from applied inventory: " + key);
      }
      if (records.putIfAbsent(key, record) != null) {
        throw new IllegalArgumentException("Duplicate trim record for artifact identity " + key);
      }
      validateTrimRecord(record, component);
    }
    return records;
  }

  private static void validateTrimRecord(ArtifactTrimRecord record, ComponentEntry component)
      throws IOException {
    Path outputPath = record.trimmedPath().toAbsolutePath().normalize();
    Path inventoryPath = component.ref.filePath().toAbsolutePath().normalize();
    if (!outputPath.equals(inventoryPath)) {
      throw new IllegalArgumentException(
          "Trim record output path does not match retained inventory for "
              + identity(record.coordinate()));
    }
    if (!Files.isRegularFile(record.originalPath()) || !Files.isRegularFile(outputPath)) {
      throw new IOException("Trim record paths must reference regular files");
    }
    if (Files.isSameFile(record.originalPath(), outputPath)) {
      throw new IllegalArgumentException("Trim record output must differ from original artifact");
    }
    if (!record.originalSha256().equals(sha256(record.originalPath()))) {
      throw new IOException("Original artifact digest does not match trim record");
    }
    if (!record.trimmedSha256().equals(sha256(outputPath))) {
      throw new IOException("Trimmed artifact digest does not match trim record");
    }
  }

  private static void addPedigree(
      ObjectNode component, ComponentEntry entry, ArtifactTrimRecord record) throws IOException {
    ObjectNode pedigree = component.putObject("pedigree");
    pedigree.putArray("ancestors").add(originalComponent(entry, record));
    ObjectNode patch = pedigree.putArray("patches").addObject();
    patch.put("type", "unofficial");
    patch
        .putObject("diff")
        .putObject("text")
        .put("contentType", "text/plain")
        .put(
            "content",
            "Trimmed "
                + (record.totalClasses() - record.retainedClasses())
                + " unreferenced classes via ProGuard Core link closure");
  }

  private static ObjectNode originalComponent(ComponentEntry entry, ArtifactTrimRecord record) {
    ArtifactCoordinate coordinate = record.coordinate();
    String purl = componentPurl(coordinate);
    ObjectNode ancestor = JSON.createObjectNode();
    ancestor.put("type", "library");
    ancestor.put("bom-ref", purl + "#original");
    ancestor.put("group", coordinate.groupId());
    ancestor.put("name", coordinate.artifactId());
    ancestor.put("version", coordinate.version());
    ancestor.put("purl", purl);
    ancestor
        .putArray("hashes")
        .addObject()
        .put("alg", "SHA-256")
        .put("content", record.originalSha256());
    ArrayNode properties = ancestor.putArray("properties");
    properties.addObject().put("name", "maven:scope").put("value", String.join(",", entry.scopes));
    properties.addObject().put("name", "maven:type").put("value", coordinate.type());
    if (!coordinate.classifier().isEmpty()) {
      properties.addObject().put("name", "maven:classifier").put("value", coordinate.classifier());
    }
    return ancestor;
  }

  static String componentPurl(ArtifactCoordinate coordinate) {
    return "pkg:maven/"
        + purl(coordinate.groupId())
        + "/"
        + purl(coordinate.artifactId())
        + "@"
        + purl(coordinate.version())
        + purlQualifiers(coordinate);
  }

  static String rootBomRef(RootIdentity root) {
    return "pkg:maven/"
        + purl(root.groupId())
        + "/"
        + purl(root.artifactId())
        + "@"
        + purl(root.version());
  }

  private static void atomicReplace(Path temporary, Path destination) throws IOException {
    Files.move(
        temporary,
        destination,
        StandardCopyOption.ATOMIC_MOVE,
        StandardCopyOption.REPLACE_EXISTING);
  }

  @FunctionalInterface
  interface AtomicReplacer {
    void replace(Path temporary, Path destination) throws IOException;
  }

  static String sha256(Path file) throws IOException {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (var input = Files.newInputStream(file)) {
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) != -1) {
          digest.update(buffer, 0, count);
        }
      }
      return HexFormat.of().formatHex(digest.digest());
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 is unavailable", ex);
    }
  }

  private static String purlQualifiers(ArtifactCoordinate coordinate) {
    StringBuilder qualifiers = new StringBuilder(64);
    if (!coordinate.classifier().isEmpty()) {
      qualifiers.append("?classifier=").append(purl(coordinate.classifier()));
    }
    if (!"jar".equals(coordinate.type())) {
      qualifiers.append(qualifiers.isEmpty() ? "?" : "&");
      qualifiers.append("type=").append(purl(coordinate.type()));
    }
    return qualifiers.toString();
  }

  private static String identity(ArtifactCoordinate c) {
    return c.groupId()
        + ":"
        + c.artifactId()
        + ":"
        + c.version()
        + ":"
        + c.type()
        + ":"
        + c.classifier();
  }

  private static String purl(String value) {
    StringBuilder encoded = new StringBuilder();
    for (byte b : value.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
      int unsigned = b & 0xff;
      char ch = (char) unsigned;
      if (unsigned < 128 && PURL_SAFE.indexOf(ch) >= 0) {
        encoded.append(ch);
      } else {
        encoded
            .append('%')
            .append("0123456789ABCDEF".charAt(unsigned >>> 4))
            .append("0123456789ABCDEF".charAt(unsigned & 15));
      }
    }
    return encoded.toString();
  }

  private static void requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }

  private static final class ComponentEntry {
    private final ArtifactFileRef ref;
    private final java.util.SortedSet<String> scopes = new java.util.TreeSet<>();

    private ComponentEntry(ArtifactFileRef ref) {
      this.ref = ref;
    }

    private void addScope(String scope) {
      scopes.add(scope);
    }
  }
}
