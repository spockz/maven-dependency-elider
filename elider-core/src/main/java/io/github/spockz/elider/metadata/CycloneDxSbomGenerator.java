// WHY: Emits an inventory of the artifacts Maven actually retained after whole-artifact elision.

package io.github.spockz.elider.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Objects;
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
  "PMD.CyclomaticComplexity",
  "PMD.ConsecutiveAppendsShouldReuse",
  "PMD.LawOfDemeter",
  "PMD.LocalVariableCouldBeFinal",
  "PMD.LooseCoupling",
  "PMD.MethodArgumentCouldBeFinal",
  "PMD.ShortVariable",
  "PMD.UseExplicitTypes"
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
    Objects.requireNonNull(output, "output must not be null");
    byte[] bytes = generate(root, appliedRetainedInventory, decision, metadata);
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
    Objects.requireNonNull(root, "root must not be null");
    Objects.requireNonNull(inventory, "inventory must not be null");
    Objects.requireNonNull(decision, "decision must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    TreeMap<String, ComponentEntry> components = new TreeMap<>();
    Set<ArtifactCoordinate> inventoryCoordinates = new HashSet<>();
    for (ArtifactFileRef ref : inventory) {
      Objects.requireNonNull(ref, "inventory item must not be null");
      ArtifactCoordinate coordinate = ref.coordinate();
      if (coordinate.version() == null || coordinate.version().isBlank()) {
        throw new IllegalArgumentException("Cannot emit unresolved version for " + coordinate);
      }
      if (!decision.isRetained(coordinate) || decision.isElided(coordinate)) {
        throw new IllegalArgumentException(
            "Applied retained inventory conflicts with decision for " + coordinate);
      }
      inventoryCoordinates.add(coordinate);
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
    rootComponent.put(
        "bom-ref",
        "pkg:maven/"
            + purl(root.groupId())
            + "/"
            + purl(root.artifactId())
            + "@"
            + purl(root.version()));
    rootComponent.put("group", root.groupId());
    rootComponent.put("name", root.name());
    rootComponent.put("version", root.version());
    rootComponent.put("purl", rootComponent.path("bom-ref").asText());
    ArrayNode outComponents = bom.putArray("components");
    for (ComponentEntry entry : components.values()) {
      outComponents.add(component(entry));
    }
    return JSON.writeValueAsBytes(bom);
  }

  private static ObjectNode component(ComponentEntry entry) throws IOException {
    ArtifactCoordinate c = entry.ref.coordinate();
    ObjectNode node = JSON.createObjectNode();
    node.put("type", "library");
    String purl =
        "pkg:maven/"
            + purl(c.groupId())
            + "/"
            + purl(c.artifactId())
            + "@"
            + purl(c.version())
            + purlQualifiers(c);
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
    return node;
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

  private static String sha256(Path file) throws IOException {
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
