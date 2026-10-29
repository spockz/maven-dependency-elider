/* WHY: Makes the declared class-provider boundary explicit and digest-bound for VEX proofs. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Immutable declared Maven class-provider inventory used by precondition proof. */
@SuppressWarnings("PMD.TooManyMethods")
public final class PreconditionClassInventory {
  /** Sort key keeps fingerprints stable across equivalent provider declarations. */
  private static final Comparator<Provider> PROVIDER_ORDER =
      Comparator.comparing((Provider provider) -> provider.kind().name())
          .thenComparing(
              provider -> provider.coordinate() == null ? "" : exactIdentity(provider.coordinate()))
          .thenComparing(provider -> provider.path().toString());

  /** Explicit inventory completeness state. */
  private final Status inventoryStatus;

  /** Immutable providers included in the proof boundary. */
  private final List<Provider> declaredProviders;

  /** Reason an inventory is incomplete or inspection failed. */
  private final String failureDetail;

  /** Fingerprint of the provider boundary and state. */
  private final String inventoryFingerprint;

  /** Distinguishes a complete declaration from missing or failed inspection. */
  public enum Status {
    COMPLETE,
    INCOMPLETE,
    INSPECTION_FAILED
  }

  /** Identifies whether a file belongs to a dependency or application input. */
  public enum ProviderKind {
    DEPENDENCY_ARCHIVE,
    APPLICATION_CLASS_FILE,
    APPLICATION_RESOURCE_FILE,
    APPLICATION_SOURCE_FILE
  }

  /** Exact path and digest for one declared class/resource provider. */
  public record Provider(
      ProviderKind kind,
      ArtifactCoordinate coordinate,
      Path path,
      String sha256,
      Set<String> discoveredClassNames) {
    /** Validates provider identity and normalizes the immutable file reference. */
    public Provider {
      Objects.requireNonNull(kind, "kind");
      if (kind == ProviderKind.DEPENDENCY_ARCHIVE) {
        Objects.requireNonNull(coordinate, "dependency provider coordinate");
      } else if (coordinate != null) {
        throw new IllegalArgumentException("Application providers must not have Maven coordinates");
      }
      path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
      requireSha256(sha256);
      Objects.requireNonNull(discoveredClassNames, "discoveredClassNames");
      discoveredClassNames = Set.copyOf(discoveredClassNames);
      if (kind == ProviderKind.APPLICATION_SOURCE_FILE) {
        final Set<String> canonicalClassNames = new TreeSet<>();
        for (final String className : discoveredClassNames) {
          if (!VulnerabilitySymbolMapping.isValidFullyQualifiedClassName(className)) {
            throw new IllegalArgumentException(
                "discoveredClassNames must contain fully qualified class names");
          }
          canonicalClassNames.add(className);
        }
        discoveredClassNames = Set.copyOf(canonicalClassNames);
      } else if (!discoveredClassNames.isEmpty()) {
        throw new IllegalArgumentException(
            "Only application source providers may supply scanner-derived class names");
      }
    }

    /** Captures a retained dependency archive and its exact Maven identity. */
    public static Provider dependencyArchive(final ArtifactCoordinate coordinate, final Path path)
        throws IOException {
      return capture(ProviderKind.DEPENDENCY_ARCHIVE, coordinate, path, Set.of());
    }

    /** Captures one declared application class file for content inspection. */
    public static Provider applicationClassFile(final Path path) throws IOException {
      return capture(ProviderKind.APPLICATION_CLASS_FILE, null, path, Set.of());
    }

    /** Captures a resource for class-byte or embedded-archive inspection. */
    public static Provider applicationResourceFile(final Path path) throws IOException {
      return capture(ProviderKind.APPLICATION_RESOURCE_FILE, null, path, Set.of());
    }

    /** Captures source bytes with class names from the configured scanner. */
    public static Provider applicationSourceFile(
        final Path path, final Set<String> discoveredClassNames) throws IOException {
      return capture(
          ProviderKind.APPLICATION_SOURCE_FILE,
          null,
          path,
          Objects.requireNonNull(discoveredClassNames, "discoveredClassNames"));
    }

    private static Provider capture(
        final ProviderKind kind,
        final ArtifactCoordinate coordinate,
        final Path path,
        final Set<String> discoveredClassNames)
        throws IOException {
      final Path realPath = Objects.requireNonNull(path, "path").toRealPath();
      if (!Files.isRegularFile(realPath)) {
        throw new IOException("Class provider is not a regular file: " + realPath);
      }
      return new Provider(
          kind,
          coordinate,
          realPath,
          ArtifactDigests.read(realPath).sha256(),
          discoveredClassNames);
    }
  }

  private PreconditionClassInventory(
      final Status status, final Collection<Provider> providers, final String detail) {
    this.inventoryStatus = Objects.requireNonNull(status, "status");
    Objects.requireNonNull(providers, "providers");
    final List<Provider> ordered = new ArrayList<>(providers.size());
    for (final Provider provider : providers) {
      ordered.add(Objects.requireNonNull(provider, "provider"));
    }
    ordered.sort(PROVIDER_ORDER);
    validateUniqueProviders(ordered);
    this.declaredProviders = List.copyOf(ordered);
    if (status == Status.COMPLETE) {
      if (detail != null && !detail.isBlank()) {
        throw new IllegalArgumentException("A complete inventory must not have failure detail");
      }
      this.failureDetail = null;
    } else {
      if (detail == null || detail.isBlank()) {
        throw new IllegalArgumentException("Incomplete inventories require a reason");
      }
      this.failureDetail = detail;
    }
    this.inventoryFingerprint =
        computeFingerprint(status, this.declaredProviders, this.failureDetail);
  }

  /**
   * Caller lists all dependency, source, class, and resource providers.
   *
   * <p>Source names are scanner-derived and bound to captured bytes.
   */
  public static PreconditionClassInventory complete(final Collection<Provider> providers) {
    return new PreconditionClassInventory(Status.COMPLETE, providers, null);
  }

  /** Records a provider list that is known to be incomplete. */
  public static PreconditionClassInventory incomplete(
      final Collection<Provider> knownProviders, final String reason) {
    return new PreconditionClassInventory(Status.INCOMPLETE, knownProviders, reason);
  }

  /** Records a provider inspection failure separately from unknown inventory inputs. */
  public static PreconditionClassInventory inspectionFailed(
      final Collection<Provider> knownProviders, final String reason) {
    return new PreconditionClassInventory(Status.INSPECTION_FAILED, knownProviders, reason);
  }

  /** Returns the explicit inventory state. */
  public Status status() {
    return inventoryStatus;
  }

  /** Returns the immutable, deterministic provider list. */
  public List<Provider> providers() {
    return declaredProviders;
  }

  /** Returns why inventory collection was incomplete or failed, if applicable. */
  public String detail() {
    return failureDetail;
  }

  /** Returns the SHA-256 fingerprint of the declared inventory and its state. */
  public String fingerprint() {
    return inventoryFingerprint;
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static String exactIdentity(final ArtifactCoordinate coordinate) {
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier()
        + ":"
        + coordinate.version();
  }

  private static void validateUniqueProviders(final List<Provider> providers) {
    final Set<Path> paths = new HashSet<>();
    final Set<String> dependencyIdentities = new HashSet<>();
    for (final Provider provider : providers) {
      if (!paths.add(provider.path())) {
        throw new IllegalArgumentException("Duplicate class provider path: " + provider.path());
      }
      if (provider.kind() == ProviderKind.DEPENDENCY_ARCHIVE
          && !dependencyIdentities.add(exactIdentity(provider.coordinate()))) {
        throw new IllegalArgumentException(
            "Duplicate retained dependency provider: " + provider.coordinate().toId());
      }
    }
  }

  private static String computeFingerprint(
      final Status status, final List<Provider> providers, final String detail) {
    try {
      final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (DataOutputStream output = new DataOutputStream(bytes)) {
        output.writeUTF(status.name());
        output.writeInt(providers.size());
        for (final Provider provider : providers) {
          output.writeUTF(provider.kind().name());
          output.writeUTF(
              provider.coordinate() == null ? "" : exactIdentity(provider.coordinate()));
          output.writeUTF(provider.path().toString());
          output.writeUTF(provider.sha256());
          final List<String> discoveredClasses =
              provider.discoveredClassNames().stream().sorted().toList();
          output.writeInt(discoveredClasses.size());
          for (final String className : discoveredClasses) {
            output.writeUTF(className);
          }
        }
        output.writeUTF(detail == null ? "" : detail);
      }
      final byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
      return HexFormat.of().formatHex(digest);
    } catch (final IOException exception) {
      throw new IllegalStateException("Could not fingerprint class inventory", exception);
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static void requireSha256(final String value) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("sha256 must be a lowercase SHA-256 digest");
    }
  }
}
