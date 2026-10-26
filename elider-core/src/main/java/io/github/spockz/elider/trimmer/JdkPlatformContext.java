/* WHY: Captures exact JDK platform identities once per analysis context so cache fingerprints
 * and deferred platform reads share release and source-selection evidence. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Owns invocation-scoped identities for selected JDK API sources. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidSynchronizedAtMethodLevel"
})
public final class JdkPlatformContext implements AutoCloseable {
  /** Changes when platform source selection or class-pool interpretation changes. */
  public static final String READER_POLICY_VERSION = "jdk-api-reader-v4";

  /** The first Java release with a supported public API signature set. */
  private static final int MIN_SUPPORTED_RELEASE = 8;

  /** Normalized JDK installation location used by this context. */
  private final Path jdkLocation;

  /** Reuses source hashes across release snapshots. */
  private final Map<Path, SourceIdentity> capturedSources = new LinkedHashMap<>();

  /** Publishes each release only after selection and hashing complete. */
  private final Map<Integer, PlatformSnapshot> snapshots = new LinkedHashMap<>();

  /** Prevents snapshot use after an explicit owner releases its identities. */
  private boolean closed;

  /** Creates an identity owner for the supplied JDK location. */
  public JdkPlatformContext(final Path javaHome) {
    this.jdkLocation = normalize(javaHome);
  }

  /** Captures or returns source identities for one effective API release. */
  public synchronized PlatformSnapshot snapshot(final int effectiveRelease) throws IOException {
    ensureOpen();
    if (effectiveRelease < MIN_SUPPORTED_RELEASE) {
      throw new IllegalArgumentException("Java release must be at least 8: " + effectiveRelease);
    }
    final PlatformSnapshot previous = snapshots.get(effectiveRelease);
    if (previous != null) {
      return previous;
    }
    final Map<Path, SourceIdentity> pending = new LinkedHashMap<>();
    final PlatformSnapshot captured = captureRelease(effectiveRelease, pending);
    capturedSources.putAll(pending);
    snapshots.put(effectiveRelease, captured);
    return captured;
  }

  /** Returns this context's normalized JDK location. */
  public Path javaHome() {
    return jdkLocation;
  }

  /** Releases identities for standalone owners. */
  @Override
  public synchronized void close() {
    closed = true;
    snapshots.clear();
    capturedSources.clear();
  }

  private PlatformSnapshot captureRelease(
      final int release, final Map<Path, SourceIdentity> pending) throws IOException {
    final Path ctSym = jdkLocation.resolve("lib/ct.sym");
    if (!Files.isRegularFile(ctSym)) {
      throw new IOException("The selected JDK does not provide lib/ct.sym: " + ctSym);
    }
    final SourceIdentity ctSymSource = sourceIdentity(ctSym, pending);
    final List<String> signatures = PlatformArchiveInspector.selectedSignatures(ctSym, release);
    if (!signatures.isEmpty()) {
      return new PlatformSnapshot(
          jdkLocation,
          release,
          "ct.sym",
          "signature-count=" + signatures.size() + ";release-code=" + releaseCode(release),
          List.of(ctSymSource));
    }

    return captureJmods(release, ctSym, ctSymSource, pending);
  }

  private PlatformSnapshot captureJmods(
      final int release,
      final Path ctSym,
      final SourceIdentity ctSymSource,
      final Map<Path, SourceIdentity> pending)
      throws IOException {
    final SourceIdentity releaseMetadata = captureReleaseMetadata(release, ctSym, pending);
    final List<Path> modules = selectedJmods(release);
    final List<SourceIdentity> sources = moduleSources(modules, pending);
    sources.addFirst(releaseMetadata);
    sources.addFirst(ctSymSource);
    return new PlatformSnapshot(
        jdkLocation, release, "jmods", jmodSelection(release, modules), sources);
  }

  private SourceIdentity captureReleaseMetadata(
      final int release, final Path ctSym, final Map<Path, SourceIdentity> pending)
      throws IOException {
    final Path releaseFile = jdkLocation.resolve("release");
    if (!Files.isRegularFile(releaseFile)) {
      throw new IOException("No JDK release metadata is available for fallback: " + releaseFile);
    }
    final SourceIdentity releaseMetadata = sourceIdentity(releaseFile, pending);
    final int runtimeRelease = PlatformArchiveInspector.readJdkRelease(releaseFile);
    if (runtimeRelease != release) {
      throw new IOException(
          "No JDK API signatures were found for --release "
              + release
              + " in "
              + ctSym
              + "; JMOD fallback is valid only for the running JDK release "
              + runtimeRelease);
    }
    return releaseMetadata;
  }

  private List<Path> selectedJmods(final int release) throws IOException {
    final Path jmods = jdkLocation.resolve("jmods");
    if (!Files.isDirectory(jmods)) {
      throw new IOException("The selected JDK has no jmods directory: " + jmods);
    }
    final List<Path> modules;
    try (java.util.stream.Stream<Path> modulePaths = Files.list(jmods)) {
      modules = modulePaths.filter(PlatformArchiveInspector::isJmod).sorted().toList();
    }
    if (modules.isEmpty()) {
      throw new IOException("No JDK platform signatures found for release " + release);
    }
    return modules;
  }

  private List<SourceIdentity> moduleSources(
      final List<Path> modules, final Map<Path, SourceIdentity> pending) throws IOException {
    final List<SourceIdentity> moduleSources = new ArrayList<>(modules.size());
    for (final Path module : modules) {
      moduleSources.add(sourceIdentity(module, pending));
    }
    return moduleSources;
  }

  private static String jmodSelection(final int release, final List<Path> modules) {
    return "runtime-release="
        + release
        + ";module-count="
        + modules.size()
        + ";modules="
        + modules.stream()
            .map(JdkPlatformContext::moduleName)
            .collect(java.util.stream.Collectors.joining(","));
  }

  private static String moduleName(final Path module) {
    return java.util.Objects.requireNonNull(module.getFileName(), "JMOD path has no filename")
        .toString();
  }

  private SourceIdentity sourceIdentity(final Path source, final Map<Path, SourceIdentity> pending)
      throws IOException {
    final Path normalizedSource = normalize(source);
    final SourceIdentity existing = capturedSources.get(normalizedSource);
    if (existing != null) {
      return existing;
    }
    final SourceIdentity withinAttempt = pending.get(normalizedSource);
    if (withinAttempt != null) {
      return withinAttempt;
    }
    final SourceIdentity captured = digestSource(normalizedSource);
    pending.put(normalizedSource, captured);
    return captured;
  }

  private static SourceIdentity digestSource(final Path source) throws IOException {
    final MessageDigest sha256 = digest();
    long size = 0;
    final byte[] buffer = new byte[64 * 1024];
    try (InputStream input = Files.newInputStream(source)) {
      while (true) {
        final int read = input.read(buffer);
        if (read < 0) {
          break;
        }
        sha256.update(buffer, 0, read);
        size += read;
      }
    }
    return new SourceIdentity(source, HexFormat.of().formatHex(sha256.digest()), size);
  }

  private static Path normalize(final Path path) {
    return java.util.Objects.requireNonNull(path, "javaHome").toAbsolutePath().normalize();
  }

  private void ensureOpen() {
    if (closed) {
      throw new IllegalStateException("JDK platform context is closed");
    }
  }

  private static MessageDigest digest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("Required SHA-256 digest is unavailable", exception);
    }
  }

  private static String releaseCode(final int release) {
    return release <= 9
        ? Integer.toString(release)
        : Character.toString((char) ('A' + release - 10));
  }

  /** Exact content identity for one selected source, without retaining archive bytes. */
  public record SourceIdentity(Path sourcePath, String sha256, long size) {}

  /** Immutable release selection and source identities for one analysis context. */
  public static final class PlatformSnapshot {
    /** Normalized JDK installation that supplied this release. */
    private final Path jdkLocationValue;

    /** Effective API release represented by the selected files. */
    private final int releaseValue;

    /** Selected source type used by the deferred reader. */
    private final String sourceKindValue;

    /** Immutable content metadata for all selected source files. */
    private final List<SourceIdentity> identities;

    /** Deterministic cache identity for this exact source selection. */
    private final String identityText;

    private PlatformSnapshot(
        final Path javaHome,
        final int effectiveRelease,
        final String sourceKind,
        final String selectionEvidence,
        final List<SourceIdentity> sources) {
      this.jdkLocationValue = javaHome;
      this.releaseValue = effectiveRelease;
      this.sourceKindValue = sourceKind;
      identities = List.copyOf(sources);
      final StringBuilder value =
          new StringBuilder(128)
              .append("jdk-platform=")
              .append(javaHome)
              .append("\nreader=")
              .append(READER_POLICY_VERSION)
              .append("\nrelease=")
              .append(effectiveRelease)
              .append("\nsource-kind=")
              .append(sourceKind)
              .append("\nselection=")
              .append(selectionEvidence)
              .append('\n');
      for (int index = 0; index < identities.size(); index++) {
        final SourceIdentity identity = identities.get(index);
        value
            .append("source[")
            .append(index)
            .append("]=")
            .append(identity.sourcePath())
            .append(':')
            .append(identity.size())
            .append(':')
            .append(identity.sha256())
            .append('\n');
      }
      identityText = value.toString();
    }

    /** Returns the JDK location and selected API release. */
    public Path javaHome() {
      return jdkLocationValue;
    }

    /** Returns the effective API release represented by this snapshot. */
    public int effectiveRelease() {
      return releaseValue;
    }

    /** Returns the selected platform source format. */
    public String sourceKind() {
      return sourceKindValue;
    }

    /** Returns path-bound SHA-256 identities for selected archives and metadata. */
    public List<SourceIdentity> sourceIdentities() {
      return identities;
    }

    /** Returns the deterministic content identity used by the trim fingerprint. */
    public String identity() {
      return identityText;
    }
  }
}
