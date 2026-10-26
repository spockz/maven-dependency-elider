/* WHY: Captures exact JDK platform archives once for one analysis context so cache identity and
 * deferred ProGuard loading use the same bytes without sharing mutable class pools. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Owns exact JDK API source snapshots for one analysis operation. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidSynchronizedAtMethodLevel"
})
public final class JdkPlatformContext implements AutoCloseable {
  /** Changes when platform source selection or class-pool interpretation changes. */
  public static final String READER_POLICY_VERSION = "jdk-api-reader-v2";

  /** The first Java release with a supported public API signature set. */
  private static final int MIN_SUPPORTED_RELEASE = 8;

  /** Normalized JDK installation location used by this context. */
  private final Path jdkLocation;

  /** Temporary storage that owns captured bytes until this context closes. */
  private final Path snapshotDirectory;

  /** WHY: Keep deterministic input order while publishing complete snapshots. */
  private final Map<Path, CapturedFile> capturedFiles = new LinkedHashMap<>();

  /** WHY: Pair cache identities and captured bytes under one monitor. */
  private final Map<Integer, PlatformSnapshot> snapshots = new LinkedHashMap<>();

  /** Whether close has released the temporary source copies. */
  private boolean closed;

  /** Creates an invocation-local snapshot owner for the supplied JDK location. */
  public JdkPlatformContext(final Path javaHome) throws IOException {
    this.jdkLocation = normalize(javaHome);
    snapshotDirectory = Files.createTempDirectory("elider-platform-snapshot-");
  }

  /** Captures or returns a release snapshot; bytes remain until context close. */
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  public synchronized PlatformSnapshot snapshot(final int effectiveRelease) throws IOException {
    ensureOpen();
    if (effectiveRelease < MIN_SUPPORTED_RELEASE) {
      throw new IllegalArgumentException("Java release must be at least 8: " + effectiveRelease);
    }
    final PlatformSnapshot previous = snapshots.get(effectiveRelease);
    if (previous != null) {
      return previous;
    }
    final Map<Path, CapturedFile> pending = new LinkedHashMap<>();
    try {
      final PlatformSnapshot captured = captureRelease(effectiveRelease, pending);
      capturedFiles.putAll(pending);
      snapshots.put(effectiveRelease, captured);
      return captured;
    } catch (final IOException | RuntimeException exception) {
      deletePending(pending, exception);
      throw exception;
    }
  }

  /** Returns this context's normalized JDK location. */
  public Path javaHome() {
    return jdkLocation;
  }

  /** Returns the total bytes stored by this context. */
  public synchronized long capturedStorageBytes() {
    return capturedFiles.values().stream().mapToLong(file -> file.identity().size()).sum();
  }

  /** Removes the invocation-owned source copies. */
  @Override
  public synchronized void close() throws IOException {
    if (closed) {
      return;
    }
    closed = true;
    try (java.util.stream.Stream<Path> paths = Files.walk(snapshotDirectory)) {
      IOException failure = null;
      final List<Path> pathsToDelete = paths.sorted(Comparator.reverseOrder()).toList();
      for (final Path path : pathsToDelete) {
        try {
          Files.deleteIfExists(path);
        } catch (final IOException exception) {
          if (failure == null) {
            failure = exception;
          } else {
            failure.addSuppressed(exception);
          }
        }
      }
      if (failure != null) {
        throw failure;
      }
    }
  }

  private PlatformSnapshot captureRelease(final int release, final Map<Path, CapturedFile> pending)
      throws IOException {
    final Path ctSym = jdkLocation.resolve("lib/ct.sym");
    if (!Files.isRegularFile(ctSym)) {
      throw new IOException("The selected JDK does not provide lib/ct.sym: " + ctSym);
    }
    final CapturedFile ctSymFile = capturedFile(ctSym, pending);
    final List<String> signatures =
        PlatformArchiveInspector.selectedSignatures(ctSymFile.snapshotPath(), release);
    if (!signatures.isEmpty()) {
      return new PlatformSnapshot(
          jdkLocation,
          release,
          "ct.sym",
          "signature-count=" + signatures.size(),
          List.of(ctSymFile));
    }

    return captureJmods(release, ctSym, ctSymFile, pending);
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private PlatformSnapshot captureJmods(
      final int release,
      final Path ctSym,
      final CapturedFile ctSymFile,
      final Map<Path, CapturedFile> pending)
      throws IOException {
    final Path releaseFile = jdkLocation.resolve("release");
    if (!Files.isRegularFile(releaseFile)) {
      throw new IOException("No JDK release metadata is available for fallback: " + releaseFile);
    }
    final CapturedFile releaseMetadata = capturedFile(releaseFile, pending);
    final int runtimeRelease =
        PlatformArchiveInspector.readJdkRelease(releaseMetadata.snapshotPath());
    if (runtimeRelease != release) {
      throw new IOException(
          "No JDK API signatures were found for --release "
              + release
              + " in "
              + ctSym
              + "; JMOD fallback is valid only for the running JDK release "
              + runtimeRelease);
    }

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
    final List<CapturedFile> moduleFiles = new ArrayList<>(modules.size());
    final Set<String> classNames = new LinkedHashSet<>();
    int classCount = 0;
    for (final Path module : modules) {
      final CapturedFile captured = capturedFile(module, pending);
      classCount +=
          PlatformArchiveInspector.collectJmodClasses(captured.snapshotPath(), classNames);
      moduleFiles.add(captured);
    }
    if (classCount == 0) {
      throw new IOException("No runtime JDK classes found in " + jmods);
    }
    final List<CapturedFile> sources = new ArrayList<>(moduleFiles.size() + 2);
    sources.add(ctSymFile);
    sources.add(releaseMetadata);
    sources.addAll(moduleFiles);
    return new PlatformSnapshot(
        jdkLocation,
        release,
        "jmods",
        "runtime-release="
            + runtimeRelease
            + ";module-count="
            + moduleFiles.size()
            + ";class-count="
            + classCount,
        sources);
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private CapturedFile capturedFile(final Path source, final Map<Path, CapturedFile> pending)
      throws IOException {
    final Path normalizedSource = normalize(source);
    final CapturedFile existing = capturedFiles.get(normalizedSource);
    if (existing != null) {
      return existing;
    }
    final CapturedFile withinAttempt = pending.get(normalizedSource);
    if (withinAttempt != null) {
      return withinAttempt;
    }
    final Path target = Files.createTempFile(snapshotDirectory, "platform-", ".snapshot");
    try {
      final CapturedFile captured = copyAndDigest(normalizedSource, target);
      pending.put(normalizedSource, captured);
      return captured;
    } catch (final IOException | RuntimeException exception) {
      try {
        Files.deleteIfExists(target);
      } catch (final IOException cleanupException) {
        exception.addSuppressed(cleanupException);
      }
      throw exception;
    }
  }

  private static CapturedFile copyAndDigest(final Path source, final Path target)
      throws IOException {
    final MessageDigest sha256 = digest("SHA-256");
    final MessageDigest sha1 = digest("SHA-1");
    long size = 0;
    try (InputStream input = Files.newInputStream(source);
        OutputStream output = Files.newOutputStream(target)) {
      final byte[] buffer = new byte[64 * 1024];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          break;
        }
        output.write(buffer, 0, count);
        sha256.update(buffer, 0, count);
        sha1.update(buffer, 0, count);
        size += count;
      }
    }
    return new CapturedFile(
        source,
        target,
        new SourceIdentity(
            source,
            HexFormat.of().formatHex(sha256.digest()),
            HexFormat.of().formatHex(sha1.digest()),
            size));
  }

  private void deletePending(
      final Map<Path, CapturedFile> pending, final Exception originalException) {
    for (final CapturedFile captured : pending.values()) {
      try {
        Files.deleteIfExists(captured.snapshotPath());
      } catch (final IOException cleanupException) {
        originalException.addSuppressed(cleanupException);
      }
    }
  }

  private void ensureOpen() {
    if (closed) {
      throw new IllegalStateException("JDK platform context is closed");
    }
  }

  private static Path normalize(final Path path) {
    return java.util.Objects.requireNonNull(path, "javaHome").toAbsolutePath().normalize();
  }

  private static MessageDigest digest(final String algorithm) {
    try {
      return MessageDigest.getInstance(algorithm);
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
          "Required digest algorithm is unavailable: " + algorithm, exception);
    }
  }

  /** Content identity for one captured source archive or release metadata file. */
  public record SourceIdentity(Path sourcePath, String sha256, String sha1, long size) {}

  /** Immutable release selection and source content used for identity and parsing. */
  public static final class PlatformSnapshot {
    /** Normalized JDK installation that supplied this release. */
    private final Path jdkLocationValue;

    /** Effective API release represented by the selected files. */
    private final int releaseValue;

    /** Selected source type used by the deferred reader. */
    private final String sourceKindValue;

    /** Captured source files used by the deferred reader. */
    private final List<CapturedFile> sourceEntries;

    /** Immutable content metadata for all selected source files. */
    private final List<SourceIdentity> identities;

    /** Deterministic cache identity for this exact source selection. */
    private final String identityText;

    private PlatformSnapshot(
        final Path javaHome,
        final int effectiveRelease,
        final String sourceKind,
        final String selectionEvidence,
        final List<CapturedFile> sources) {
      this.jdkLocationValue = javaHome;
      this.releaseValue = effectiveRelease;
      this.sourceKindValue = sourceKind;
      this.sourceEntries = List.copyOf(sources);
      identities = sources.stream().map(CapturedFile::identity).toList();
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
            .append(':')
            .append(identity.sha1())
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

    /** Returns content identities for the selected archives and metadata. */
    public List<SourceIdentity> sourceIdentities() {
      return List.copyOf(new ArrayList<>(identities));
    }

    /** Returns the deterministic content identity used by the trim fingerprint. */
    public String identity() {
      return identityText;
    }

    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    List<CapturedFile> capturedFiles() {
      return sourceEntries;
    }
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record CapturedFile(Path sourcePath, Path snapshotPath, SourceIdentity identity) {}
}
