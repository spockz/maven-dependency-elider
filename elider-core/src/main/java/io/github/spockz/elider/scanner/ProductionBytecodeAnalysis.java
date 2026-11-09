/* WHY: Binds bytecode and ServiceLoader evidence to one validated production-output snapshot. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

/** Captures production class bytes once for all analysis passes. */
@SuppressWarnings({"PMD.TooManyMethods", "PMD.CyclomaticComplexity", "PMD.CommentSize"})
public final class ProductionBytecodeAnalysis {
  /** WHY: Keeps cache identities stable across output generations. */
  private static final byte[] FINGERPRINT_VERSION =
      "production-output-v2".getBytes(StandardCharsets.UTF_8);

  private ProductionBytecodeAnalysis() {
    throw new AssertionError("No instances");
  }

  /** Holds bytes across scans so all evidence uses one output version. */
  public static final class Snapshot {
    /** Immutable digest for the captured class paths and bytes. */
    private final String fingerprintValue;

    /** Direct symbolic references parsed from the captured bytes. */
    private final BytecodeReferenceScan referenceScan;

    /** Logical class names derived from the captured relative paths. */
    private final Set<String> productionClassNames;

    /** Captured class files retained for the later global ServiceLoader passes. */
    private final List<ClassFile> classFiles;

    private Snapshot(
        final String fingerprint,
        final BytecodeReferenceScan bytecodeReferences,
        final Set<String> classNames,
        final List<ClassFile> classFiles) {
      this.fingerprintValue = fingerprint;
      this.referenceScan = bytecodeReferences;
      this.productionClassNames = Set.copyOf(classNames);
      this.classFiles = classFiles;
    }

    /** Returns the fingerprint bound to this snapshot's paths and contents. */
    public String fingerprint() {
      return fingerprintValue;
    }

    /** Returns direct-reference evidence from this snapshot. */
    public BytecodeReferenceScan bytecodeReferences() {
      return referenceScan;
    }

    /** Returns production class names from this snapshot. */
    public Set<String> classNames() {
      return productionClassNames;
    }

    /** Scans ServiceLoader calls from captured bytes in their original walk order. */
    public ServiceLoaderCallScanner.ScanResult scanServiceLoaderCalls() throws IOException {
      return ServiceLoaderCallScanner.scanCaptured(classFiles);
    }
  }

  /** Captures classes once for direct and later evidence scans. */
  public static Snapshot capture(final Path productionOutput) throws IOException {
    return capture(productionOutput, List.of());
  }

  /**
   * Captures classes across primary production output and additional class directories (e.g. Spring
   * AOT).
   */
  public static Snapshot capture(final Path productionOutput, final List<Path> additionalOutputs)
      throws IOException {
    final Path scope = productionOutput.toAbsolutePath().normalize();
    final boolean missingScope = Files.notExists(scope);
    if (!missingScope && !Files.isDirectory(scope)) {
      throw new IOException("Production class output path is not a directory: " + scope);
    }
    final List<Path> additionalRoots = existingAdditionalRoots(additionalOutputs);
    final List<Path> roots = fingerprintRoots(scope, additionalRoots);
    final List<ClassFile> classFiles = captureClassFiles(scope, missingScope, additionalRoots);
    final List<ClassFile> sortedFiles =
        classFiles.stream().sorted(Comparator.comparing(ClassFile::path)).toList();
    final Set<String> references = scanReferences(sortedFiles);
    final Set<String> classNames = productionClassNames(classFiles, scope, additionalRoots);
    final BytecodeReferenceScan referenceScan =
        new BytecodeReferenceScan(scope, references, classFiles.size(), true);
    return new Snapshot(
        fingerprintCapturedFiles(roots, sortedFiles), referenceScan, classNames, classFiles);
  }

  private static List<Path> existingAdditionalRoots(final List<Path> additionalOutputs) {
    final List<Path> roots = new ArrayList<>();
    for (final Path additional : additionalOutputs) {
      final Path normalized = additional.toAbsolutePath().normalize();
      if (Files.isDirectory(normalized)) {
        roots.add(normalized);
      }
    }
    return List.copyOf(roots);
  }

  private static List<Path> fingerprintRoots(final Path scope, final List<Path> additionalRoots) {
    final List<Path> roots = new ArrayList<>(additionalRoots.size() + 1);
    roots.add(scope);
    roots.addAll(additionalRoots);
    return List.copyOf(roots);
  }

  private static List<ClassFile> captureClassFiles(final Path scope) throws IOException {
    final List<ClassFile> classFiles = new ArrayList<>();
    try (Stream<Path> paths = Files.walk(scope)) {
      final Iterator<Path> iterator = paths.iterator();
      while (iterator.hasNext()) {
        final Path path = iterator.next();
        if (Files.isRegularFile(path) && isClassFile(path)) {
          classFiles.add(new ClassFile(path, Files.readAllBytes(path)));
        }
      }
    }
    return List.copyOf(classFiles);
  }

  private static List<ClassFile> captureClassFiles(
      final Path scope, final boolean missingScope, final List<Path> additionalRoots)
      throws IOException {
    final List<ClassFile> classFiles = new ArrayList<>();
    if (!missingScope) {
      classFiles.addAll(captureClassFiles(scope));
    }
    for (final Path additional : additionalRoots) {
      classFiles.addAll(captureClassFiles(additional));
    }
    return List.copyOf(classFiles);
  }

  private static Set<String> scanReferences(final List<ClassFile> classFiles) throws IOException {
    final Set<String> references = new java.util.HashSet<>();
    for (final ClassFile classFile : classFiles) {
      ProductionBytecodeReferenceScanner.scanClassFile(
          classFile.path(), classFile.content(), references);
    }
    return references;
  }

  private static Set<String> productionClassNames(
      final List<ClassFile> classFiles, final Path scope, final List<Path> additionalRoots) {
    final Set<String> classNames = new TreeSet<>();
    for (final ClassFile classFile : classFiles) {
      final Path root = outputRoot(classFile.path(), scope, additionalRoots);
      final String relativePath = root.relativize(classFile.path()).toString().replace('\\', '/');
      if (!"module-info.class".equals(relativePath)
          && !relativePath.endsWith("/module-info.class")) {
        classNames.add(
            TraceData.normalizeToDot(
                relativePath.substring(0, relativePath.length() - ".class".length())));
      }
    }
    return classNames;
  }

  private static Path outputRoot(
      final Path classFile, final Path scope, final List<Path> additionalRoots) {
    for (final Path root : additionalRoots) {
      if (classFile.startsWith(root)) {
        return root;
      }
    }
    return scope;
  }

  /** Computes the versioned fingerprint by rereading the current production output. */
  public static String fingerprint(final Path output) throws IOException {
    return fingerprint(output, List.of());
  }

  /** Computes the versioned fingerprint by rereading current production outputs. */
  public static String fingerprint(final Path output, final List<Path> additionalOutputs)
      throws IOException {
    final Path scope = output.toAbsolutePath().normalize();
    final boolean missingScope = Files.notExists(scope);
    if (!missingScope && !Files.isDirectory(scope)) {
      throw new IOException("Production class output path is not a directory: " + scope);
    }
    final List<Path> roots = new ArrayList<>();
    roots.add(scope);
    for (final Path additional : additionalOutputs) {
      final Path normalized = additional.toAbsolutePath().normalize();
      if (Files.isDirectory(normalized)) {
        roots.add(normalized);
      }
    }
    final List<Path> classes = new ArrayList<>();
    for (final Path root : roots) {
      if (Files.notExists(root)) {
        continue;
      }
      if (!Files.isDirectory(root)) {
        throw new IOException("Production class output path is not a directory: " + root);
      }
      try (Stream<Path> paths = Files.walk(root)) {
        classes.addAll(
            paths
                .filter(Files::isRegularFile)
                .filter(ProductionBytecodeAnalysis::isClassFile)
                .toList());
      }
    }
    classes.sort(Comparator.naturalOrder());
    final MessageDigest digest = startFingerprint();
    for (final Path classFile : classes) {
      final Path root = roots.stream().filter(classFile::startsWith).findFirst().orElse(scope);
      updateFingerprint(digest, root, classFile, Files.readAllBytes(classFile));
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static String fingerprintCapturedFiles(
      final List<Path> roots, final List<ClassFile> classFiles) {
    final MessageDigest digest = startFingerprint();
    final Path primaryScope = roots.getFirst();
    for (final ClassFile classFile : classFiles) {
      final Path root =
          roots.stream().filter(classFile.path()::startsWith).findFirst().orElse(primaryScope);
      updateFingerprint(digest, root, classFile.path(), classFile.content());
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static MessageDigest startFingerprint() {
    final MessageDigest digest = sha256();
    digest.update(FINGERPRINT_VERSION);
    return digest;
  }

  private static void updateFingerprint(
      final MessageDigest digest, final Path scope, final Path path, final byte[] content) {
    final byte[] relativePath =
        scope.relativize(path).toString().replace('\\', '/').getBytes(StandardCharsets.UTF_8);
    updateLength(digest, relativePath.length);
    digest.update(relativePath);
    updateLength(digest, content.length);
    digest.update(content);
  }

  private static void updateLength(final MessageDigest digest, final int length) {
    digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(length).array());
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static boolean isClassFile(final Path path) {
    final Path fileName = path.getFileName();
    return fileName != null && fileName.toString().endsWith(".class");
  }

  /* package */ record ClassFile(Path path, byte[] content) {}
}
