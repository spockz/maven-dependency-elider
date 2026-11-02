/* WHY: Binds bytecode and ServiceLoader evidence to one validated production-output snapshot. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
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
    final Path scope = productionOutput.toAbsolutePath().normalize();
    if (!Files.isDirectory(scope)) {
      throw new IOException("Production class output directory is missing: " + scope);
    }
    final List<ClassFile> classFiles = captureClassFiles(scope);
    final List<ClassFile> sortedFiles =
        classFiles.stream().sorted(Comparator.comparing(ClassFile::path)).toList();
    final Set<String> references = new java.util.HashSet<>();
    for (final ClassFile classFile : sortedFiles) {
      ProductionBytecodeReferenceScanner.scanClassFile(
          classFile.path(), classFile.content(), references);
    }
    final Set<String> classNames = new TreeSet<>();
    for (final ClassFile classFile : classFiles) {
      final String relativePath = scope.relativize(classFile.path()).toString().replace('\\', '/');
      if (!"module-info.class".equals(relativePath)
          && !relativePath.endsWith("/module-info.class")) {
        classNames.add(
            TraceData.normalizeToDot(
                relativePath.substring(0, relativePath.length() - ".class".length())));
      }
    }
    final BytecodeReferenceScan referenceScan =
        new BytecodeReferenceScan(scope, references, classFiles.size(), true);
    return new Snapshot(
        fingerprintCapturedFiles(scope, sortedFiles), referenceScan, classNames, classFiles);
  }

  /** Computes the versioned fingerprint by rereading the current production output. */
  public static String fingerprint(final Path output) throws IOException {
    final Path scope = output.toAbsolutePath().normalize();
    if (!Files.isDirectory(scope)) {
      throw new IOException("Production class output directory is missing: " + scope);
    }
    final List<Path> classes;
    try (Stream<Path> paths = Files.walk(scope)) {
      classes =
          paths
              .filter(Files::isRegularFile)
              .filter(ProductionBytecodeAnalysis::isClassFile)
              .sorted()
              .toList();
    }
    final MessageDigest digest = startFingerprint();
    for (final Path classFile : classes) {
      updateFingerprint(digest, scope, classFile, Files.readAllBytes(classFile));
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static List<ClassFile> captureClassFiles(final Path scope) throws IOException {
    final List<ClassFile> classFiles = new ArrayList<>();
    try (Stream<Path> paths = Files.walk(scope)) {
      final Iterator<Path> iterator = paths.iterator();
      while (iterator.hasNext()) {
        final Path path = iterator.next();
        final BasicFileAttributes attributes =
            Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attributes.isSymbolicLink()) {
          throw new IOException("Symbolic link in production class output: " + path);
        }
        if (attributes.isRegularFile() && isClassFile(path)) {
          classFiles.add(new ClassFile(path, Files.readAllBytes(path)));
        }
      }
    }
    return List.copyOf(classFiles);
  }

  private static String fingerprintCapturedFiles(
      final Path scope, final List<ClassFile> classFiles) {
    final MessageDigest digest = startFingerprint();
    for (final ClassFile classFile : classFiles) {
      updateFingerprint(digest, scope, classFile.path(), classFile.content());
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
