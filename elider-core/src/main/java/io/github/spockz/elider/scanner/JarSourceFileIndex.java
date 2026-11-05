/* WHY: Reads class SourceFile attributes without treating them as complete source attribution. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;

/** Immutable SourceFile metadata read from one unchanged JAR. */
public record JarSourceFileIndex(String archiveSha256, List<ClassSourceFile> classFiles) {
  /** Prefix whose entries are versioned according to the MRJAR manifest flag. */
  private static final String MR_PREFIX = "META-INF/versions/";

  /** Manifest attribute that enables versioned class entries. */
  private static final String MULTI_RELEASE_ATTRIBUTE = "Multi-Release";

  /** Minimum class-file version allowed in the MRJAR versions directory. */
  private static final int MIN_MULTI_RELEASE_VERSION = 9;

  /** Records the relationship between a class file and its source file attribute. */
  public record ClassSourceFile(
      String physicalJarEntry,
      String classEntry,
      int multiReleaseTier,
      String sourceFile,
      Set<MethodIdentity> declaredMethods) {
    /** Compact constructor. */
    public ClassSourceFile {
      declaredMethods = declaredMethods == null ? Set.of() : Set.copyOf(declaredMethods);
    }

    /**
     * Creates a class source file without declared methods.
     *
     * @param physicalJarEntry physical jar entry path
     * @param classEntry class entry name
     * @param multiReleaseTier MRJAR version
     * @param sourceFile SourceFile attribute
     */
    public ClassSourceFile(
        final String physicalJarEntry,
        final String classEntry,
        final int multiReleaseTier,
        final String sourceFile) {
      this(physicalJarEntry, classEntry, multiReleaseTier, sourceFile, Set.of());
    }
  }

  /** One method name and its JVM descriptor. */
  public record MethodIdentity(String name, String descriptor)
      implements Comparable<MethodIdentity> {
    /** Validates the class-file method identity. */
    public MethodIdentity {
      Objects.requireNonNull(name, "name");
      Objects.requireNonNull(descriptor, "descriptor");
      if (name.isBlank() || descriptor.isBlank()) {
        throw new IllegalArgumentException("method name and descriptor must not be blank");
      }
    }

    @Override
    public int compareTo(final MethodIdentity other) {
      final int nameOrder = name.compareTo(other.name);
      return nameOrder == 0 ? descriptor.compareTo(other.descriptor) : nameOrder;
    }
  }

  /** Keeps a physical entry path separate from its logical class name. */
  private record EntryIdentity(String internalClassName, int multiReleaseTier) {}

  /** Freezes scan results and verifies the archive digest format. */
  public JarSourceFileIndex {
    Objects.requireNonNull(archiveSha256, "archiveSha256");
    if (!archiveSha256.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("archiveSha256 must be a lowercase SHA-256");
    }
    classFiles = List.copyOf(classFiles);
  }

  /** Reads metadata and digest for this archive. */
  public static JarSourceFileIndex read(final Path path) throws IOException {
    final ArtifactDigests digest = ArtifactDigests.read(path);
    final List<ClassSourceFile> classes = readClassFiles(path);
    classes.sort(Comparator.comparing(ClassSourceFile::physicalJarEntry));
    return new JarSourceFileIndex(digest.sha256(), classes);
  }

  private static List<ClassSourceFile> readClassFiles(final Path path) throws IOException {
    final List<ClassSourceFile> classes = new ArrayList<>();
    final Set<String> physicalEntryNames = new HashSet<>();
    try (ZipFile archive = new ZipFile(path.toFile())) {
      final boolean multiRelease = isMultiRelease(archive);
      final Enumeration<? extends ZipEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        if (!physicalEntryNames.add(entry.getName())) {
          throw new IOException("duplicate physical ZIP entry: " + entry.getName());
        }
        if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
          continue;
        }
        readClassFile(archive, entry, multiRelease).ifPresent(classes::add);
      }
    }
    return classes;
  }

  private static java.util.Optional<ClassSourceFile> readClassFile(
      final ZipFile archive, final ZipEntry entry, final boolean multiRelease) throws IOException {
    final EntryIdentity identity = entryIdentity(entry.getName(), multiRelease);
    if (identity == null || "module-info".equals(identity.internalClassName())) {
      return java.util.Optional.empty();
    }
    try (InputStream input = archive.getInputStream(entry)) {
      final ClassReader reader = new ClassReader(input);
      final String internalName = reader.getClassName();
      if (!identity.internalClassName().equals(internalName)) {
        throw new IOException("Class entry path does not match class-file identity");
      }
      final String[] sourceFile = {null};
      final Set<MethodIdentity> declaredMethods = new HashSet<>();
      reader.accept(
          new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visitSource(final String source, final String debug) {
              sourceFile[0] = source;
            }

            @Override
            public org.objectweb.asm.MethodVisitor visitMethod(
                final int access,
                final String name,
                final String descriptor,
                final String signature,
                final String[] exceptions) {
              declaredMethods.add(new MethodIdentity(name, descriptor));
              return null;
            }
          },
          ClassReader.SKIP_CODE | ClassReader.SKIP_FRAMES);
      return java.util.Optional.of(
          new ClassSourceFile(
              entry.getName(),
              internalName.replace('/', '.'),
              identity.multiReleaseTier(),
              sourceFile[0],
              declaredMethods));
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException("Could not read class-file source metadata", exception);
    }
  }

  private static boolean isMultiRelease(final ZipFile archive) throws IOException {
    final ZipEntry manifestEntry = archive.getEntry("META-INF/MANIFEST.MF");
    if (manifestEntry == null) {
      return false;
    }
    try (InputStream manifestInput = archive.getInputStream(manifestEntry)) {
      final String value =
          new Manifest(manifestInput).getMainAttributes().getValue(MULTI_RELEASE_ATTRIBUTE);
      return "true".equalsIgnoreCase(value);
    }
  }

  private static EntryIdentity entryIdentity(final String physicalPath, final boolean multiRelease)
      throws IOException {
    final boolean versionedPath = physicalPath.startsWith(MR_PREFIX);
    if (versionedPath && !multiRelease) {
      return null;
    }
    final int tier = versionedPath ? multiReleaseTier(physicalPath) : 0;
    final String logicalPath = versionedPath ? logicalPath(physicalPath) : physicalPath;
    if (!logicalPath.endsWith(".class")) {
      return null;
    }
    final String internalName = logicalPath.substring(0, logicalPath.length() - 6);
    if (internalName.isBlank()) {
      throw new IOException("Malformed class entry identity");
    }
    return new EntryIdentity(internalName, tier);
  }

  private static int multiReleaseTier(final String physicalPath) throws IOException {
    final int versionEnd = physicalPath.indexOf('/', MR_PREFIX.length());
    if (versionEnd < 0 || versionEnd == physicalPath.length() - 1) {
      throw new IOException("Malformed multi-release class entry path");
    }
    final String versionText = physicalPath.substring(MR_PREFIX.length(), versionEnd);
    return requireSupportedTier(parseCanonicalTier(versionText));
  }

  private static int parseCanonicalTier(final String versionText) throws IOException {
    if (!versionText.matches("[1-9][0-9]*")) {
      throw new IOException("Non-canonical multi-release class entry version");
    }
    try {
      return Integer.parseInt(versionText);
    } catch (final NumberFormatException exception) {
      throw new IOException("Invalid multi-release class entry version", exception);
    }
  }

  private static int requireSupportedTier(final int tier) throws IOException {
    if (tier < MIN_MULTI_RELEASE_VERSION) {
      throw new IOException("multi-release class entry version must be at least 9");
    }
    return tier;
  }

  private static String logicalPath(final String physicalPath) {
    final int versionEnd = physicalPath.indexOf('/', MR_PREFIX.length());
    return physicalPath.substring(versionEnd + 1);
  }
}
