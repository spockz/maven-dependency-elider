/* WHY: Presents multi-release dependencies as effective classpath inputs
 * for ProGuard closure analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;

/** Builds effective classpath inputs for ProGuard. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseLibraryProjection {
  private static final String VERSIONS_PREFIX = "META-INF/versions/";
  private static final String CLASS_SUFFIX = ".class";

  private MultiReleaseLibraryProjection() {}

  static boolean hasRootModuleDescriptor(final Path original) throws IOException {
    try (JarFile archive = new JarFile(original.toFile())) {
      final JarEntry descriptor = archive.getJarEntry("module-info.class");
      if (descriptor == null) {
        return false;
      }
      try (InputStream input = archive.getInputStream(descriptor)) {
        validateModuleDescriptor(original, input);
      }
      return true;
    }
  }

  static Path create(
      final Path original,
      final ArtifactCoordinate coordinate,
      final Path outputDirectory,
      final int release)
      throws IOException {
    final Path normalizedOriginal = original.toAbsolutePath().normalize();
    final Path normalizedOutputDirectory = outputDirectory.toAbsolutePath().normalize();
    final Path projection =
        normalizedOutputDirectory.resolve(
            safe(coordinate.groupId())
                + "-"
                + safe(coordinate.artifactId())
                + "-"
                + safe(coordinate.version())
                + (coordinate.classifier().isBlank() ? "" : "-" + safe(coordinate.classifier()))
                + "-release-"
                + release
                + "-analysis.jar");
    Files.createDirectories(normalizedOutputDirectory);
    try (JarFile input =
            new JarFile(
                normalizedOriginal.toFile(),
                false,
                ZipFile.OPEN_READ,
                Runtime.Version.parse(Integer.toString(release)));
        JarOutputStream output =
            new JarOutputStream(
                Files.newOutputStream(
                    projection,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE))) {
      final boolean hasVersionedEntry =
          input.stream().anyMatch(entry -> entry.getName().startsWith(VERSIONS_PREFIX));
      final Set<String> outputNames = new HashSet<>();
      final java.util.Iterator<JarEntry> entries = input.versionedStream().iterator();
      while (entries.hasNext()) {
        copyEffectiveClass(input, output, normalizedOriginal, entries.next(), outputNames);
      }
      if (!hasVersionedEntry && !hasRootModuleDescriptor(normalizedOriginal)) {
        Files.deleteIfExists(projection);
        return normalizedOriginal;
      }
    }
    return projection;
  }

  private static void copyEffectiveClass(
      final JarFile input,
      final JarOutputStream output,
      final Path original,
      final JarEntry entry,
      final Set<String> outputNames)
      throws IOException {
    if (entry.isDirectory() || !entry.getName().endsWith(CLASS_SUFFIX)) {
      return;
    }
    final String logicalName = MultiReleaseClassInventory.logicalClassName(entry.getName());
    if (MultiReleaseClassInventory.isModuleDescriptor(logicalName)) {
      try (InputStream moduleBytes = input.getInputStream(entry)) {
        validateModuleDescriptor(original, moduleBytes);
      }
      return;
    }
    if (!outputNames.add(logicalName)) {
      throw new IOException(
          "Multi-release projection contains duplicate effective class " + logicalName);
    }
    output.putNextEntry(new JarEntry(logicalName));
    try (InputStream classBytes = input.getInputStream(entry)) {
      classBytes.transferTo(output);
    }
    output.closeEntry();
  }

  private static String safe(final String value) {
    return value.replaceAll("[^A-Za-z0-9._-]", "_");
  }

  private static void validateModuleDescriptor(final Path original, final InputStream input)
      throws IOException {
    final ClassReader reader = new ClassReader(input);
    if (!"module-info".equals(reader.getClassName())
        || (reader.getAccess() & Opcodes.ACC_MODULE) == 0) {
      throw new IOException("Invalid module-info.class in classpath JAR: " + original);
    }
  }
}
