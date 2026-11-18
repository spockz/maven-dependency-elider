/* WHY: Presents multi-release dependencies as effective classpath inputs for
 * ProGuard closure analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MultiReleaseClassInventory;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
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
      return hasRootModuleDescriptor(archive, original);
    }
  }

  private static boolean hasRootModuleDescriptor(final JarFile archive, final Path original)
      throws IOException {
    final JarEntry descriptor = archive.getJarEntry("module-info.class");
    if (descriptor == null) {
      return false;
    }
    try (InputStream input = archive.getInputStream(descriptor)) {
      validateModuleDescriptor(original, input);
    }
    return true;
  }

  static Set<String> requiredTargetRoots(
      final Path source,
      final ArtifactCoordinate coordinate,
      final Path projectionDirectory,
      final int targetRelease)
      throws IOException {
    final Path targetProjection = create(source, coordinate, projectionDirectory, targetRelease);
    final Set<String> targetClasses = TrimPaths.classNames(targetProjection);
    final MultiReleaseArchivePlan.PluginView view =
        MultiReleaseArchivePlan.create(source, targetRelease, Set.of(), Set.of()).pluginView();
    final Set<String> viewClasses = dottedNames(view.targetPresentClasses());
    if (!viewClasses.equals(targetClasses)) {
      throw new IOException("MRJAR target projection and archive plan disagree for " + coordinate);
    }
    return dottedNames(view.requiredRootClasses());
  }

  private static Set<String> dottedNames(final Set<String> names) {
    return names.stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
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
            TrimPaths.coordinateFilePrefix(coordinate) + "-release-" + release + "-analysis.jar");
    try (JarFile input =
        new JarFile(
            normalizedOriginal.toFile(),
            false,
            ZipFile.OPEN_READ,
            Runtime.Version.parse(Integer.toString(release)))) {
      final boolean hasVersionedEntry =
          input.stream().anyMatch(entry -> entry.getName().startsWith(VERSIONS_PREFIX));
      if (!hasVersionedEntry && !hasRootModuleDescriptor(input, normalizedOriginal)) {
        return normalizedOriginal;
      }
      Files.createDirectories(normalizedOutputDirectory);
      try (JarOutputStream output =
          new JarOutputStream(
              Files.newOutputStream(
                  projection,
                  StandardOpenOption.CREATE,
                  StandardOpenOption.TRUNCATE_EXISTING,
                  StandardOpenOption.WRITE))) {
        final Set<String> outputNames = new HashSet<>();
        final byte[] copyBuffer = new byte[8192];
        for (final JarEntry entry : input.versionedStream().toList()) {
          copyEffectiveClass(input, output, normalizedOriginal, entry, outputNames, copyBuffer);
        }
      }
    }
    return projection;
  }

  private static void copyEffectiveClass(
      final JarFile input,
      final JarOutputStream output,
      final Path original,
      final JarEntry entry,
      final Set<String> outputNames,
      final byte[] copyBuffer)
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
      while (true) {
        final int read = classBytes.read(copyBuffer);
        if (read == -1) {
          break;
        }
        output.write(copyBuffer, 0, read);
      }
    }
    output.closeEntry();
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
