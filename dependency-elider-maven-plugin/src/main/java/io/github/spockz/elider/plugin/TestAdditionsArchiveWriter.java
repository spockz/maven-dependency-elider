/* WHY: Writes a repeatable test overlay after rejecting archive features it cannot preserve. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.MultiReleaseClassInventory;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;

/** Prepares the class-only archive used by test execution. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.GodClass",
  "PMD.TestClassWithoutTestCases",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidLiteralsInIfCondition"
})
final class TestAdditionsArchiveWriter {
  private static final String CLASS_SUFFIX = ".class";
  private static final String MANIFEST = "META-INF/MANIFEST.MF";
  private static final String VERSIONED = "META-INF/versions/";

  private TestAdditionsArchiveWriter() {}

  record Inventory(
      TestAdditionsAnalyzer.ArtifactInput input,
      Set<String> classes,
      Set<String> resources,
      String unsupported) {}

  static List<Inventory> inspect(final List<TestAdditionsAnalyzer.ArtifactInput> inputs)
      throws IOException {
    final List<Inventory> inventories = new ArrayList<>(inputs.size());
    final Set<String> identities = new HashSet<>();
    for (final TestAdditionsAnalyzer.ArtifactInput input : inputs) {
      if (!identities.add(input.identity())) {
        throw new IOException("Duplicate allowed original artifact identity: " + input.identity());
      }
      inventories.add(read(input));
    }
    return List.copyOf(inventories);
  }

  static Set<String> classNames(final Path archive) throws IOException {
    return readArchive(archive).classes();
  }

  static Optional<String> changedResource(final Inventory original, final Path effective)
      throws IOException {
    final Set<String> effectiveResources = readArchive(effective).resources();
    for (final String name : new TreeSet<>(original.resources())) {
      if (!effectiveResources.contains(name)) {
        return Optional.of(name);
      }
    }
    for (final String name : new TreeSet<>(effectiveResources)) {
      if (!original.resources().contains(name)) {
        return Optional.of(name);
      }
    }
    try (JarFile source = new JarFile(original.input().originalJar().toFile());
        JarFile runtime = new JarFile(effective.toFile())) {
      for (final String name : new TreeSet<>(original.resources())) {
        try (InputStream sourceBytes = source.getInputStream(source.getJarEntry(name));
            InputStream runtimeBytes = runtime.getInputStream(runtime.getJarEntry(name))) {
          if (!Arrays.equals(sourceBytes.readAllBytes(), runtimeBytes.readAllBytes())) {
            return Optional.of(name);
          }
        }
      }
    }
    return Optional.empty();
  }

  static IOException changedResource(final Inventory original, final String name) {
    return new IOException(
        "Changed-path test artifact has a resource requiring a complete test view: "
            + original.input().identity()
            + "!"
            + name);
  }

  static void verifyServiceProviderView(
      final List<Inventory> originals,
      final Map<String, Integer> originalOwners,
      final Map<String, Integer> runtimeOwners,
      final Map<String, Set<String>> additions)
      throws IOException {
    final Set<String> added = new TreeSet<>();
    additions.values().forEach(added::addAll);
    for (final Inventory original : originals) {
      if (original.resources().stream().noneMatch(name -> name.startsWith("META-INF/services/"))) {
        continue;
      }
      final Optional<Path> effective = original.input().effectiveRuntimeJar();
      if (effective.isEmpty()
          || Files.isSameFile(original.input().originalJar(), effective.orElseThrow())) {
        continue;
      }
      for (final DependencyDynamicRoots.ServiceDescriptor descriptor :
          DependencyDynamicRoots.scan(effective.orElseThrow()).serviceDescriptors()) {
        for (final String provider : descriptor.providers()) {
          final String name = provider.replace('.', '/');
          if (originalOwners.containsKey(name)
              && !runtimeOwners.containsKey(name)
              && !added.contains(name)) {
            throw changedResource(original, "META-INF/services/" + descriptor.serviceInterface());
          }
        }
      }
    }
  }

  private static Inventory read(final TestAdditionsAnalyzer.ArtifactInput input)
      throws IOException {
    final ArchiveContents contents = readArchive(input.originalJar());
    return new Inventory(input, contents.classes(), contents.resources(), contents.unsupported());
  }

  private static ArchiveContents readArchive(final Path archivePath) throws IOException {
    if (!Files.isRegularFile(archivePath) || !archivePath.toString().endsWith(".jar")) {
      throw new IOException("Test artifact is not a regular JAR: " + archivePath);
    }
    final Set<String> names = new HashSet<>();
    final Set<String> classes = new TreeSet<>();
    final Set<String> resources = new TreeSet<>();
    String unsupported = "";
    try (JarFile archive =
        new JarFile(archivePath.toFile(), false, ZipFile.OPEN_READ, Runtime.version())) {
      final Manifest manifest = archive.getManifest();
      if (manifest != null) {
        unsupported = unsupportedManifest(manifest);
      }
      for (final JarEntry entry : archive.stream().toList()) {
        final String name = entry.getName();
        if (!names.add(name)) {
          throw new IOException(
              "Duplicate physical test artifact entry: " + archivePath + "!" + name);
        }
        if (entry.isDirectory()) {
          continue;
        }
        if ("module-info.class".equals(name) || name.startsWith(VERSIONED)) {
          unsupported = "modular or multi-release archive";
          continue;
        }
        if (signatureEntry(name)) {
          unsupported = "signed archive";
          continue;
        }
        if (MANIFEST.equalsIgnoreCase(name) || name.startsWith("META-INF/maven/")) {
          continue;
        }
        if (!name.endsWith(CLASS_SUFFIX)) {
          resources.add(name);
        }
      }
      for (final JarEntry entry : archive.versionedStream().toList()) {
        final String name = entry.getName();
        if (entry.isDirectory() || !name.endsWith(CLASS_SUFFIX)) {
          continue;
        }
        if (!archive.isMultiRelease() && name.startsWith(VERSIONED)) {
          continue;
        }
        final String logical = MultiReleaseClassInventory.logicalClassName(name);
        if (!"module-info.class".equals(logical)) {
          classes.add(logical.substring(0, logical.length() - CLASS_SUFFIX.length()));
        }
      }
    }
    return new ArchiveContents(Set.copyOf(classes), Set.copyOf(resources), unsupported);
  }

  private static String unsupportedManifest(final Manifest manifest) {
    if (!manifest.getEntries().isEmpty()) {
      return "named package manifest attributes";
    }
    if ("true".equalsIgnoreCase(manifest.getMainAttributes().getValue(Attributes.Name.SEALED))) {
      return "sealed package manifest";
    }
    for (final Object key : manifest.getMainAttributes().keySet()) {
      final String name = key.toString();
      if (!"Manifest-Version".equalsIgnoreCase(name)
          && !"Created-By".equalsIgnoreCase(name)
          && !"Build-Jdk-Spec".equalsIgnoreCase(name)
          && !"Java-Version".equalsIgnoreCase(name)) {
        return "classpath-relevant manifest attributes";
      }
    }
    return "";
  }

  private static boolean signatureEntry(final String name) {
    if (!name.regionMatches(true, 0, "META-INF/", 0, "META-INF/".length())) {
      return false;
    }
    final String upper = name.toUpperCase(java.util.Locale.ROOT);
    return upper.endsWith(".SF")
        || upper.endsWith(".RSA")
        || upper.endsWith(".DSA")
        || upper.endsWith(".EC")
        || upper.startsWith("META-INF/SIG-");
  }

  static void write(
      final Path output,
      final List<Inventory> originals,
      final Map<String, Set<String>> addedClassesByArtifact)
      throws IOException {
    final Path parent = output.getParent();
    if (parent == null) {
      throw new IOException("Test additions JAR has no parent: " + output);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".test-additions-", ".jar");
    boolean published = false;
    try {
      try (JarOutputStream result = new JarOutputStream(Files.newOutputStream(temporary))) {
        final Set<String> written = new HashSet<>();
        for (final Inventory inventory : originals) {
          final Set<String> selected = addedClassesByArtifact.get(inventory.input().identity());
          if (selected == null || selected.isEmpty()) {
            continue;
          }
          if (!inventory.unsupported().isEmpty()) {
            throw new IOException(
                "Test artifact needs a complete test view for "
                    + inventory.unsupported()
                    + ": "
                    + inventory.input().identity());
          }
          try (JarFile source = new JarFile(inventory.input().originalJar().toFile())) {
            for (final String internalName : new TreeSet<>(selected)) {
              final String entryName = internalName + CLASS_SUFFIX;
              if (!written.add(entryName)) {
                throw new IOException("Duplicate test addition class: " + entryName);
              }
              final JarEntry original = source.getJarEntry(entryName);
              if (original == null || original.isDirectory()) {
                throw new IOException(
                    "Missing selected original class: "
                        + inventory.input().identity()
                        + "!"
                        + entryName);
              }
              final JarEntry entry = new JarEntry(entryName);
              entry.setTime(0L);
              result.putNextEntry(entry);
              try (InputStream bytes = source.getInputStream(original)) {
                bytes.transferTo(result);
              }
              result.closeEntry();
            }
          }
        }
      }
      Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
      published = true;
    } finally {
      if (!published) {
        Files.deleteIfExists(temporary);
      }
    }
  }

  private record ArchiveContents(Set<String> classes, Set<String> resources, String unsupported) {}
}
