/* WHY: Builds the physical JAR shapes used to compare goal predictions with published output. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

/** Builds small physical archives for end-to-end runtime-evidence scenarios. */
final class RuntimeEvidenceArchiveFixture {
  /** Root module descriptor entry name used by the classpath-only fixture. */
  private static final String MODULE_CLASS = "module-info";

  /** Prefix used to normalize classes from effective upper MRJAR tiers. */
  private static final String VERSIONED_PREFIX = "META-INF/versions/";

  private RuntimeEvidenceArchiveFixture() {}

  /** Each upper entry needs a fresh ZIP member. */
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  /* default */ static Path addUpperOnlyClass(final Path source, final Path output)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarFile input = new JarFile(source.toFile());
        JarOutputStream jar = new JarOutputStream(Files.newOutputStream(output), manifest)) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory() || "closure/b/Unused.class".equals(entry.getName())) {
          continue;
        }
        jar.putNextEntry(new JarEntry(entry.getName()));
        try (InputStream content = input.getInputStream(entry)) {
          content.transferTo(jar);
        }
        jar.closeEntry();
      }
      jar.putNextEntry(new JarEntry("META-INF/versions/17/closure/b/Unused.class"));
      try (JarFile original = new JarFile(source.toFile());
          InputStream content =
              original.getInputStream(original.getJarEntry("closure/b/Unused.class"))) {
        content.transferTo(jar);
      }
      jar.closeEntry();
    }
    return output;
  }

  /* default */ static Path compileJar(
      final Path temporaryDirectory,
      final String name,
      final Map<String, String> sources,
      final Path classpath,
      final int release)
      throws IOException {
    final Path jar = temporaryDirectory.resolve(name);
    return io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        jar, temporaryDirectory.resolve(name + "-src"), sources, classpath, release);
  }

  /** Each resource entry needs a distinct mutable ZIP member. */
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  /* default */ static Path mergedJar(
      final Path base,
      final Path additions,
      final Path output,
      final Map<String, String> resources,
      final String additionPrefix)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (additionPrefix != null) {
      manifest.getMainAttributes().putValue("Multi-Release", "true");
    }
    try (JarFile baseArchive = new JarFile(base.toFile());
        JarFile additionArchive = new JarFile(additions.toFile());
        JarOutputStream jar =
            additionPrefix == null
                ? new JarOutputStream(Files.newOutputStream(output))
                : new JarOutputStream(Files.newOutputStream(output), manifest)) {
      copyEntries(baseArchive, jar, "");
      copyEntries(additionArchive, jar, additionPrefix == null ? "" : additionPrefix);
      for (final Map.Entry<String, String> resource : resources.entrySet()) {
        jar.putNextEntry(new JarEntry(resource.getKey()));
        jar.write(resource.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        jar.closeEntry();
      }
    }
    return output;
  }

  /* default */ static Set<String> classNames(final Path archivePath) throws IOException {
    final Set<String> names = new java.util.TreeSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        String name = entries.nextElement().getName();
        if (!name.endsWith(".class")) {
          continue;
        }
        if (name.startsWith(VERSIONED_PREFIX)) {
          name = name.substring(name.indexOf('/', VERSIONED_PREFIX.length()) + 1);
        }
        names.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
      }
    }
    return Set.copyOf(names);
  }

  /* default */ static Path addRootModuleInfo(final Path input, final Path output)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V9, Opcodes.ACC_MODULE, MODULE_CLASS, null, null, null);
    final ModuleVisitor module = writer.visitModule("fixture.a", 0, null);
    module.visitRequire("java.base", 0, null);
    module.visitExport("closure/a", 0);
    module.visitEnd();
    writer.visitEnd();
    try (JarFile inputJar = new JarFile(input.toFile());
        JarOutputStream outputJar = new JarOutputStream(Files.newOutputStream(output))) {
      copyEntries(inputJar, outputJar, "");
      outputJar.putNextEntry(new JarEntry(MODULE_CLASS + ".class"));
      outputJar.write(writer.toByteArray());
      outputJar.closeEntry();
    }
    return output;
  }

  /** Each ZIP entry needs a fresh mutable metadata object for sequential writing. */
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static void copyEntries(
      final JarFile source, final JarOutputStream destination, final String prefix)
      throws IOException {
    final Enumeration<JarEntry> entries = source.entries();
    while (entries.hasMoreElements()) {
      final JarEntry entry = entries.nextElement();
      if (entry.isDirectory()) {
        continue;
      }
      destination.putNextEntry(new JarEntry(prefix + entry.getName()));
      try (InputStream content = source.getInputStream(entry)) {
        content.transferTo(destination);
      }
      destination.closeEntry();
    }
  }
}
