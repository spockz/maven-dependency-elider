/* WHY: Builds focused JARs that expose SourceFile and MRJAR indexing edge cases. */

package io.github.spockz.elider.scanner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Generates small class archives for scanner tests without invoking a compiler. */
public final class JarSourceFileFixtures {
  /** Manifest entry path used to activate MRJAR version tiers. */
  private static final String MANIFEST_PATH = "META-INF/MANIFEST.MF";

  private JarSourceFileFixtures() {
    throw new AssertionError("Utility class");
  }

  /** The default access modifier shares generated archives with same-package tests. */
  public static void writeArchive(
      final Path path, final boolean multiRelease, final String sourceFile) throws IOException {
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      add(output, MANIFEST_PATH, manifestBytes(multiRelease));
      addClass(output, "org/example/Outer.class", "org/example/Outer", sourceFile);
      addClass(output, "org/example/Helper.class", "org/example/Helper", sourceFile);
      addClass(output, "org/example/Outer$1.class", "org/example/Outer$1", sourceFile);
      addClass(
          output, "META-INF/versions/17/org/example/Outer.class", "org/example/Outer", sourceFile);
      addClass(output, "org/other/Outer.class", "org/other/Outer", sourceFile);
      addClass(output, "org/other/WithoutSource.class", "org/other/WithoutSource", null);
    }
  }

  /** Writes an MRJAR containing a class under the supplied textual tier. */
  public static void writeArchiveWithVersionEntry(final Path path, final String tierText)
      throws IOException {
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      add(output, MANIFEST_PATH, manifestBytes(true));
      addClass(
          output,
          "META-INF/versions/" + tierText + "/org/example/Outer.class",
          "org/example/Outer",
          "Outer.java");
    }
  }

  private static byte[] manifestBytes(final boolean multiRelease) throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (multiRelease) {
      manifest.getMainAttributes().putValue("Multi-Release", "true");
    }
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    manifest.write(output);
    return output.toByteArray();
  }

  private static void addClass(
      final ZipOutputStream output,
      final String entryPath,
      final String internalName,
      final String sourceFile)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    if (sourceFile != null) {
      writer.visitSource(sourceFile, null);
    }
    writer.visitEnd();
    add(output, entryPath, writer.toByteArray());
  }

  private static void add(final ZipOutputStream output, final String path, final byte[] bytes)
      throws IOException {
    output.putNextEntry(new ZipEntry(path));
    output.write(bytes);
    output.closeEntry();
  }
}
