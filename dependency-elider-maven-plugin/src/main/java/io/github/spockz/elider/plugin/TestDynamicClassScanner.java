/* WHY: Finds dynamic class-loading calls that symbolic bytecode references cannot close. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AsciiBinaryClassName;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Scans direct literal reflection and ServiceLoader calls. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.TestClassWithoutTestCases"
})
final class TestDynamicClassScanner {
  private TestDynamicClassScanner() {}

  record ScanResult(Set<String> literalNames, Set<String> unresolvedDynamicCalls) {
    ScanResult {
      literalNames = Set.copyOf(literalNames);
      unresolvedDynamicCalls = Set.copyOf(unresolvedDynamicCalls);
    }
  }

  static ScanResult scanDirectory(final Path directory) throws IOException {
    final Set<String> names = new TreeSet<>();
    final Set<String> unresolved = new TreeSet<>();
    try (Stream<Path> paths = Files.walk(directory)) {
      for (final Path path : paths.filter(Files::isRegularFile).sorted().toList()) {
        if (path.toString().endsWith(".class")) {
          final String className =
              directory
                  .relativize(path)
                  .toString()
                  .replace('\\', '/')
                  .replaceFirst("\\.class$", "");
          scan(Files.readAllBytes(path), className, names, unresolved);
        }
      }
    }
    return new ScanResult(names, unresolved);
  }

  static ScanResult scanArchiveClasses(final Path archive, final Set<String> classes)
      throws IOException {
    final Set<String> names = new TreeSet<>();
    final Set<String> unresolved = new TreeSet<>();
    try (JarFile jar = new JarFile(archive.toFile())) {
      for (final String className : new TreeSet<>(classes)) {
        final String entryName = className + ".class";
        final JarEntry entry = jar.getJarEntry(entryName);
        if (entry == null) {
          throw new IOException("Selected test class is missing from analysis view: " + entryName);
        }
        try (java.io.InputStream input = jar.getInputStream(entry)) {
          scan(input.readAllBytes(), className, names, unresolved);
        }
      }
    }
    return new ScanResult(names, unresolved);
  }

  private static void scan(
      final byte[] bytes,
      final String source,
      final Set<String> names,
      final Set<String> unresolved)
      throws IOException {
    try {
      new ClassReader(bytes)
          .accept(
              new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(
                    final int access,
                    final String name,
                    final String descriptor,
                    final String signature,
                    final String[] exceptions) {
                  return new LiteralLoadVisitor(source, names, unresolved);
                }
              },
              ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Cannot scan reflective class roots in " + source, exception);
    }
  }

  @SuppressWarnings({"PMD.TooManyMethods", "PMD.NPathComplexity"})
  private static final class LiteralLoadVisitor extends MethodVisitor {
    private final String source;
    private final Set<String> names;
    private final Set<String> unresolved;
    private String pending = "";

    LiteralLoadVisitor(final String source, final Set<String> names, final Set<String> unresolved) {
      super(Opcodes.ASM9);
      this.source = source;
      this.names = names;
      this.unresolved = unresolved;
    }

    @Override
    public void visitLdcInsn(final Object value) {
      pending = value instanceof String literal ? literal : "";
    }

    @Override
    public void visitMethodInsn(
        final int opcode,
        final String owner,
        final String name,
        final String descriptor,
        final boolean isInterface) {
      final boolean reflective =
          (opcode == Opcodes.INVOKESTATIC
                  && "java/lang/Class".equals(owner)
                  && "forName".equals(name))
              || (opcode == Opcodes.INVOKEVIRTUAL
                  && "java/lang/ClassLoader".equals(owner)
                  && "loadClass".equals(name));
      final boolean serviceLoader =
          opcode == Opcodes.INVOKESTATIC
              && "java/util/ServiceLoader".equals(owner)
              && ("load".equals(name) || "loadInstalled".equals(name));
      if (reflective) {
        if ("(Ljava/lang/String;)Ljava/lang/Class;".equals(descriptor)
            && !pending.isEmpty()
            && AsciiBinaryClassName.isFullyQualified(pending)) {
          names.add(pending);
        } else {
          unresolved.add(source);
        }
      } else if (serviceLoader) {
        unresolved.add(source);
      }
      pending = "";
    }

    @Override
    public void visitInsn(final int opcode) {
      pending = "";
    }

    @Override
    public void visitIntInsn(final int opcode, final int operand) {
      pending = "";
    }

    @Override
    public void visitVarInsn(final int opcode, final int varIndex) {
      pending = "";
    }

    @Override
    public void visitTypeInsn(final int opcode, final String type) {
      pending = "";
    }

    @Override
    public void visitFieldInsn(
        final int opcode, final String owner, final String name, final String descriptor) {
      pending = "";
    }

    @Override
    public void visitInvokeDynamicInsn(
        final String name,
        final String descriptor,
        final Handle bootstrapMethodHandle,
        final Object... bootstrapMethodArguments) {
      pending = "";
    }

    @Override
    public void visitJumpInsn(final int opcode, final Label label) {
      pending = "";
    }

    @Override
    public void visitLabel(final Label label) {
      pending = "";
    }

    @Override
    public void visitIincInsn(final int varIndex, final int increment) {
      pending = "";
    }

    @Override
    public void visitTableSwitchInsn(
        final int min, final int max, final Label dflt, final Label... labels) {
      pending = "";
    }

    @Override
    public void visitLookupSwitchInsn(final Label dflt, final int[] keys, final Label[] labels) {
      pending = "";
    }

    @Override
    public void visitMultiANewArrayInsn(final String descriptor, final int numDimensions) {
      pending = "";
    }
  }
}
