/* WHY: Validates MRJAR class paths, tiers, and API surfaces separately from archive planning. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Reads class names and public API shapes from physical archive entries. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseClassFile {
  private static final int API_ACCESS = Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED;

  private MultiReleaseClassFile() {}

  static MultiReleaseArchivePlan.ClassVariant read(
      final JarFile archive, final JarEntry entry, final String logicalPath, final int release)
      throws IOException {
    final ClassReader reader;
    try (InputStream input = archive.getInputStream(entry)) {
      reader = new ClassReader(input);
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException("Could not read class entry: " + entry.getName(), exception);
    }
    final String className = reader.getClassName();
    if (!(className + MultiReleaseArchivePlan.CLASS_SUFFIX).equals(logicalPath)) {
      throw new IOException(
          "Class entry path does not match its declared name: " + entry.getName());
    }
    final int visibility = reader.getAccess() & API_ACCESS;
    final int majorVersion = reader.readUnsignedShort(6);
    if (release > 0 && majorVersion > release + 44) {
      throw new IOException("Versioned class file exceeds its release: " + entry.getName());
    }
    return new MultiReleaseArchivePlan.ClassVariant(
        className,
        entry.getName(),
        release,
        reader.getAccess(),
        visibility,
        majorVersion,
        apiShape(reader));
  }

  static void validateRelease(final MultiReleaseArchivePlan.ClassVariant variant)
      throws IOException {
    if (variant.majorVersion() > variant.release() + 44) {
      throw new IOException("Versioned class file exceeds its release: " + variant.entryName());
    }
  }

  private static MultiReleaseArchivePlan.ApiShape apiShape(final ClassReader reader) {
    final ApiShapeBuilder builder = new ApiShapeBuilder();
    reader.accept(
        builder, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    return builder.build();
  }

  private static final class ApiShapeBuilder extends ClassVisitor {
    private String header;
    private final List<String> members = new ArrayList<>();
    private final List<String> records = new ArrayList<>();

    private ApiShapeBuilder() {
      super(Opcodes.ASM9);
    }

    @Override
    public void visit(
        final int version,
        final int access,
        final String name,
        final String signature,
        final String superName,
        final String[] interfaces) {
      final List<String> interfaceNames = List.of(interfaces);
      header = access + ":" + name + ":" + signature + ":" + superName + ":" + interfaceNames;
    }

    @Override
    public FieldVisitor visitField(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final Object value) {
      if ((access & API_ACCESS) != 0) {
        members.add("F:" + access + ":" + name + ":" + descriptor + ":" + signature + ":" + value);
      }
      return null;
    }

    @Override
    public MethodVisitor visitMethod(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final String[] exceptions) {
      if ((access & API_ACCESS) != 0) {
        final List<String> exceptionNames = exceptions == null ? List.of() : List.of(exceptions);
        members.add(
            "M:" + access + ":" + name + ":" + descriptor + ":" + signature + ":" + exceptionNames);
      }
      return null;
    }

    @Override
    public org.objectweb.asm.RecordComponentVisitor visitRecordComponent(
        final String name, final String descriptor, final String signature) {
      records.add(name + ":" + descriptor + ":" + signature);
      return null;
    }

    private MultiReleaseArchivePlan.ApiShape build() {
      members.sort(Comparator.naturalOrder());
      records.sort(Comparator.naturalOrder());
      return new MultiReleaseArchivePlan.ApiShape(
          header, List.copyOf(members), List.copyOf(records));
    }
  }
}
