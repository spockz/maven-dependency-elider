/* WHY: Separates direct symbolic references in production bytecode from runtime observations so
 * callers can compare these independent evidence sources. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

/** Scans class files beneath a caller supplied production output directory. */
public final class ProductionBytecodeReferenceScanner {
  /** Creates a production class reference scanner. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public ProductionBytecodeReferenceScanner() {}

  /** Scans all supplied class files and fails if the scan cannot complete. */
  public BytecodeReferenceScan scan(final Path productionOutput) throws IOException {
    if (productionOutput == null || !Files.isDirectory(productionOutput)) {
      throw new IOException(
          "Production class output directory is missing or not a directory: " + productionOutput);
    }
    final Path scope = productionOutput.toAbsolutePath().normalize();
    final Set<String> references = new HashSet<>();
    int count = 0;
    try (Stream<Path> paths = Files.walk(scope)) {
      for (final Path classFile : paths.sorted().toList()) {
        count += scanPath(classFile, references);
      }
    }
    return new BytecodeReferenceScan(scope, references, count, true);
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static int scanPath(final Path path, final Set<String> references) throws IOException {
    final BasicFileAttributes attributes =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (attributes.isSymbolicLink()) {
      throw new IOException("Symbolic link in production class output: " + path);
    }
    final Path fileName = path.getFileName();
    if (!attributes.isRegularFile()
        || fileName == null
        || !fileName.toString().endsWith(".class")) {
      return 0;
    }
    try {
      new ClassReader(Files.readAllBytes(path)).accept(new ReferencesVisitor(references), 0);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not scan production class file: " + path, exception);
    }
    return 1;
  }

  /** Collects the symbolic references exposed by ASM's class-file visitor callbacks. */
  @SuppressWarnings("PMD.TooManyMethods")
  private static final class ReferencesVisitor extends ClassVisitor {
    /** Accumulates names shared by the visitor callbacks for one class output scan. */
    private final Set<String> references;

    /** Creates the callback visitor over the scan's shared reference set. */
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    ReferencesVisitor(final Set<String> references) {
      super(Opcodes.ASM9);
      this.references = references;
    }

    @Override
    public void visit(
        final int version,
        final int access,
        final String name,
        final String signature,
        final String superName,
        final String[] interfaces) {
      add(superName);
      addAll(interfaces);
      addSignature(signature, false);
    }

    @Override
    public void visitOuterClass(final String owner, final String name, final String descriptor) {
      add(owner);
      addDescriptor(descriptor);
    }

    @Override
    public void visitNestHost(final String nestHost) {
      add(nestHost);
    }

    @Override
    public void visitNestMember(final String nestMember) {
      add(nestMember);
    }

    @Override
    public void visitPermittedSubclass(final String permittedSubclass) {
      add(permittedSubclass);
    }

    @Override
    public ModuleVisitor visitModule(final String name, final int access, final String version) {
      return new ModuleVisitor(Opcodes.ASM9) {
        @Override
        public void visitMainClass(final String mainClass) {
          add(mainClass);
        }

        @Override
        public void visitUse(final String service) {
          add(service);
        }

        @Override
        public void visitProvide(final String service, final String... providers) {
          add(service);
          addAll(providers);
        }
      };
    }

    @Override
    public void visitInnerClass(
        final String name, final String outerName, final String innerName, final int access) {
      add(name);
      add(outerName);
    }

    @Override
    public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
      addDescriptor(descriptor);
      return annotationVisitor();
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(
        final int typeRef,
        final org.objectweb.asm.TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor);
      return annotationVisitor();
    }

    @Override
    public RecordComponentVisitor visitRecordComponent(
        final String name, final String descriptor, final String signature) {
      addDescriptor(descriptor);
      addSignature(signature, true);
      return new RecordComponentVisitor(Opcodes.ASM9) {
        @Override
        public AnnotationVisitor visitAnnotation(final String desc, final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(
            final int ref,
            final org.objectweb.asm.TypePath path,
            final String desc,
            final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }
      };
    }

    @Override
    public FieldVisitor visitField(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final Object value) {
      addDescriptor(descriptor);
      addSignature(signature, true);
      addValue(value);
      return new FieldVisitor(Opcodes.ASM9) {
        @Override
        public AnnotationVisitor visitAnnotation(final String desc, final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(
            final int ref,
            final org.objectweb.asm.TypePath path,
            final String desc,
            final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }
      };
    }

    @Override
    public MethodVisitor visitMethod(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final String[] exceptions) {
      addDescriptor(descriptor);
      addSignature(signature, false);
      addAll(exceptions);
      return new MethodVisitor(Opcodes.ASM9) {
        @Override
        public AnnotationVisitor visitAnnotationDefault() {
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitAnnotation(final String desc, final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(
            final int ref,
            final org.objectweb.asm.TypePath path,
            final String desc,
            final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitParameterAnnotation(
            final int parameter, final String desc, final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitInsnAnnotation(
            final int ref,
            final org.objectweb.asm.TypePath path,
            final String desc,
            final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitTryCatchAnnotation(
            final int ref,
            final org.objectweb.asm.TypePath path,
            final String desc,
            final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitLocalVariableAnnotation(
            final int ref,
            final org.objectweb.asm.TypePath path,
            final org.objectweb.asm.Label[] start,
            final org.objectweb.asm.Label[] end,
            final int[] index,
            final String desc,
            final boolean visible) {
          addDescriptor(desc);
          return annotationVisitor();
        }

        @Override
        public void visitTypeInsn(final int opcode, final String type) {
          if (type.startsWith("[")) {
            addDescriptor(type);
          } else {
            add(type);
          }
        }

        @Override
        public void visitFieldInsn(
            final int opcode, final String owner, final String field, final String desc) {
          add(owner);
          addDescriptor(desc);
        }

        @Override
        public void visitMethodInsn(
            final int opcode,
            final String owner,
            final String method,
            final String desc,
            final boolean isInterface) {
          add(owner);
          addDescriptor(desc);
        }

        @Override
        public void visitInvokeDynamicInsn(
            final String name,
            final String desc,
            final Handle bootstrap,
            final Object... arguments) {
          addDescriptor(desc);
          addValue(bootstrap);
          for (final Object argument : arguments) {
            addValue(argument);
          }
        }

        @Override
        public void visitLdcInsn(final Object value) {
          addValue(value);
        }

        @Override
        public void visitMultiANewArrayInsn(final String desc, final int dimensions) {
          addDescriptor(desc);
        }

        @Override
        public void visitTryCatchBlock(
            final org.objectweb.asm.Label start,
            final org.objectweb.asm.Label end,
            final org.objectweb.asm.Label handler,
            final String type) {
          add(type);
        }

        @Override
        public void visitLocalVariable(
            final String name,
            final String desc,
            final String localSignature,
            final org.objectweb.asm.Label start,
            final org.objectweb.asm.Label end,
            final int index) {
          addDescriptor(desc);
          addSignature(localSignature, true);
        }

        @Override
        public void visitFrame(
            final int type,
            final int numLocal,
            final Object[] local,
            final int numStack,
            final Object[] stack) {
          addFrameTypes(local);
          addFrameTypes(stack);
        }
      };
    }

    private AnnotationVisitor annotationVisitor() {
      return new AnnotationVisitor(Opcodes.ASM9) {
        @Override
        public void visit(final String name, final Object value) {
          addValue(value);
        }

        @Override
        public void visitEnum(final String name, final String descriptor, final String value) {
          addDescriptor(descriptor);
        }

        @Override
        public AnnotationVisitor visitAnnotation(final String name, final String descriptor) {
          addDescriptor(descriptor);
          return annotationVisitor();
        }

        @Override
        public AnnotationVisitor visitArray(final String name) {
          return annotationVisitor();
        }
      };
    }

    private void addValue(final Object value) {
      if (value instanceof Type type) {
        addType(type);
      } else if (value instanceof Handle handle) {
        add(handle.getOwner());
        addDescriptor(handle.getDesc());
      } else if (value instanceof ConstantDynamic dynamic) {
        addDescriptor(dynamic.getDescriptor());
        addValue(dynamic.getBootstrapMethod());
        for (int index = 0; index < dynamic.getBootstrapMethodArgumentCount(); index++) {
          addValue(dynamic.getBootstrapMethodArgument(index));
        }
      } else if (value instanceof Object[] values) {
        for (final Object element : values) {
          addValue(element);
        }
      }
    }

    private void addDescriptor(final String descriptor) {
      if (descriptor != null) {
        addType(Type.getType(descriptor));
      }
    }

    private void addType(final Type type) {
      switch (type.getSort()) {
        case Type.ARRAY -> addType(type.getElementType());
        case Type.OBJECT -> add(type.getInternalName());
        case Type.METHOD -> {
          for (final Type argument : type.getArgumentTypes()) {
            addType(argument);
          }
          addType(type.getReturnType());
        }
        default -> {}
      }
    }

    private void addSignature(final String signature, final boolean typeSignature) {
      if (signature == null) {
        return;
      }
      final SignatureReader reader = new SignatureReader(signature);
      final SignatureVisitor visitor = new SignatureCollector();
      if (typeSignature) {
        reader.acceptType(visitor);
      } else {
        reader.accept(visitor);
      }
    }

    /** Traverses nested generic signatures with isolated branch state. */
    @SuppressWarnings("PMD.TooManyMethods")
    private class SignatureCollector extends SignatureVisitor {
      /** Tracks the current owner so nested signature classes retain their binary name. */
      private String current;

      /** Creates a visitor for one signature branch. */
      @SuppressWarnings("PMD.CommentDefaultAccessModifier")
      SignatureCollector() {
        super(Opcodes.ASM9);
      }

      @Override
      public void visitClassType(final String name) {
        current = name;
        add(name);
      }

      @Override
      public void visitInnerClassType(final String name) {
        current = current + "$" + name;
        add(current);
      }

      @Override
      public SignatureVisitor visitArrayType() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitClassBound() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitInterfaceBound() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitSuperclass() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitInterface() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitParameterType() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitReturnType() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitExceptionType() {
        return new SignatureCollector();
      }

      @Override
      public SignatureVisitor visitTypeArgument(final char wildcard) {
        return new SignatureCollector();
      }
    }

    private void addAll(final String... names) {
      if (names != null) {
        for (final String name : names) {
          add(name);
        }
      }
    }

    private void addFrameTypes(final Object... values) {
      if (values == null) {
        return;
      }
      for (final Object value : values) {
        if (value instanceof String className) {
          add(className);
        }
      }
    }

    private void add(final String internalName) {
      if (internalName != null && !internalName.isEmpty()) {
        if (internalName.startsWith("[")) {
          addDescriptor(internalName);
        } else {
          references.add(TraceData.normalizeToDot(internalName));
        }
      }
    }
  }
}
