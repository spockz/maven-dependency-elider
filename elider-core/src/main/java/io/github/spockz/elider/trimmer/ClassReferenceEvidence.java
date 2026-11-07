/* WHY: Classifies bytecode links so bounded closure omits only excluded method-body edges. */

package io.github.spockz.elider.trimmer;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

/** Extracts typed class edges from class-file metadata and selected method bodies. */
final class ClassReferenceEvidence {
  private ClassReferenceEvidence() {}

  // WHY: Visitor maps are local; ASM parser failures use unchecked exceptions.
  // The default access modifier keeps this extractor package-private.
  // WHY: Only graph assembly needs this method.
  @SuppressWarnings({
    "PMD.UseConcurrentHashMap",
    "PMD.AvoidCatchingGenericException",
    "PMD.CommentDefaultAccessModifier"
  })
  static Map<String, Set<ReferenceGraph.EdgeKind>> references(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<String, Set<ReferenceGraph.EdgeKind>> references = new LinkedHashMap<>();
    references
        .computeIfAbsent(sourceClass, unused -> EnumSet.noneOf(ReferenceGraph.EdgeKind.class))
        .add(ReferenceGraph.EdgeKind.STRUCTURAL);
    try {
      new ClassReader(bytes)
          .accept(new StructuralAndBodyVisitor(sourceClass, references, includeMethodBodies), 0);
    } catch (final RuntimeException exception) {
      throw new IllegalArgumentException(
          "Could not classify references for class " + sourceClass, exception);
    }
    final Map<String, Set<ReferenceGraph.EdgeKind>> immutable = new HashMap<>();
    references.forEach((target, kinds) -> immutable.put(target, Set.copyOf(kinds)));
    return Map.copyOf(immutable);
  }

  /** Collects all ASM callbacks into the source class's typed edge set. */
  // WHY: One ASM adapter handles distinct metadata and code events.
  @SuppressWarnings({"PMD.GodClass", "PMD.TooManyMethods"})
  private static final class StructuralAndBodyVisitor extends ClassVisitor {
    /** Source identity keeps malformed bytecode errors actionable. */
    private final String sourceClass;

    /** Receives links classified by the visitor's metadata and body callbacks. */
    private final Map<String, Set<ReferenceGraph.EdgeKind>> references;

    /** Sibling library roles exclude method bodies from graph evidence. */
    private final boolean includeMethodBodies;

    /** Binds one source identity and its edge sink to the ASM event adapter. */
    private StructuralAndBodyVisitor(
        final String sourceClass,
        final Map<String, Set<ReferenceGraph.EdgeKind>> references,
        final boolean includeMethodBodies) {
      super(Opcodes.ASM9);
      this.sourceClass = sourceClass;
      this.references = references;
      this.includeMethodBodies = includeMethodBodies;
    }

    @Override
    public void visit(
        final int version,
        final int access,
        final String name,
        final String signature,
        final String superName,
        final String[] interfaces) {
      addInternalName(superName, ReferenceGraph.EdgeKind.STRUCTURAL);
      if (interfaces != null) {
        for (final String interfaceName : interfaces) {
          addInternalName(interfaceName, ReferenceGraph.EdgeKind.STRUCTURAL);
        }
      }
      addSignature(signature, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitOuterClass(final String owner, final String name, final String descriptor) {
      addInternalName(owner, ReferenceGraph.EdgeKind.STRUCTURAL);
      addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitNestHost(final String nestHost) {
      addInternalName(nestHost, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitNestMember(final String nestMember) {
      addInternalName(nestMember, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitPermittedSubclass(final String permittedSubclass) {
      addInternalName(permittedSubclass, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitInnerClass(
        final String name, final String outerName, final String innerName, final int access) {
      addInternalName(name, ReferenceGraph.EdgeKind.STRUCTURAL);
      addInternalName(outerName, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
      addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      return annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(
        final int typeRef,
        final org.objectweb.asm.TypePath typePath,
        final String descriptor,
        final boolean visible) {
      addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      return annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public FieldVisitor visitField(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final Object value) {
      addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      addSignature(signature, ReferenceGraph.EdgeKind.STRUCTURAL);
      return new FieldVisitor(Opcodes.ASM9) {
        @Override
        public AnnotationVisitor visitAnnotation(
            final String annotationDescriptor, final boolean visible) {
          addDescriptor(annotationDescriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
          return annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(
            final int typeRef,
            final org.objectweb.asm.TypePath typePath,
            final String annotationDescriptor,
            final boolean visible) {
          addDescriptor(annotationDescriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
          return annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
        }
      };
    }

    @Override
    public RecordComponentVisitor visitRecordComponent(
        final String name, final String descriptor, final String signature) {
      addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      addSignature(signature, ReferenceGraph.EdgeKind.STRUCTURAL);
      return new RecordComponentVisitor(Opcodes.ASM9) {
        @Override
        public AnnotationVisitor visitAnnotation(
            final String annotationDescriptor, final boolean visible) {
          addDescriptor(annotationDescriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
          return annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
        }

        @Override
        public AnnotationVisitor visitTypeAnnotation(
            final int typeRef,
            final org.objectweb.asm.TypePath typePath,
            final String annotationDescriptor,
            final boolean visible) {
          addDescriptor(annotationDescriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
          return annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
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
      addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      addSignature(signature, ReferenceGraph.EdgeKind.STRUCTURAL);
      if (exceptions != null) {
        for (final String exception : exceptions) {
          addInternalName(exception, ReferenceGraph.EdgeKind.STRUCTURAL);
        }
      }
      if (!includeMethodBodies) {
        return null;
      }
      return new MethodReferenceVisitor(this);
    }

    private AnnotationVisitor annotationVisitor(final ReferenceGraph.EdgeKind kind) {
      return new AnnotationVisitor(Opcodes.ASM9) {
        @Override
        public void visit(final String name, final Object value) {
          if (value instanceof Type type) {
            addType(type, kind);
          }
        }

        @Override
        public void visitEnum(final String name, final String descriptor, final String value) {
          addDescriptor(descriptor, kind);
        }

        @Override
        public AnnotationVisitor visitAnnotation(final String name, final String descriptor) {
          addDescriptor(descriptor, kind);
          return annotationVisitor(kind);
        }

        @Override
        public AnnotationVisitor visitArray(final String name) {
          return annotationVisitor(kind);
        }
      };
    }

    // WHY: SignatureReader uses varied unchecked failures for malformed forms.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void addSignature(final String signature, final ReferenceGraph.EdgeKind kind) {
      if (signature == null) {
        return;
      }
      try {
        new SignatureReader(signature).accept(signatureVisitor(kind));
      } catch (final RuntimeException exception) {
        throw new IllegalArgumentException(
            "Invalid reference signature in " + sourceClass + ": " + signature, exception);
      }
    }

    private SignatureVisitor signatureVisitor(final ReferenceGraph.EdgeKind kind) {
      return new SignatureVisitor(Opcodes.ASM9) {
        /** Tracks the enclosing class within this signature visitor scope. */
        private String currentClassType;

        @Override
        public void visitClassType(final String name) {
          currentClassType = name;
          addInternalName(name, kind);
        }

        @Override
        public void visitInnerClassType(final String name) {
          currentClassType = currentClassType + "$" + name;
          addInternalName(currentClassType, kind);
        }

        @Override
        public SignatureVisitor visitClassBound() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitInterfaceBound() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitSuperclass() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitInterface() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitParameterType() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitReturnType() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitExceptionType() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitArrayType() {
          return signatureVisitor(kind);
        }

        @Override
        public SignatureVisitor visitTypeArgument(final char wildcard) {
          return signatureVisitor(kind);
        }
      };
    }

    private void addDescriptor(final String descriptor, final ReferenceGraph.EdgeKind kind) {
      if (descriptor != null) {
        final Type type;
        try {
          type = Type.getType(descriptor);
        } catch (final IllegalArgumentException exception) {
          throw new IllegalArgumentException(
              "Invalid reference descriptor in " + sourceClass + ": " + descriptor, exception);
        }
        if (!validObjectDescriptor(descriptor) || !type.getDescriptor().equals(descriptor)) {
          throw new IllegalArgumentException(
              "Invalid reference descriptor in " + sourceClass + ": " + descriptor);
        }
        addType(type, kind);
      }
    }

    private static boolean validObjectDescriptor(final String descriptor) {
      if (descriptor.startsWith("[")) {
        return validObjectDescriptor(descriptor.substring(1));
      }
      return !descriptor.startsWith("L")
          || (descriptor.length() >= 3
              && descriptor.endsWith(";")
              && !descriptor.substring(1, descriptor.length() - 1).contains(";"));
    }

    private void addType(final Type type, final ReferenceGraph.EdgeKind kind) {
      if (type.getSort() == Type.METHOD) {
        addType(type.getReturnType(), kind);
        for (final Type argument : type.getArgumentTypes()) {
          addType(argument, kind);
        }
      } else if (type.getSort() == Type.ARRAY) {
        addType(type.getElementType(), kind);
      } else if (type.getSort() == Type.OBJECT) {
        addInternalName(type.getInternalName(), kind);
      }
    }

    private void addInternalName(final String name, final ReferenceGraph.EdgeKind kind) {
      if (name == null) {
        return;
      }
      if (name.startsWith("[")) {
        addDescriptor(name, kind);
        return;
      }
      references
          .computeIfAbsent(name, unused -> EnumSet.noneOf(ReferenceGraph.EdgeKind.class))
          .add(kind);
    }

    private void addHandle(final Handle handle) {
      addInternalName(handle.getOwner(), ReferenceGraph.EdgeKind.BODY);
      addDescriptor(handle.getDesc(), ReferenceGraph.EdgeKind.BODY);
    }

    private void addFrameTypes(final Object[] types, final int count) {
      if (types == null) {
        return;
      }
      for (int index = 0; index < count; index++) {
        if (types[index] instanceof String name) {
          addInternalName(name, ReferenceGraph.EdgeKind.BODY);
        }
      }
    }

    private void addConstant(final Object value) {
      if (value instanceof Type type) {
        addType(type, ReferenceGraph.EdgeKind.BODY);
      } else if (value instanceof Handle handle) {
        addHandle(handle);
      } else if (value instanceof ConstantDynamic dynamic) {
        addDescriptor(dynamic.getDescriptor(), ReferenceGraph.EdgeKind.BODY);
        addHandle(dynamic.getBootstrapMethod());
        for (int index = 0; index < dynamic.getBootstrapMethodArgumentCount(); index++) {
          addConstant(dynamic.getBootstrapMethodArgument(index));
        }
      }
    }
  }

  /** Collects method metadata and bytecode references for one class. */
  // WHY: ASM exposes these method events through one visitor adapter.
  @SuppressWarnings("PMD.TooManyMethods")
  private static final class MethodReferenceVisitor extends MethodVisitor {
    /** Provides the typed-edge sink for method callbacks. */
    private final StructuralAndBodyVisitor owner;

    private MethodReferenceVisitor(final StructuralAndBodyVisitor owner) {
      super(Opcodes.ASM9);
      this.owner = owner;
    }

    @Override
    public AnnotationVisitor visitAnnotationDefault() {
      return owner.annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      return owner.annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitTypeAnnotation(
        final int typeRef,
        final org.objectweb.asm.TypePath typePath,
        final String descriptor,
        final boolean visible) {
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      return owner.annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public AnnotationVisitor visitParameterAnnotation(
        final int parameter, final String descriptor, final boolean visible) {
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.STRUCTURAL);
      return owner.annotationVisitor(ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitTryCatchBlock(
        final org.objectweb.asm.Label start,
        final org.objectweb.asm.Label end,
        final org.objectweb.asm.Label handler,
        final String type) {
      owner.addInternalName(type, ReferenceGraph.EdgeKind.STRUCTURAL);
    }

    @Override
    public void visitFrame(
        final int type,
        final int numLocal,
        final Object[] local,
        final int numStack,
        final Object[] stack) {
      owner.addFrameTypes(local, numLocal);
      owner.addFrameTypes(stack, numStack);
    }

    @Override
    public void visitTypeInsn(final int opcode, final String type) {
      owner.addInternalName(type, ReferenceGraph.EdgeKind.BODY);
    }

    @Override
    public void visitFieldInsn(
        final int opcode, final String ownerName, final String fieldName, final String descriptor) {
      owner.addInternalName(ownerName, ReferenceGraph.EdgeKind.BODY);
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.BODY);
    }

    @Override
    public void visitMethodInsn(
        final int opcode,
        final String ownerName,
        final String methodName,
        final String descriptor,
        final boolean isInterface) {
      owner.addInternalName(ownerName, ReferenceGraph.EdgeKind.BODY);
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.BODY);
    }

    @Override
    public void visitInvokeDynamicInsn(
        final String name,
        final String descriptor,
        final Handle bootstrapMethodHandle,
        final Object... bootstrapMethodArguments) {
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.BODY);
      owner.addHandle(bootstrapMethodHandle);
      for (final Object argument : bootstrapMethodArguments) {
        owner.addConstant(argument);
      }
    }

    @Override
    public void visitLdcInsn(final Object value) {
      owner.addConstant(value);
    }

    @Override
    public void visitMultiANewArrayInsn(final String descriptor, final int dimensions) {
      owner.addDescriptor(descriptor, ReferenceGraph.EdgeKind.BODY);
    }
  }
}
