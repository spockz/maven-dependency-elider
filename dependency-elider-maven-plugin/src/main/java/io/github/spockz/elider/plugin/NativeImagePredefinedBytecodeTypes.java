/* WHY: Collects class references encoded in predefined class bytecode structures. */

package io.github.spockz.elider.plugin;

import java.util.Set;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.signature.SignatureReader;
import org.objectweb.asm.signature.SignatureVisitor;

/** Extracts types from descriptors, signatures, annotations, and constants. */
final class NativeImagePredefinedBytecodeTypes {
  private NativeImagePredefinedBytecodeTypes() {}

  /* package */
  static void addFrameTypes(final Object[] frame, final int count, final Set<String> roots) {
    for (int index = 0; index < count; index++) {
      final Object value = frame[index];
      if (value instanceof String internalName) {
        addInternalName(internalName, roots);
      }
    }
  }

  /* package */
  static AnnotationVisitor annotationVisitor(final Set<String> roots) {
    return new AnnotationVisitor(Opcodes.ASM9) {
      @Override
      public void visit(final String name, final Object value) {
        addConstantTypes(value, roots);
      }

      @Override
      public void visitEnum(final String name, final String descriptor, final String value) {
        addDescriptorTypes(descriptor, roots);
      }

      @Override
      public AnnotationVisitor visitAnnotation(final String name, final String descriptor) {
        addDescriptorTypes(descriptor, roots);
        return annotationVisitor(roots);
      }

      @Override
      public AnnotationVisitor visitArray(final String name) {
        return annotationVisitor(roots);
      }
    };
  }

  /* package */
  static void addConstantTypes(final Object value, final Set<String> roots) {
    if (value instanceof Type type) {
      collectType(type, roots);
    } else if (value instanceof Handle handle) {
      addInternalName(handle.getOwner(), roots);
      addDescriptorTypes(handle.getDesc(), roots);
    } else if (value instanceof ConstantDynamic dynamic) {
      addDescriptorTypes(dynamic.getDescriptor(), roots);
      addConstantTypes(dynamic.getBootstrapMethod(), roots);
      for (int index = 0; index < dynamic.getBootstrapMethodArgumentCount(); index++) {
        addConstantTypes(dynamic.getBootstrapMethodArgument(index), roots);
      }
    }
  }

  /* package */
  static void addSignatureTypes(final String signature, final Set<String> roots) {
    if (signature == null) {
      return;
    }
    final SignatureVisitor visitor =
        new SignatureVisitor(Opcodes.ASM9) {
          /** Tracks nested class signature segments while collecting binary names. */
          private String currentClass;

          @Override
          public void visitClassType(final String name) {
            currentClass = name;
            addInternalName(currentClass, roots);
          }

          @Override
          public void visitInnerClassType(final String name) {
            currentClass = currentClass + "$" + name;
            addInternalName(currentClass, roots);
          }

          @Override
          public SignatureVisitor visitTypeArgument(final char wildcard) {
            return signatureVisitor(roots);
          }
        };
    try {
      new SignatureReader(signature).accept(visitor);
    } catch (IllegalArgumentException exception) {
      new SignatureReader(signature).acceptType(visitor);
    }
  }

  /* package */
  static void addDescriptorTypes(final String descriptor, final Set<String> roots) {
    if (descriptor == null) {
      return;
    }
    try {
      final Type parsed =
          descriptor.startsWith("(") ? Type.getMethodType(descriptor) : Type.getType(descriptor);
      collectType(parsed, roots);
    } catch (IllegalArgumentException descriptorFailure) {
      try {
        final SignatureReader reader = new SignatureReader(descriptor);
        final SignatureVisitor visitor = signatureVisitor(roots);
        try {
          reader.accept(visitor);
        } catch (IllegalArgumentException classOrMethodSignatureFailure) {
          reader.acceptType(visitor);
        }
      } catch (IllegalArgumentException signatureFailure) {
        signatureFailure.addSuppressed(descriptorFailure);
        throw new IllegalArgumentException(
            "Malformed JVM descriptor or signature: " + descriptor, signatureFailure);
      }
    }
  }

  private static SignatureVisitor signatureVisitor(final Set<String> roots) {
    return new SignatureVisitor(Opcodes.ASM9) {
      /** Tracks nested class signature segments while collecting binary names. */
      private String currentClass;

      @Override
      public void visitClassType(final String name) {
        currentClass = name;
        addInternalName(currentClass, roots);
      }

      @Override
      public void visitInnerClassType(final String name) {
        currentClass = currentClass + "$" + name;
        addInternalName(currentClass, roots);
      }

      @Override
      public SignatureVisitor visitTypeArgument(final char wildcard) {
        return signatureVisitor(roots);
      }
    };
  }

  private static void collectType(final Type type, final Set<String> roots) {
    switch (type.getSort()) {
      case Type.ARRAY -> collectType(type.getElementType(), roots);
      case Type.OBJECT -> addInternalName(type.getInternalName(), roots);
      case Type.METHOD -> {
        collectType(type.getReturnType(), roots);
        for (final Type argument : type.getArgumentTypes()) {
          collectType(argument, roots);
        }
      }
      default -> {}
    }
  }

  /* package */
  static void addInternalName(final String internalName, final Set<String> roots) {
    if (internalName != null && internalName.startsWith("[")) {
      addDescriptorTypes(internalName, roots);
    } else if (internalName != null) {
      final String binary = internalName.replace('/', '.');
      if (NativeImageDynamicRoots.isBinaryClassName(binary)) {
        roots.add(binary);
      }
    }
  }
}
