/* WHY: Collects class and member references while decoding predefined bytecode. */

package io.github.spockz.elider.plugin;

import java.util.Set;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;

/** Collects class references from class headers, members, annotations, and code. */
final class NativeImagePredefinedClassVisitor extends ClassVisitor {
  /** WHY: These callbacks contribute to the same predefined class closure. */
  private final Set<String> references;

  /* package */
  NativeImagePredefinedClassVisitor(final Set<String> references) {
    super(Opcodes.ASM9, new NativeImagePredefinedClassMetadataVisitor(references));
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
    NativeImagePredefinedBytecodeTypes.addInternalName(name, references);
    NativeImagePredefinedBytecodeTypes.addInternalName(superName, references);
    if (interfaces != null) {
      for (final String interfaceName : interfaces) {
        NativeImagePredefinedBytecodeTypes.addInternalName(interfaceName, references);
      }
    }
    NativeImagePredefinedBytecodeTypes.addSignatureTypes(signature, references);
    super.visit(version, access, name, signature, superName, interfaces);
  }

  @Override
  public RecordComponentVisitor visitRecordComponent(
      final String name, final String descriptor, final String signature) {
    NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
    NativeImagePredefinedBytecodeTypes.addSignatureTypes(signature, references);
    return new RecordComponentVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotation(
          final String annotationDescriptor, final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final org.objectweb.asm.TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }
    };
  }

  @Override
  public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
    NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
    return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
  }

  @Override
  public AnnotationVisitor visitTypeAnnotation(
      final int typeRef,
      final org.objectweb.asm.TypePath typePath,
      final String descriptor,
      final boolean visible) {
    NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
    return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
  }

  @Override
  public FieldVisitor visitField(
      final int access,
      final String name,
      final String descriptor,
      final String signature,
      final Object value) {
    NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
    NativeImagePredefinedBytecodeTypes.addSignatureTypes(signature, references);
    NativeImagePredefinedBytecodeTypes.addConstantTypes(value, references);
    return new FieldVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotation(final String descriptor, final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final org.objectweb.asm.TypePath typePath,
          final String descriptor,
          final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
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
    NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
    NativeImagePredefinedBytecodeTypes.addSignatureTypes(signature, references);
    if (exceptions != null) {
      for (final String exception : exceptions) {
        NativeImagePredefinedBytecodeTypes.addInternalName(exception, references);
      }
    }
    return new MethodVisitor(Opcodes.ASM9) {
      @Override
      public AnnotationVisitor visitAnnotationDefault() {
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitAnnotation(
          final String annotationDescriptor, final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitParameterAnnotation(
          final int parameter, final String annotationDescriptor, final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitTypeAnnotation(
          final int typeRef,
          final org.objectweb.asm.TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitInsnAnnotation(
          final int typeRef,
          final org.objectweb.asm.TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitTryCatchAnnotation(
          final int typeRef,
          final org.objectweb.asm.TypePath typePath,
          final String annotationDescriptor,
          final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public AnnotationVisitor visitLocalVariableAnnotation(
          final int typeRef,
          final org.objectweb.asm.TypePath typePath,
          final org.objectweb.asm.Label[] start,
          final org.objectweb.asm.Label[] end,
          final int[] index,
          final String annotationDescriptor,
          final boolean visible) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(annotationDescriptor, references);
        return NativeImagePredefinedBytecodeTypes.annotationVisitor(references);
      }

      @Override
      public void visitFrame(
          final int type,
          final int numLocal,
          final Object[] local,
          final int numStack,
          final Object[] stack) {
        NativeImagePredefinedBytecodeTypes.addFrameTypes(local, numLocal, references);
        NativeImagePredefinedBytecodeTypes.addFrameTypes(stack, numStack, references);
      }

      @Override
      public void visitTryCatchBlock(
          final org.objectweb.asm.Label start,
          final org.objectweb.asm.Label end,
          final org.objectweb.asm.Label handler,
          final String type) {
        NativeImagePredefinedBytecodeTypes.addInternalName(type, references);
      }

      @Override
      public void visitLocalVariable(
          final String localName,
          final String localDescriptor,
          final String localSignature,
          final org.objectweb.asm.Label start,
          final org.objectweb.asm.Label end,
          final int index) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(localDescriptor, references);
        NativeImagePredefinedBytecodeTypes.addSignatureTypes(localSignature, references);
      }

      @Override
      public void visitLdcInsn(final Object value) {
        NativeImagePredefinedBytecodeTypes.addConstantTypes(value, references);
      }

      @Override
      public void visitInvokeDynamicInsn(
          final String invokedName,
          final String invokedDescriptor,
          final Handle bootstrapMethodHandle,
          final Object... bootstrapMethodArguments) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(invokedDescriptor, references);
        NativeImagePredefinedBytecodeTypes.addConstantTypes(bootstrapMethodHandle, references);
        for (final Object argument : bootstrapMethodArguments) {
          NativeImagePredefinedBytecodeTypes.addConstantTypes(argument, references);
        }
      }

      @Override
      public void visitTypeInsn(final int opcode, final String type) {
        NativeImagePredefinedBytecodeTypes.addInternalName(type, references);
      }

      @Override
      public void visitFieldInsn(
          final int opcode, final String owner, final String field, final String desc) {
        NativeImagePredefinedBytecodeTypes.addInternalName(owner, references);
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(desc, references);
      }

      @Override
      public void visitMethodInsn(
          final int opcode,
          final String owner,
          final String method,
          final String desc,
          final boolean isInterface) {
        NativeImagePredefinedBytecodeTypes.addInternalName(owner, references);
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(desc, references);
      }

      @Override
      public void visitMultiANewArrayInsn(final String desc, final int dimensions) {
        NativeImagePredefinedBytecodeTypes.addDescriptorTypes(desc, references);
      }
    };
  }
}
