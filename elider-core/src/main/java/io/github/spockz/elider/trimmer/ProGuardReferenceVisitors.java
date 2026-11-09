/* WHY: Keeps ProGuard callbacks with the edge semantics they record. */

package io.github.spockz.elider.trimmer;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.objectweb.asm.Type;
import proguard.classfile.Clazz;
import proguard.classfile.attribute.Attribute;
import proguard.classfile.attribute.RecordAttribute;
import proguard.classfile.attribute.RecordComponentInfo;
import proguard.classfile.attribute.visitor.RecordComponentInfoVisitor;
import proguard.classfile.constant.ClassConstant;
import proguard.classfile.constant.Constant;
import proguard.classfile.constant.DynamicConstant;
import proguard.classfile.constant.RefConstant;
import proguard.classfile.util.InvalidReferenceVisitor;
import proguard.classfile.visitor.ClassVisitor;
import proguard.classfile.visitor.ReferencedClassVisitor;

/** WHY: ProGuard callbacks build role-scoped reference evidence. */
/* Package access keeps callback plumbing out of the public API. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ProGuardReferenceVisitors {
  /** WHY: Class tokens need distinct handling from other reference callbacks. */
  enum EdgeOrigin {
    /** WHY: Class-file parsing verifies whether this origin is structural. */
    CLASS_CONSTANT(1),
    /** WHY: Other callbacks preserve conservative body and member references. */
    OTHER(2);

    /** WHY: Nested callbacks combine origins with the enclosing visitor context. */
    final int mask;

    EdgeOrigin(final int mask) {
      this.mask = mask;
    }
  }

  /** WHY: This visitor carries origin information through ProGuard callbacks. */
  interface OriginTrackingClassVisitor extends ClassVisitor {
    /** WHY: Keeps nested callbacks associated with their originating ProGuard role. */
    void withOrigin(EdgeOrigin origin, Runnable action);

    /** WHY: Allows class-file evidence to identify symbolic class tokens separately. */
    void recordClassConstant(String name);
  }

  /** Prevents construction of the visitor factory. */
  private ProGuardReferenceVisitors() {}

  /* Package access keeps callback construction internal to the trimmer. */
  static ClassVisitor complete(
      final OriginTrackingClassVisitor classVisitor, final Function<String, Clazz> classLookup) {
    return new CompleteReferencedClassVisitor(classVisitor, classLookup);
  }

  /* Package access keeps callback construction internal to the trimmer. */
  static InvalidReferenceVisitor recordingInvalid(
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedReferences,
      final SignaturePolymorphicReferenceResolver resolver) {
    return new RecordingInvalidReferenceVisitor(unresolvedReferences, resolver);
  }

  /* Package access keeps callback construction internal to the trimmer. */
  static InvalidReferenceVisitor recordingLibraryInvalid(
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedReferences,
      final SignaturePolymorphicReferenceResolver resolver) {
    return new RecordingLibraryReferenceVisitor(unresolvedReferences, resolver);
  }

  /** Adds metadata links ProGuard Core omits from its general visitor. */
  /* Package access keeps the ProGuard visitor internal to the trimmer. */
  static final class CompleteReferencedClassVisitor extends ReferencedClassVisitor
      implements RecordComponentInfoVisitor {
    /** Receives newly reached candidate and sibling classes. */
    private final OriginTrackingClassVisitor classVisitor;

    /** Resolves descriptor names against the merged analysis pools. */
    private final Function<String, Clazz> classLookup;

    /* Package access lets the factory instantiate this visitor. */
    CompleteReferencedClassVisitor(
        final OriginTrackingClassVisitor classVisitor, final Function<String, Clazz> classLookup) {
      super(classVisitor);
      this.classVisitor = classVisitor;
      this.classLookup = classLookup;
    }

    @Override
    public void visitAnyConstant(final Clazz clazz, final Constant constant) {
      if (constant instanceof ClassConstant) {
        super.visitAnyConstant(clazz, constant);
        return;
      }
      classVisitor.withOrigin(
          EdgeOrigin.OTHER,
          () -> {
            if (constant instanceof DynamicConstant dynamicConstant) {
              dynamicConstant.referencedClassesAccept(classVisitor);
              dynamicConstant.bootstrapMethodHandleAccept(clazz, this);
            }
            super.visitAnyConstant(clazz, constant);
          });
    }

    @Override
    public void visitClassConstant(final Clazz clazz, final ClassConstant classConstant) {
      classVisitor.withOrigin(
          EdgeOrigin.CLASS_CONSTANT,
          () -> {
            classVisitor.recordClassConstant(classConstant.getName(clazz));
            super.visitClassConstant(clazz, classConstant);
          });
    }

    @Override
    public void visitAnyRefConstant(final Clazz clazz, final RefConstant refConstant) {
      classVisitor.withOrigin(
          EdgeOrigin.OTHER,
          () -> {
            super.visitAnyRefConstant(clazz, refConstant);
            visitDescriptorClasses(refConstant.getType(clazz), classLookup, classVisitor);
          });
    }

    @Override
    public void visitInvokeDynamicConstant(
        final Clazz clazz, final proguard.classfile.constant.InvokeDynamicConstant constant) {
      classVisitor.withOrigin(
          EdgeOrigin.OTHER, () -> super.visitInvokeDynamicConstant(clazz, constant));
    }

    @Override
    public void visitMethodTypeConstant(
        final Clazz clazz, final proguard.classfile.constant.MethodTypeConstant constant) {
      classVisitor.withOrigin(
          EdgeOrigin.OTHER, () -> super.visitMethodTypeConstant(clazz, constant));
    }

    @Override
    public void visitAnyAttribute(final Clazz clazz, final Attribute attribute) {
      classVisitor.withOrigin(
          EdgeOrigin.OTHER,
          () -> {
            if (attribute instanceof RecordAttribute recordAttribute) {
              recordAttribute.componentsAccept(clazz, this);
            }
            super.visitAnyAttribute(clazz, attribute);
          });
    }

    @Override
    public void visitRecordComponentInfo(
        final Clazz clazz, final RecordComponentInfo recordComponentInfo) {
      recordComponentInfo.referencedFieldAccept(clazz, this);
      recordComponentInfo.attributesAccept(clazz, this);
    }
  }

  private static void visitDescriptorClasses(
      final String descriptor,
      final Function<String, Clazz> classLookup,
      final ClassVisitor classVisitor) {
    final Type descriptorType = Type.getType(descriptor);
    if (descriptorType.getSort() == Type.METHOD) {
      visitType(descriptorType.getReturnType(), classLookup, classVisitor);
      for (final Type argumentType : descriptorType.getArgumentTypes()) {
        visitType(argumentType, classLookup, classVisitor);
      }
    } else {
      visitType(descriptorType, classLookup, classVisitor);
    }
  }

  private static void visitType(
      final Type type, final Function<String, Clazz> classLookup, final ClassVisitor classVisitor) {
    final Type elementType = type.getSort() == Type.ARRAY ? type.getElementType() : type;
    if (elementType.getSort() == Type.OBJECT) {
      final Clazz referencedClass = classLookup.apply(elementType.getInternalName());
      if (referencedClass != null) {
        classVisitor.visitAnyClass(referencedClass);
      }
    }
  }

  /** Records missing candidate links before closure starts. */
  /* Package access keeps unresolved-link recording internal to the trimmer. */
  static final class RecordingInvalidReferenceVisitor implements InvalidReferenceVisitor {
    /** Stores missing reference descriptions. */
    private final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedReferences;

    /** Handles legal signature-polymorphic links omitted by Core's visitor. */
    private final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver;

    /* Package access lets the factory instantiate this visitor. */
    RecordingInvalidReferenceVisitor(
        final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedReferences,
        final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver) {
      this.unresolvedReferences = unresolvedReferences;
      this.signaturePolymorphicResolver = signaturePolymorphicResolver;
    }

    @Override
    public void visitMissingClass(final Clazz referencingClass, final String missingClassName) {
      add(
          referencingClass,
          missingClassName,
          ReferenceGraph.UnresolvedKind.MISSING_CLASS,
          "class " + missingClassName);
    }

    @Override
    public void visitProgramDependency(final Clazz referencingClass, final Clazz dependencyClass) {
      // Cross-artifact library references are valid.
    }

    @Override
    public void visitAnyMissingMember(
        final Clazz referencingClass,
        final Clazz targetClass,
        final String memberName,
        final String memberDescriptor) {
      if (signaturePolymorphicResolver.recordIfSignaturePolymorphic(
          referencingClass, targetClass, memberName, memberDescriptor, unresolvedReferences)) {
        return;
      }
      add(
          referencingClass,
          targetClass.getName(),
          ReferenceGraph.UnresolvedKind.MISSING_MEMBER,
          "member " + targetClass.getName() + "." + memberName + memberDescriptor);
    }

    private void add(
        final Clazz referencingClass,
        final String targetClass,
        final ReferenceGraph.UnresolvedKind kind,
        final String missingReference) {
      unresolvedReferences
          .computeIfAbsent(referencingClass.getName(), unused -> new LinkedHashSet<>())
          .add(
              new ReferenceGraph.UnresolvedLink(
                  targetClass, kind, referencingClass.getName() + " -> " + missingReference));
    }
  }

  /** Defers missing sibling links until a sibling class is reached. */
  /* Package access keeps sibling-link recording internal to the trimmer. */
  static final class RecordingLibraryReferenceVisitor implements InvalidReferenceVisitor {
    /** Maps each sibling class to its unresolved links. */
    private final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedReferences;

    /** Handles legal signature-polymorphic links omitted by Core's visitor. */
    private final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver;

    /* Package access lets the factory instantiate this visitor. */
    RecordingLibraryReferenceVisitor(
        final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedReferences,
        final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver) {
      this.unresolvedReferences = unresolvedReferences;
      this.signaturePolymorphicResolver = signaturePolymorphicResolver;
    }

    @Override
    public void visitMissingClass(final Clazz referencingClass, final String missingClassName) {
      add(
          referencingClass,
          missingClassName,
          ReferenceGraph.UnresolvedKind.MISSING_CLASS,
          "class " + missingClassName);
    }

    @Override
    public void visitProgramDependency(final Clazz referencingClass, final Clazz dependencyClass) {
      // Cross-artifact library references are valid.
    }

    @Override
    public void visitAnyMissingMember(
        final Clazz referencingClass,
        final Clazz targetClass,
        final String memberName,
        final String memberDescriptor) {
      if (signaturePolymorphicResolver.recordIfSignaturePolymorphic(
          referencingClass, targetClass, memberName, memberDescriptor, unresolvedReferences)) {
        return;
      }
      add(
          referencingClass,
          targetClass.getName(),
          ReferenceGraph.UnresolvedKind.MISSING_MEMBER,
          "member " + targetClass.getName() + "." + memberName + memberDescriptor);
    }

    private void add(
        final Clazz referencingClass,
        final String targetClass,
        final ReferenceGraph.UnresolvedKind kind,
        final String missingReference) {
      unresolvedReferences
          .computeIfAbsent(referencingClass.getName(), unused -> new LinkedHashSet<>())
          .add(
              new ReferenceGraph.UnresolvedLink(
                  targetClass, kind, referencingClass.getName() + " -> " + missingReference));
    }
  }
}
