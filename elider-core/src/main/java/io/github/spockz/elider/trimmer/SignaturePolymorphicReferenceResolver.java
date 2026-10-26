/* WHY: ProGuard Core omits call-site descriptor links for signature-polymorphic methods. */

package io.github.spockz.elider.trimmer;

import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.objectweb.asm.Type;
import proguard.classfile.AccessConstants;
import proguard.classfile.Clazz;
import proguard.classfile.Member;
import proguard.classfile.Method;
import proguard.classfile.visitor.ClassVisitor;
import proguard.classfile.visitor.MemberVisitor;

/** Resolves special method links omitted by ProGuard Core. */
/* Package access keeps the analysis-only resolver out of the public core API. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SignaturePolymorphicReferenceResolver {
  /** Method declaration flags required by JVMS signature-polymorphic resolution. */
  private static final int REQUIRED_FLAGS = AccessConstants.NATIVE | AccessConstants.VARARGS;

  /** Prefix shared by the native variable-arity declarations. */
  private static final String OBJECT_ARRAY_DESCRIPTOR = "([Ljava/lang/Object;)";

  /** Descriptor types retained until their referencing class enters closure. */
  private final Map<String, Set<String>> descriptorTypes;

  /** Looks up candidate and sibling classes by internal name. */
  private final Function<String, Clazz> classLookup;

  SignaturePolymorphicReferenceResolver(
      final Map<String, Set<String>> descriptorTypes, final Function<String, Clazz> classLookup) {
    this.descriptorTypes = descriptorTypes;
    this.classLookup = classLookup;
  }

  boolean recordIfSignaturePolymorphic(
      final Clazz referencingClass,
      final Clazz targetClass,
      final String memberName,
      final String memberDescriptor,
      final Map<String, Set<String>> unresolvedReferences) {
    if (!hasDeclaration(targetClass, memberName)) {
      return false;
    }
    for (final Type argumentType : Type.getArgumentTypes(memberDescriptor)) {
      recordType(referencingClass, argumentType, unresolvedReferences);
    }
    recordType(referencingClass, Type.getReturnType(memberDescriptor), unresolvedReferences);
    return true;
  }

  void enqueueDescriptorTypes(final Clazz referencingClass, final ClassVisitor classVisitor) {
    descriptorTypes.getOrDefault(referencingClass.getName(), Set.of()).stream()
        .map(classLookup)
        .filter(java.util.Objects::nonNull)
        .forEach(clazz -> clazz.accept(classVisitor));
  }

  private static boolean hasDeclaration(final Clazz targetClass, final String memberName) {
    if (!("invoke".equals(memberName) || "invokeExact".equals(memberName))) {
      return hasVarHandleDeclaration(targetClass, memberName);
    }
    final Clazz methodHandle = findSuperClass(targetClass, "java/lang/invoke/MethodHandle");
    if (methodHandle == null) {
      return false;
    }
    final Method declaration =
        methodHandle.findMethod(memberName, OBJECT_ARRAY_DESCRIPTOR + "Ljava/lang/Object;");
    return declaration != null && hasRequiredFlags(declaration);
  }

  private static boolean hasVarHandleDeclaration(final Clazz targetClass, final String memberName) {
    final Clazz varHandle = findSuperClass(targetClass, "java/lang/invoke/VarHandle");
    if (varHandle == null) {
      return false;
    }
    final AtomicBoolean hasDeclaration = new AtomicBoolean();
    varHandle.methodsAccept(
        new MemberVisitor() {
          @Override
          public void visitAnyMember(final Clazz owner, final Member declaration) {
            if (memberName.equals(declaration.getName(owner))
                && declaration.getDescriptor(owner).startsWith(OBJECT_ARRAY_DESCRIPTOR)
                && hasRequiredFlags(declaration)) {
              hasDeclaration.set(true);
            }
          }
        });
    return hasDeclaration.get();
  }

  private static boolean hasRequiredFlags(final Member declaration) {
    return (declaration.getAccessFlags() & REQUIRED_FLAGS) == REQUIRED_FLAGS;
  }

  private static Clazz findSuperClass(final Clazz targetClass, final String expectedName) {
    Clazz owner = targetClass;
    while (owner != null && !expectedName.equals(owner.getName())) {
      owner = owner.getSuperClass();
    }
    return owner;
  }

  private void recordType(
      final Clazz referencingClass,
      final Type descriptorType,
      final Map<String, Set<String>> unresolvedReferences) {
    final Type referenceType =
        descriptorType.getSort() == Type.ARRAY ? descriptorType.getElementType() : descriptorType;
    if (referenceType.getSort() != Type.OBJECT) {
      return;
    }
    final String className = referenceType.getInternalName();
    if (classLookup.apply(className) == null) {
      unresolvedReferences
          .computeIfAbsent(referencingClass.getName(), unused -> new TreeSet<>())
          .add(referencingClass.getName() + " -> class " + className);
      return;
    }
    descriptorTypes
        .computeIfAbsent(referencingClass.getName(), unused -> new TreeSet<>())
        .add(className);
  }
}
