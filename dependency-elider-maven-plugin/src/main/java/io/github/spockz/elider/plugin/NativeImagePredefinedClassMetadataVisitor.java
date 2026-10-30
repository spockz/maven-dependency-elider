/* WHY: Isolates class-level metadata callbacks from member bytecode traversal. */

package io.github.spockz.elider.plugin;

import java.util.Set;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;

/** Collects type references stored in class-level metadata. */
final class NativeImagePredefinedClassMetadataVisitor extends ClassVisitor {
  /** WHY: Metadata callbacks contribute to the shared predefined class closure. */
  private final Set<String> references;

  /* package */
  NativeImagePredefinedClassMetadataVisitor(final Set<String> references) {
    super(Opcodes.ASM9);
    this.references = references;
  }

  @Override
  public void visitOuterClass(final String owner, final String method, final String descriptor) {
    NativeImagePredefinedBytecodeTypes.addInternalName(owner, references);
    NativeImagePredefinedBytecodeTypes.addDescriptorTypes(descriptor, references);
  }

  @Override
  public void visitNestHost(final String nestHost) {
    NativeImagePredefinedBytecodeTypes.addInternalName(nestHost, references);
  }

  @Override
  public void visitNestMember(final String nestMember) {
    NativeImagePredefinedBytecodeTypes.addInternalName(nestMember, references);
  }

  @Override
  public void visitPermittedSubclass(final String permittedSubclass) {
    NativeImagePredefinedBytecodeTypes.addInternalName(permittedSubclass, references);
  }

  @Override
  public ModuleVisitor visitModule(
      final String moduleName, final int access, final String version) {
    return new ModuleVisitor(Opcodes.ASM9) {
      @Override
      public void visitUse(final String service) {
        NativeImagePredefinedBytecodeTypes.addInternalName(service, references);
      }

      @Override
      public void visitProvide(final String service, final String... providers) {
        NativeImagePredefinedBytecodeTypes.addInternalName(service, references);
        for (final String provider : providers) {
          NativeImagePredefinedBytecodeTypes.addInternalName(provider, references);
        }
      }
    };
  }

  @Override
  public void visitInnerClass(
      final String name, final String outerName, final String innerName, final int access) {
    NativeImagePredefinedBytecodeTypes.addInternalName(name, references);
    NativeImagePredefinedBytecodeTypes.addInternalName(outerName, references);
  }
}
