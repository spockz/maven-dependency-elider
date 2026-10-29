/* WHY: Detects static ServiceLoader invocations with constant parameters across scanned bytecode
 * to provide positive proof of service usage without relying on whole-inventory conservative
 * roots. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Scans class bytecode for ServiceLoader calls with constant class/string targets. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidCatchingGenericException",
  "PMD.UseVarargs"
})
public final class ServiceLoaderCallScanner {
  private static final String SERVICE_LOADER_INTERNAL = "java/util/ServiceLoader";
  private static final String CLASS_INTERNAL = "java/lang/Class";
  private static final String CLINIT_NAME = "<clinit>";
  private static final Object UNKNOWN = new Object();

  /** Result of a ServiceLoader bytecode scan with proven service interface names. */
  public record ScanResult(Set<String> provenServiceInterfaces) {
    /** Canonicalizes proven service names to dot format. */
    public ScanResult {
      Objects.requireNonNull(provenServiceInterfaces, "provenServiceInterfaces");
      final SortedSet<String> sorted = new TreeSet<>();
      for (final String service : provenServiceInterfaces) {
        if (service != null && !service.isBlank()) {
          sorted.add(TraceData.normalizeToDot(service.trim()));
        }
      }
      provenServiceInterfaces = Collections.unmodifiableSet(sorted);
    }
  }

  /** Creates a new ServiceLoader call scanner. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public ServiceLoaderCallScanner() {}

  /** Scans a directory of class files for ServiceLoader invocations. */
  public ScanResult scan(final Path rootDirectory) throws IOException {
    if (rootDirectory == null || !Files.isDirectory(rootDirectory)) {
      return new ScanResult(Set.of());
    }
    final Set<String> proven = new HashSet<>();
    final Map<String, Object> staticConstants = new HashMap<>();
    final Path scope = rootDirectory.toAbsolutePath().normalize();
    try (Stream<Path> paths = Files.walk(scope)) {
      final List<Path> classFiles =
          paths
              .filter(Files::isRegularFile)
              .filter(
                  p -> {
                    final Path fileName = p.getFileName();
                    return fileName != null && fileName.toString().endsWith(".class");
                  })
              .toList();
      for (final Path classFile : classFiles) {
        scanConstants(classFile, staticConstants);
      }
      for (final Path classFile : classFiles) {
        scanMethods(classFile, staticConstants, proven);
      }
    }
    return new ScanResult(proven);
  }

  /** Scans class bytes directly from an input stream. */
  public ScanResult scan(final InputStream classInputStream) throws IOException {
    final Set<String> proven = new HashSet<>();
    final Map<String, Object> staticConstants = new HashMap<>();
    final byte[] bytes = classInputStream.readAllBytes();
    new ClassReader(bytes).accept(new ConstantCollectorVisitor(staticConstants), 0);
    new ClassReader(bytes).accept(new ServiceLoaderCallVisitor(staticConstants, proven), 0);
    return new ScanResult(proven);
  }

  private static void scanConstants(final Path path, final Map<String, Object> constants)
      throws IOException {
    final BasicFileAttributes attributes =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!attributes.isRegularFile()) {
      return;
    }
    try (InputStream inputStream = Files.newInputStream(path)) {
      new ClassReader(inputStream).accept(new ConstantCollectorVisitor(constants), 0);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not scan class constants: " + path, exception);
    }
  }

  private static void scanMethods(
      final Path path, final Map<String, Object> constants, final Set<String> proven)
      throws IOException {
    final BasicFileAttributes attributes =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!attributes.isRegularFile()) {
      return;
    }
    try (InputStream inputStream = Files.newInputStream(path)) {
      new ClassReader(inputStream).accept(new ServiceLoaderCallVisitor(constants, proven), 0);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not scan ServiceLoader calls: " + path, exception);
    }
  }

  private static final class ConstantCollectorVisitor extends ClassVisitor {
    private final Map<String, Object> constants;
    private String currentClass;

    ConstantCollectorVisitor(final Map<String, Object> constants) {
      super(Opcodes.ASM9);
      this.constants = constants;
    }

    @Override
    public void visit(
        final int version,
        final int access,
        final String name,
        final String signature,
        final String superName,
        final String[] interfaces) {
      this.currentClass = name;
      super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public FieldVisitor visitField(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final Object value) {
      final boolean isStaticFinal =
          (access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) != 0;
      if (isStaticFinal && value instanceof String strValue) {
        constants.put(currentClass + "#" + name, strValue);
      }
      return super.visitField(access, name, descriptor, signature, value);
    }

    @Override
    public MethodVisitor visitMethod(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final String[] exceptions) {
      if (CLINIT_NAME.equals(name)) {
        return new ClinitConstantVisitor(currentClass, constants);
      }
      return super.visitMethod(access, name, descriptor, signature, exceptions);
    }
  }

  private static final class ClinitConstantVisitor extends MethodVisitor {
    private final String currentClass;
    private final Map<String, Object> constants;
    private Object lastConstant = UNKNOWN;

    ClinitConstantVisitor(final String currentClass, final Map<String, Object> constants) {
      super(Opcodes.ASM9);
      this.currentClass = currentClass;
      this.constants = constants;
    }

    @Override
    public void visitLdcInsn(final Object value) {
      if (value instanceof String str) {
        lastConstant = str;
      } else if (value instanceof Type type && type.getSort() == Type.OBJECT) {
        lastConstant = type.getClassName();
      } else {
        lastConstant = UNKNOWN;
      }
      super.visitLdcInsn(value);
    }

    @Override
    public void visitFieldInsn(
        final int opcode, final String owner, final String name, final String descriptor) {
      if (opcode == Opcodes.PUTSTATIC && owner.equals(currentClass) && lastConstant != UNKNOWN) {
        constants.put(owner + "#" + name, lastConstant);
      }
      super.visitFieldInsn(opcode, owner, name, descriptor);
    }
  }

  private static final class ServiceLoaderCallVisitor extends ClassVisitor {
    private final Map<String, Object> constants;
    private final Set<String> proven;
    private String currentClass;

    ServiceLoaderCallVisitor(final Map<String, Object> constants, final Set<String> proven) {
      super(Opcodes.ASM9);
      this.constants = constants;
      this.proven = proven;
    }

    @Override
    public void visit(
        final int version,
        final int access,
        final String name,
        final String signature,
        final String superName,
        final String[] interfaces) {
      this.currentClass = name;
      super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final String[] exceptions) {
      return new MethodServiceLoaderTracker(currentClass, constants, proven);
    }
  }

  private static final class MethodServiceLoaderTracker extends MethodVisitor {
    private final String currentClass;
    private final Map<String, Object> constants;
    private final Set<String> proven;
    private final Deque<Object> stack = new ArrayDeque<>();
    private final Map<Integer, Object> locals = new HashMap<>();

    MethodServiceLoaderTracker(
        final String currentClass, final Map<String, Object> constants, final Set<String> proven) {
      super(Opcodes.ASM9);
      this.currentClass = currentClass;
      this.constants = constants;
      this.proven = proven;
    }

    @Override
    public void visitInsn(final int opcode) {
      switch (opcode) {
        case Opcodes.ACONST_NULL,
            Opcodes.ICONST_M1,
            Opcodes.ICONST_0,
            Opcodes.ICONST_1,
            Opcodes.ICONST_2,
            Opcodes.ICONST_3,
            Opcodes.ICONST_4,
            Opcodes.ICONST_5,
            Opcodes.LCONST_0,
            Opcodes.LCONST_1,
            Opcodes.FCONST_0,
            Opcodes.FCONST_1,
            Opcodes.FCONST_2,
            Opcodes.DCONST_0,
            Opcodes.DCONST_1 ->
            push(UNKNOWN);
        case Opcodes.POP -> pop();
        case Opcodes.POP2 -> {
          pop();
          pop();
        }
        case Opcodes.DUP -> {
          final Object top = pop();
          push(top);
          push(top);
        }
        default -> {
          if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN || opcode == Opcodes.ATHROW) {
            stack.clear();
          }
        }
      }
      super.visitInsn(opcode);
    }

    @Override
    public void visitLdcInsn(final Object value) {
      if (value instanceof String str) {
        push(str);
      } else if (value instanceof Type type && type.getSort() == Type.OBJECT) {
        push(type.getClassName());
      } else {
        push(UNKNOWN);
      }
      super.visitLdcInsn(value);
    }

    @Override
    public void visitVarInsn(final int opcode, final int varIndex) {
      switch (opcode) {
        case Opcodes.ASTORE, Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE -> {
          final Object val = pop();
          locals.put(varIndex, val);
        }
        case Opcodes.ALOAD, Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD -> {
          final Object val = locals.getOrDefault(varIndex, UNKNOWN);
          push(val);
        }
        default -> push(UNKNOWN);
      }
      super.visitVarInsn(opcode, varIndex);
    }

    @Override
    public void visitFieldInsn(
        final int opcode, final String owner, final String name, final String descriptor) {
      if (opcode == Opcodes.GETSTATIC) {
        final Object constVal = constants.get(owner + "#" + name);
        push(constVal != null ? constVal : UNKNOWN);
      } else if (opcode == Opcodes.PUTSTATIC) {
        final Object val = pop();
        if (owner.equals(currentClass) && val != UNKNOWN) {
          constants.put(owner + "#" + name, val);
        }
      } else if (opcode == Opcodes.GETFIELD) {
        pop();
        push(UNKNOWN);
      } else if (opcode == Opcodes.PUTFIELD) {
        pop();
        pop();
      }
      super.visitFieldInsn(opcode, owner, name, descriptor);
    }

    @Override
    public void visitMethodInsn(
        final int opcode,
        final String owner,
        final String name,
        final String descriptor,
        final boolean isInterface) {
      final Type[] argTypes = Type.getArgumentTypes(descriptor);
      final Object[] args = new Object[argTypes.length];
      for (int i = argTypes.length - 1; i >= 0; i--) {
        args[i] = pop();
      }
      if (opcode != Opcodes.INVOKESTATIC) {
        pop();
      }

      if (SERVICE_LOADER_INTERNAL.equals(owner)
          && ("load".equals(name) || "loadInstalled".equals(name))) {
        inspectServiceLoaderCall(name, descriptor, args);
      } else if (CLASS_INTERNAL.equals(owner)
          && "forName".equals(name)
          && args.length >= 1
          && args[0] instanceof String className) {
        push(className);
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        return;
      }

      final Type returnType = Type.getReturnType(descriptor);
      if (returnType.getSort() != Type.VOID) {
        push(UNKNOWN);
      }
      super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }

    private void inspectServiceLoaderCall(
        final String methodName, final String descriptor, final Object[] args) {
      if (args.length == 0) {
        return;
      }
      final int targetArgIndex =
          "load".equals(methodName)
                  && descriptor.contains("Ljava/lang/ModuleLayer;")
                  && args.length > 1
              ? 1
              : 0;
      final Object target = args[targetArgIndex];
      if (target instanceof String targetClass && !targetClass.isBlank()) {
        proven.add(TraceData.normalizeToDot(targetClass));
      }
    }

    private void push(final Object value) {
      stack.push(value != null ? value : UNKNOWN);
    }

    private Object pop() {
      return stack.isEmpty() ? UNKNOWN : stack.pop();
    }
  }
}
