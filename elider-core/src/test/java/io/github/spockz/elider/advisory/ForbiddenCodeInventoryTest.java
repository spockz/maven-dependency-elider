// WHY: Exercises physical policy observations through class files, including inherited declarations
// and nested names.

package io.github.spockz.elider.advisory;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Physical assessment fixtures exercise bytecode and archive boundaries together. */
@SuppressWarnings({
  "PMD.UnitTestAssertionsShouldIncludeMessage",
  "PMD.TooManyMethods",
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.PublicMemberInNonPublicType",
  "PMD.UseVarargs",
  "PMD.UncommentedEmptyMethodBody",
  "PMD.UnusedPrivateMethod",
  "PMD.ImplicitFunctionalInterface",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter"
})
class ForbiddenCodeInventoryTest {
  static class Parent {
    public void inherited(int[] values) {}

    private void secret() {}
  }

  static class Child extends Parent {
    public void local(String value) {}
  }

  interface Generic<T> {
    T value();
  }

  static class Bridge implements Generic<String> {
    @Override
    public String value() {
      return "value";
    }

    @SuppressWarnings({
      "checkstyle:GoogleMethodName",
      "PMD.MethodNamingConventions",
      "PMD.MethodWithSameNameAsEnclosingClass"
    })
    public int Bridge() {
      return 1;
    }
  }

  @Test
  void preservesBothBridgeDescriptorsAndConstructor(@TempDir final Path root) throws IOException {
    copyClass(root, Bridge.class);
    final ForbiddenSymbol method =
        ForbiddenSymbol.parse(Bridge.class.getCanonicalName() + "#value()");
    final ForbiddenSymbol constructor =
        ForbiddenSymbol.parse(Bridge.class.getCanonicalName() + "#Bridge()");
    final ForbiddenSymbol binaryConstructor =
        ForbiddenSymbol.parse(Bridge.class.getName() + "#Bridge()");
    final Map<ForbiddenSymbol, ForbiddenCodeInventory.Result> results =
        ForbiddenCodeInventory.scan(
            root, List.of(method, constructor, binaryConstructor), Set.of());
    assertAll(
        () ->
            assertEquals(
                Set.of("()Ljava/lang/Object;", "()Ljava/lang/String;"),
                results.get(method).evidence().stream()
                    .map(ForbiddenCodeInventory.Evidence::descriptor)
                    .collect(java.util.stream.Collectors.toSet())),
        () ->
            assertEquals(
                Set.of("()V", "()I"),
                results.get(constructor).evidence().stream()
                    .map(ForbiddenCodeInventory.Evidence::descriptor)
                    .collect(java.util.stream.Collectors.toSet())),
        () ->
            assertEquals(
                results.get(constructor).evidence(), results.get(binaryConstructor).evidence()));
  }

  @Test
  void inspectsDeclarationsAndInheritedMethods(@TempDir final Path root) throws IOException {
    copyClass(root, Parent.class);
    copyClass(root, Child.class);
    final String child = Child.class.getCanonicalName();
    final ForbiddenSymbol inherited = ForbiddenSymbol.parse(child + "#inherited(int[])");
    final ForbiddenSymbol local = ForbiddenSymbol.parse(child + "#local(java.lang.String)");
    final ForbiddenSymbol absent = ForbiddenSymbol.parse(child + "#local(int)");
    final ForbiddenSymbol missing = ForbiddenSymbol.parse("example.Missing");
    final ForbiddenSymbol secret = ForbiddenSymbol.parse(child + "#secret()");
    final ForbiddenSymbol objectMethod = ForbiddenSymbol.parse(child + "#toString()");
    final Map<ForbiddenSymbol, ForbiddenCodeInventory.Result> results =
        ForbiddenCodeInventory.scan(
            root, List.of(inherited, local, absent, missing, secret, objectMethod), Set.of());
    assertAll(
        () ->
            assertEquals(ForbiddenCodeInventory.Status.VIOLATION, results.get(inherited).status()),
        () -> assertEquals(ForbiddenCodeInventory.Status.VIOLATION, results.get(local).status()),
        () -> assertEquals(ForbiddenCodeInventory.Status.PASS, results.get(absent).status()),
        () -> assertEquals(ForbiddenCodeInventory.Status.PASS, results.get(missing).status()),
        () -> assertEquals(ForbiddenCodeInventory.Status.PASS, results.get(secret).status()),
        () ->
            assertEquals(
                ForbiddenCodeInventory.Status.UNKNOWN, results.get(objectMethod).status()));
  }

  @Test
  void rejectsMalformedSymbols() {
    assertAll(
        () ->
            assertThrows(IllegalArgumentException.class, () -> ForbiddenSymbol.parse("x.Y#method")),
        () ->
            assertThrows(
                IllegalArgumentException.class, () -> ForbiddenSymbol.parse("x.Y#method(void)")),
        () -> assertThrows(IllegalArgumentException.class, () -> ForbiddenSymbol.parse("x.***")));
  }

  @Test
  void acceptsSingleSegmentPackageWildcard() {
    assertEquals("example.*", ForbiddenSymbol.parse("example.*").value());
  }

  @Test
  void resolvesInheritanceInTheCorrectReleaseView(@TempDir final Path root) throws IOException {
    final Path archive = root.resolve("staged.jar.tmp");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
      writeEntry(
          zip, "example/Parent.class", fixtureClass("example/Parent", "java/lang/Object", true));
      writeEntry(
          zip,
          "META-INF/versions/21/example/Parent.class",
          fixtureClass("example/Parent", "java/lang/Object", false));
      writeEntry(
          zip,
          "META-INF/versions/21/example/Child.class",
          fixtureClass("example/Child", "example/Parent", false));
    }
    final ForbiddenSymbol symbol = ForbiddenSymbol.parse("example.Child#target()");
    final ForbiddenCodeInventory.Result result =
        ForbiddenCodeInventory.scan(archive, List.of(symbol), Set.of()).get(symbol);
    assertEquals(ForbiddenCodeInventory.Status.PASS, result.status());
  }

  @Test
  void examinesDuplicatePhysicalEntries(@TempDir final Path root) throws IOException {
    final Path archive = root.resolve("duplicate.jar.tmp");
    final byte[] contents = fixtureClass("example/Duplicate", "java/lang/Object", true);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
      writeEntry(zip, "a.class", contents);
      writeEntry(zip, "b.class", contents);
    }
    final byte[] bytes = Files.readAllBytes(archive);
    final byte[] name = "b.class".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    for (int i = 0; i <= bytes.length - name.length; i++) {
      if (java.util.Arrays.equals(bytes, i, i + name.length, name, 0, name.length)) {
        bytes[i] = 'a';
      }
    }
    Files.write(archive, bytes);
    final ForbiddenSymbol symbol = ForbiddenSymbol.parse("example.Duplicate#target()");
    final ForbiddenCodeInventory.Result result =
        ForbiddenCodeInventory.scan(archive, List.of(symbol), Set.of()).get(symbol);
    assertAll(
        () -> assertEquals(ForbiddenCodeInventory.Status.VIOLATION, result.status()),
        () -> assertEquals(2, result.evidence().size()));
  }

  @Test
  void directCallsUseTheEffectiveReleaseView(@TempDir final Path root) throws IOException {
    final Path archive = root.resolve("runtime-caller.jar");
    final String base = "example/Calls.class";
    final String override = "META-INF/versions/21/" + base;
    final String future = "META-INF/versions/22/" + base;
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(Attributes.Name.MULTI_RELEASE, "true");
    final byte[] directCall = runtimeCaller();
    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(archive), manifest)) {
      writeEntry(jar, base, directCall);
      writeEntry(jar, override, fixtureClass("example/Calls", "java/lang/Object", false));
      writeEntry(jar, future, directCall);
    }
    final ForbiddenSymbol symbol = ForbiddenSymbol.parse("java.lang.System#gc()");
    final ForbiddenRuntimeCalls calls = ForbiddenRuntimeCalls.index(List.of(symbol));
    assertAll(
        () ->
            assertEquals(
                List.of(new ForbiddenCodeInventory.Evidence("java.lang.System", "()V", base, 0)),
                calls.scan(archive, Set.of(), null, 20).get(symbol)),
        () -> assertEquals(Map.of(), calls.scan(archive, Set.of(), null, 21)),
        () ->
            assertEquals(
                List.of(new ForbiddenCodeInventory.Evidence("java.lang.System", "()V", future, 22)),
                calls.scan(archive, Set.of(), null, 22).get(symbol)),
        () ->
            assertEquals(
                List.of(new ForbiddenCodeInventory.Evidence("java.lang.System", "()V", base, 0)),
                calls.scan(archive, Set.of(), Map.of(future, base), 21).get(symbol)),
        () -> assertEquals(Map.of(), calls.scan(archive, Set.of("example.Calls"), null, 22)));
  }

  private static byte[] runtimeCaller() {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "example/Calls", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    method.visitCode();
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "gc", "()V", false);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  @Test
  void directCallsRequireUnambiguousCallerMetadataButNoRuntimeDeclarations(@TempDir final Path root)
      throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "example/Calls", null, "java/lang/Object", null);
    writer.visitInnerClass(
        "java/lang/Example$Nested", "java/lang/Example", "Nested", Opcodes.ACC_PUBLIC);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
    method.visitCode();
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, "java/lang/System", "symbolicExample", "()V", false);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, "java/lang/Example$Nested", "symbolicExample", "()V", false);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, "java/lang/Example/Nested", "symbolicExample", "()V", false);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, "java/lang/Other$Inner", "symbolicExample", "()V", false);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
    writer.visitEnd();
    final Path output = Files.createDirectories(root.resolve("example"));
    Files.write(output.resolve("Calls.class"), writer.toByteArray());
    final ForbiddenSymbol declarationMissing =
        ForbiddenSymbol.parse("java.lang.System#symbolicExample()");
    final ForbiddenSymbol exactBinary =
        ForbiddenSymbol.parse("java.lang.Example$Nested#symbolicExample()");
    final ForbiddenSymbol ambiguous =
        ForbiddenSymbol.parse("java.lang.Example.Nested#symbolicExample()");
    final ForbiddenSymbol unresolved =
        ForbiddenSymbol.parse("java.lang.Other.Inner#symbolicExample()");
    final ForbiddenRuntimeCalls calls =
        ForbiddenRuntimeCalls.index(
            List.of(declarationMissing, exactBinary, ambiguous, unresolved));
    final Map<ForbiddenSymbol, List<ForbiddenCodeInventory.Evidence>> matches =
        calls.scan(root, Set.of(), null, Runtime.version().feature());
    assertAll(
        () ->
            assertEquals(
                List.of(
                    new ForbiddenCodeInventory.Evidence(
                        "java.lang.System", "()V", "example/Calls.class", 0)),
                matches.get(declarationMissing)),
        () ->
            assertEquals(
                List.of(
                    new ForbiddenCodeInventory.Evidence(
                        "java.lang.Example$Nested", "()V", "example/Calls.class", 0)),
                matches.get(exactBinary)),
        () -> assertFalse(ForbiddenRuntimeCalls.unambiguous(matches.get(ambiguous))),
        () -> assertFalse(matches.containsKey(unresolved)));
  }

  @Test
  void unresolvedNestedConstructorParameterIsUnknown(@TempDir final Path root) throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "example/Thing", null, "java/lang/Object", null);
    writer
        .visitMethod(Opcodes.ACC_PUBLIC, "<init>", "(Lexample/Outer$Inner;)V", null, null)
        .visitEnd();
    writer.visitEnd();
    final Path target = root.resolve("example/Thing.class");
    Files.createDirectories(target.getParent());
    Files.write(target, writer.toByteArray());
    final ForbiddenSymbol symbol =
        ForbiddenSymbol.parse("example.Thing#Thing(example.Outer.Inner)");
    assertEquals(
        ForbiddenCodeInventory.Status.UNKNOWN,
        ForbiddenCodeInventory.scan(root, List.of(symbol), Set.of()).get(symbol).status());
  }

  private static byte[] fixtureClass(final String name, final String parent, final boolean method) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, parent, null);
    if (method) {
      writer
          .visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "target", "()V", null, null)
          .visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void writeEntry(
      final ZipOutputStream zip, final String name, final byte[] contents) throws IOException {
    zip.putNextEntry(new ZipEntry(name));
    zip.write(contents);
    zip.closeEntry();
  }

  @Test
  void rejectsInvalidArchive(@TempDir final Path root) throws IOException {
    final Path archive = root.resolve("invalid.jar");
    Files.writeString(archive, "not a zip");
    assertThrows(
        IOException.class,
        () ->
            ForbiddenCodeInventory.scan(
                archive, List.of(ForbiddenSymbol.parse("a.Missing")), Set.of()));
  }

  @Test
  void rejectsMalformedClass(@TempDir final Path root) throws IOException {
    Files.write(root.resolve("Broken.class"), new byte[] {0, 1, 2});
    assertThrows(
        IOException.class,
        () ->
            ForbiddenCodeInventory.scan(
                root, List.of(ForbiddenSymbol.parse("example.Broken")), Set.of()));
  }

  @Test
  void expandsPackageAndNestedWildcards(@TempDir final Path root) throws IOException {
    copyClass(root, Parent.class);
    copyClass(root, Child.class);
    final ForbiddenSymbol nested =
        ForbiddenSymbol.parse(ForbiddenCodeInventoryTest.class.getCanonicalName() + "$*");
    final ForbiddenSymbol directPackage =
        ForbiddenSymbol.parse("io.github.spockz.elider.advisory.*");
    final Map<ForbiddenSymbol, ForbiddenCodeInventory.Result> results =
        ForbiddenCodeInventory.scan(root, List.of(nested, directPackage), Set.of());
    assertAll(
        () -> assertEquals(2, results.get(nested).evidence().size()),
        () ->
            assertEquals(ForbiddenCodeInventory.Status.PASS, results.get(directPackage).status()));
  }

  @Test
  void inspectsProjectedMultiReleaseEntries(@TempDir final Path root) throws IOException {
    final Path archive = root.resolve("input.jar");
    final String classPath = Child.class.getName().replace('.', '/') + ".class";
    final String upper = "META-INF/versions/21/" + classPath;
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive));
        java.io.InputStream input =
            Thread.currentThread().getContextClassLoader().getResourceAsStream(classPath)) {
      zip.putNextEntry(new ZipEntry(upper));
      input.transferTo(zip);
      zip.closeEntry();
    }
    final ForbiddenSymbol symbol =
        ForbiddenSymbol.parse(Child.class.getCanonicalName() + "#local(java.lang.String)");
    final ForbiddenCodeInventory.Result retained =
        ForbiddenCodeInventory.scan(archive, List.of(symbol), Set.of(), Map.of(upper, classPath))
            .get(symbol);
    final ForbiddenCodeInventory.Result removed =
        ForbiddenCodeInventory.scan(archive, List.of(symbol), Set.of(), Map.of()).get(symbol);
    assertAll(
        () -> assertEquals(ForbiddenCodeInventory.Status.VIOLATION, retained.status()),
        () -> assertEquals(classPath, retained.evidence().getFirst().entry()),
        () -> assertEquals(0, retained.evidence().getFirst().tier()),
        () -> assertEquals(ForbiddenCodeInventory.Status.PASS, removed.status()));
  }

  private static void copyClass(final Path root, final Class<?> type) throws IOException {
    final String name = type.getName().replace('.', '/') + ".class";
    final Path target = root.resolve(name);
    Files.createDirectories(target.getParent());
    try (java.io.InputStream input =
        Thread.currentThread().getContextClassLoader().getResourceAsStream(name)) {
      Files.copy(input, target);
    }
  }
}
