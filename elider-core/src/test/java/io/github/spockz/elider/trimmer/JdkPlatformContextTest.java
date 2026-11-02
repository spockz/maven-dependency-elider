/* WHY: Verifies active-runtime module identity and JDK class table population.
 * It checks incomplete-view refusal without depending on private JDK archives. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.lang.module.ModuleFinder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ModuleVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.TooManyMethods",
  "PMD.DoNotUseThreads",
  "PMD.LawOfDemeter",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidDuplicateLiterals"
})
class JdkPlatformContextTest {
  @TempDir Path temporaryDirectory;

  @Test
  @DisplayName("P02: active system modules bind identity and full platform class declarations")
  void activeRuntimePlatformUsesSystemModules() throws Exception {
    try (JdkPlatformContext context = new JdkPlatformContext()) {
      final JdkPlatformContext.PlatformSnapshot snapshot = context.snapshot();
      final List<String> expectedModules =
          ModuleFinder.ofSystem().findAll().stream()
              .map(reference -> reference.descriptor().name())
              .sorted()
              .toList();

      assertAll(
          "active runtime platform",
          () ->
              assertAll(
                  "snapshot metadata",
                  () -> assertThat(snapshot.sourceKind()).isEqualTo("jrt"),
                  () ->
                      assertThat(snapshot.runtimeRelease()).isEqualTo(Runtime.version().feature()),
                  () ->
                      assertThat(snapshot.moduleIdentities())
                          .extracting(JdkPlatformContext.ModuleIdentity::moduleName)
                          .containsExactlyElementsOf(expectedModules),
                  () ->
                      assertThat(snapshot.moduleIdentities())
                          .allSatisfy(
                              identity -> assertThat(identity.sha256()).matches("[0-9a-f]{64}")),
                  () -> assertThat(snapshot.identity()).contains("java.base"),
                  () -> assertThat(context.snapshot()).isSameAs(snapshot)),
          () -> {
            final JdkApiClassTableReader reader = new JdkApiClassTableReader();
            final ClassPool first = reader.read(snapshot);
            final ClassPool second = reader.read(snapshot);
            assertAll(
                "JDK class table declarations",
                () -> assertThat(first.getClass("java/lang/Object")).isNotNull(),
                () ->
                    assertThat(first.getClass("java/lang/String"))
                        .isNotSameAs(second.getClass("java/lang/String")),
                () -> assertStringModel(first));
          });
    }
  }

  @Test
  @DisplayName("P02: resource-only system modules do not make a complete platform fail")
  void resourceOnlyModuleIsIncludedWithoutClassRequirement() throws Exception {
    final Path base =
        writeModule(
            "fixture.base", Map.of("java/lang/Object.class", classBytes("java/lang/Object", null)));
    final Path resources =
        writeModule(
            "fixture.resources", Map.of("META-INF/services/example.Service", new byte[] {1}));

    try (JdkPlatformContext context = new JdkPlatformContext(ModuleFinder.of(base, resources))) {
      final JdkPlatformContext.PlatformSnapshot snapshot = context.snapshot();
      final JdkPlatformContext.ModuleIdentity resourceIdentity =
          snapshot.moduleIdentities().stream()
              .filter(identity -> "fixture.resources".equals(identity.moduleName()))
              .findFirst()
              .orElseThrow();
      assertAll(
          "resource-only module identity",
          () -> assertThat(resourceIdentity.classCount()).isZero(),
          () -> assertThat(resourceIdentity.sha256()).matches("[0-9a-f]{64}"),
          () ->
              assertThat(new JdkApiClassTableReader().read(snapshot).getClass("java/lang/Object"))
                  .isNotNull());
    }
  }

  @Test
  @DisplayName("P02: a runtime platform without java.lang.Object is refused explicitly")
  void missingObjectFailsPlatformCapture() throws Exception {
    final Path incomplete =
        writeModule(
            "fixture.incomplete",
            Map.of("fixture/Only.class", classBytes("fixture/Only", "java/lang/Object")));
    try (JdkPlatformContext context = new JdkPlatformContext(ModuleFinder.of(incomplete))) {
      assertThatThrownBy(context::snapshot)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("java/lang/Object");
    }
  }

  @Test
  @DisplayName("P02: module content and descriptor changes invalidate the identity and templates")
  void changedModuleBytesChangeIdentityAndParsedMembers() throws Exception {
    final Path firstModule =
        writeModule(
            "fixture.base",
            "fixture-base-baseline",
            null,
            Map.of(
                "java/lang/Object.class", classBytesWithMethod("java/lang/Object", "oldMember")));
    final Path changedClassModule =
        writeModule(
            "fixture.base",
            "fixture-base-class-changed",
            null,
            Map.of(
                "java/lang/Object.class", classBytesWithMethod("java/lang/Object", "newMember")));
    final Path changedDescriptorModule =
        writeModule(
            "fixture.base",
            "fixture-base-descriptor-changed",
            "2",
            Map.of(
                "java/lang/Object.class", classBytesWithMethod("java/lang/Object", "oldMember")));
    final JdkPlatformContext.PlatformSnapshot first = capture(firstModule);
    final JdkPlatformContext.PlatformSnapshot changedClass = capture(changedClassModule);
    final JdkPlatformContext.PlatformSnapshot changedDescriptor = capture(changedDescriptorModule);

    final LibraryClass firstObject =
        (LibraryClass) new JdkApiClassTableReader().read(first).getClass("java/lang/Object");
    final LibraryClass changedClassObject =
        (LibraryClass) new JdkApiClassTableReader().read(changedClass).getClass("java/lang/Object");
    final LibraryClass changedDescriptorObject =
        (LibraryClass)
            new JdkApiClassTableReader().read(changedDescriptor).getClass("java/lang/Object");
    assertAll(
        "module bytes and descriptors independently contribute to cache identity",
        () -> assertThat(changedClass.identity()).isNotEqualTo(first.identity()),
        () ->
            assertThat(changedClass.moduleIdentities().getFirst().sha256())
                .isNotEqualTo(first.moduleIdentities().getFirst().sha256()),
        () -> assertThat(changedDescriptor.identity()).isNotEqualTo(first.identity()),
        () ->
            assertThat(changedDescriptor.moduleIdentities().getFirst().sha256())
                .isNotEqualTo(first.moduleIdentities().getFirst().sha256()),
        () -> assertThat(firstObject.findMethod("oldMember", "()V")).isNotNull(),
        () -> assertThat(firstObject.findMethod("newMember", "()V")).isNull(),
        () -> assertThat(changedClassObject.findMethod("newMember", "()V")).isNotNull(),
        () -> assertThat(changedClassObject.findMethod("oldMember", "()V")).isNull(),
        () -> assertThat(changedDescriptorObject.findMethod("oldMember", "()V")).isNotNull(),
        () -> assertThat(changedDescriptorObject.findMethod("newMember", "()V")).isNull());
  }

  @Test
  @DisplayName("P02: a listed malformed class fails platform capture")
  void malformedRuntimeClassFailsPlatformCapture() throws Exception {
    final Path base =
        writeModule(
            "fixture.base", Map.of("java/lang/Object.class", classBytes("java/lang/Object", null)));
    final Path malformed =
        writeModule("fixture.malformed", Map.of("fixture/Broken.class", new byte[] {1, 2, 3}));
    try (JdkPlatformContext context = new JdkPlatformContext(ModuleFinder.of(base, malformed))) {
      assertThatThrownBy(context::snapshot)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("fixture/Broken.class");
    }
  }

  @Test
  @DisplayName("P02: concurrent snapshot requests publish the same complete runtime identity")
  void concurrentCaptureReturnsOneSnapshot() throws Exception {
    try (JdkPlatformContext context = new JdkPlatformContext();
        ExecutorService executor = Executors.newFixedThreadPool(4)) {
      final CountDownLatch ready = new CountDownLatch(4);
      final CountDownLatch start = new CountDownLatch(1);
      final List<Future<JdkPlatformContext.PlatformSnapshot>> results =
          java.util.stream.IntStream.range(0, 4)
              .mapToObj(
                  ignored ->
                      executor.submit(
                          () -> {
                            ready.countDown();
                            start.await();
                            return context.snapshot();
                          }))
              .toList();
      ready.await();
      start.countDown();
      final JdkPlatformContext.PlatformSnapshot published = results.getFirst().get();
      for (final Future<JdkPlatformContext.PlatformSnapshot> result : results) {
        assertThat(result.get()).isSameAs(published);
      }
    }
  }

  @Test
  @DisplayName("P02: closed runtime platform contexts refuse further snapshots")
  void closedContextRefusesSnapshot() throws Exception {
    try (JdkPlatformContext context = new JdkPlatformContext()) {
      context.close();
      assertThatThrownBy(context::snapshot)
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("closed");
    }
  }

  private Path writeModule(final String name, final Map<String, byte[]> entries)
      throws IOException {
    return writeModule(name, null, entries);
  }

  private Path writeModule(
      final String name, final String version, final Map<String, byte[]> entries)
      throws IOException {
    return writeModule(name, name, version, entries);
  }

  private Path writeModule(
      final String name,
      final String archiveName,
      final String version,
      final Map<String, byte[]> entries)
      throws IOException {
    final String fileSuffix = version == null ? "" : "-" + version;
    final Path archive = temporaryDirectory.resolve(archiveName + fileSuffix + ".jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
      output.putNextEntry(new JarEntry("module-info.class"));
      output.write(moduleInfo(name, version));
      output.closeEntry();
      for (final Map.Entry<String, byte[]> entry : entries.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey()));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return archive;
  }

  private JdkPlatformContext.PlatformSnapshot capture(final Path module) throws IOException {
    try (JdkPlatformContext context = new JdkPlatformContext(ModuleFinder.of(module))) {
      return context.snapshot();
    }
  }

  private static byte[] moduleInfo(final String name, final String version) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V9, Opcodes.ACC_MODULE, "module-info", null, null, null);
    final ModuleVisitor module = writer.visitModule(name, 0, version);
    module.visitRequire("java.base", 0, null);
    module.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classBytes(final String name, final String parent) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, parent, null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classBytesWithMethod(final String name, final String methodName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, null, null);
    writer.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void assertStringModel(final ClassPool jdkClassTable) {
    final LibraryClass stringClass = (LibraryClass) jdkClassTable.getClass("java/lang/String");
    if (stringClass == null) {
      throw new AssertionError("java.lang.String is absent from the runtime JDK class table");
    }
    assertAll(
        "java.lang.String hierarchy and members",
        () -> assertThat(stringClass.superClassName).isEqualTo("java/lang/Object"),
        () -> assertThat(stringClass.findMethod("length", "()I")).isNotNull());
  }
}
