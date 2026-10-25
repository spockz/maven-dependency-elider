/* WHY: Exercises per-JAR class closure against real compiled class files and verifies that the
 * retained subset still loads and runs in an isolated JVM class loader. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipOutputStream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;

/** Exercises ADR-0003 closure with compiled JARs and isolated runtime verification. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.AtLeastOneConstructor",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.CyclomaticComplexity",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CommentDefaultAccessModifier"
})
class DependencyJarTrimmerTest {
  /** Test source package prefix. */
  private static final String SOURCE_ROOT = "package fixture; ";

  /** Isolates generated fixture files. */
  @TempDir Path temporaryDirectory;

  /** The explicit Java 21 API used by test analysis. */
  private static ClassPool jdkLibraryPool;

  /** Compiler output used to assemble the sibling archive. */
  private Path fixtureOutputDirectory;

  @BeforeAll
  static void readJdk21Api() throws IOException {
    jdkLibraryPool = new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 21);
    assertThat(jdkLibraryPool.getClass("java/lang/Object")).isNotNull();
  }

  @Test
  @DisplayName("ADR-0003: ct.sym reader uses the explicit compiler API release")
  void ctSymReaderUsesExplicitReleaseAndRejectsUnavailableRelease() throws IOException {
    assertThat(jdkLibraryPool.size()).isGreaterThan(1_000);
    assertThat(jdkLibraryPool.getClass("java/util/List")).isNotNull();
    final ClassPool runtimeApi =
        new JdkApiClassPoolReader()
            .read(Path.of(System.getProperty("java.home")), Runtime.version().feature());
    assertThat(runtimeApi.size()).isGreaterThan(1_000);
    assertThat(runtimeApi.getClass("java/lang/Object")).isNotNull();
    assertThatThrownBy(
            () -> new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 99))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("No JDK API signatures");
  }

  @Test
  @DisplayName("ADR-0003: current JDK API falls back to unchanged jmods")
  void currentReleaseUsesJmodsWhenCtSymHasNoClasses() throws IOException {
    final Path javaHome = Path.of(System.getProperty("java.home"));
    final Path testJavaHome = temporaryDirectory.resolve("current-jdk");
    Files.createDirectories(testJavaHome.resolve("lib"));
    Files.copy(javaHome.resolve("release"), testJavaHome.resolve("release"));
    Files.createSymbolicLink(testJavaHome.resolve("jmods"), javaHome.resolve("jmods"));
    try (ZipOutputStream ignored =
        new ZipOutputStream(Files.newOutputStream(testJavaHome.resolve("lib/ct.sym")))) {
      ignored.finish();
    }

    final ClassPool currentApi =
        new JdkApiClassPoolReader().read(testJavaHome, Runtime.version().feature());
    assertThat(currentApi.size()).isGreaterThan(1_000);
    assertThat(currentApi.getClass("java/lang/Object")).isNotNull();
  }

  @Test
  @DisplayName("ADR-0003: closes root references and omits unrelated candidate classes")
  void retainsTransitiveReferencesAndOmitsUnreferencedClass() throws Exception {
    final Path candidateJar = compileFixtureJar(false);
    final DependencyJarTrimmer.TrimAnalysis result =
        analyze(candidateJar, List.of(writeSiblingJar()), List.of("fixture.A"));

    assertThat(result.retainedClasses())
        .contains(
            "fixture/A",
            "fixture/B",
            "fixture/Helper",
            "fixture/Problem",
            "fixture/Outer",
            "fixture/Outer$Inner",
            "fixture/DynamicOnly",
            "fixture/RecordHolder",
            "fixture/RecordOnly",
            "fixture/RecordOnlyType",
            "fixture/SignatureOnly",
            "fixture/SignatureBound",
            "fixture/CondyUse",
            "fixture/CondyOnly",
            "fixture/InternalBase",
            "fixture/InternalGrandparent",
            "fixture/InternalMarker")
        .doesNotContain("fixture/C");
    assertThat(result.totalClasses()).isGreaterThan(result.retainedClasses().size());
  }

  @Test
  @DisplayName("ADR-0003: retained class bytes verify and resolve runtime metadata")
  void retainedClassesPassJvmVerificationAndMetadataUse() throws Exception {
    final Path candidateJar = compileFixtureJar(false);
    final Path siblingJar = writeSiblingJar();
    final DependencyJarTrimmer.TrimAnalysis result =
        analyze(candidateJar, List.of(siblingJar), List.of("fixture.A"));
    final Path retainedJar = writeRetainedJar(candidateJar, result.retainedClasses());
    assertThat(result.retainedClasses()).contains("fixture/HierarchyBase", "fixture/SiblingOnly");

    try (URLClassLoader classLoader =
        new URLClassLoader(
            new java.net.URL[] {retainedJar.toUri().toURL(), siblingJar.toUri().toURL()},
            ClassLoader.getPlatformClassLoader())) {
      final Class<?> entryClass = classLoader.loadClass("fixture.A");
      final Object entry = entryClass.getConstructor().newInstance();
      final Object resultValue = entryClass.getMethod("value").invoke(entry);
      assertThat(resultValue.getClass().getName()).isEqualTo("fixture.B");
      assertThat(
              resultValue.getClass().getMethod("helper").invoke(resultValue).getClass().getName())
          .isEqualTo("fixture.Helper");
      final Object innerValue = entryClass.getMethod("inner").invoke(entry);
      assertThat(innerValue.getClass().getName()).isEqualTo("fixture.Outer$Inner");
      assertThat(innerValue.getClass().getDeclaringClass().getName()).isEqualTo("fixture.Outer");
      assertThat((List<?>) entryClass.getMethod("generic").invoke(entry)).isNotEmpty();
      assertThat(entryClass.getMethod("record").invoke(entry).getClass().getName())
          .isEqualTo("fixture.RecordHolder");
      assertThat(entryClass.getMethod("value").getExceptionTypes())
          .extracting(Class::getName)
          .contains("fixture.Problem");
      assertThat(entryClass.getMethod("generic").getGenericReturnType().getTypeName())
          .contains("fixture.B");
      final Object record = entryClass.getMethod("record").invoke(entry);
      assertThat(record.getClass().getRecordComponents()[0].getGenericType().getTypeName())
          .isEqualTo("fixture.B");
      final java.lang.annotation.Annotation recordOnly =
          record
              .getClass()
              .getRecordComponents()[0]
              .getAnnotation(
                  classLoader
                      .loadClass("fixture.RecordOnly")
                      .asSubclass(java.lang.annotation.Annotation.class));
      assertThat(recordOnly).isNotNull();
      assertThat(recordOnly.annotationType().getMethod("value").invoke(recordOnly))
          .isEqualTo(classLoader.loadClass("fixture.RecordOnlyType"));
      assertThat(entryClass.getMethod("dynamic").invoke(entry)).isNull();
      assertThat(entryClass.getMethod("signature").getGenericReturnType().getTypeName())
          .contains("fixture.SignatureOnly");
      assertThat(
              classLoader
                  .loadClass("fixture.SignatureOnly")
                  .getTypeParameters()[0]
                  .getBounds()[0]
                  .getTypeName())
          .isEqualTo("fixture.SignatureBound");
      final Class<?> creatorClass = entryClass.getField("creator").getType();
      final Object creator = creatorClass.getConstructor().newInstance();
      final Object siblingRoot = creatorClass.getMethod("create").invoke(creator);
      assertThat(
              siblingRoot
                  .getClass()
                  .getMethod("inherited")
                  .invoke(siblingRoot)
                  .getClass()
                  .getName())
          .isEqualTo("fixture.SiblingOnly");
    }
  }

  @Test
  @DisplayName("ADR-0003: unresolved candidate references fail closed")
  void unresolvedReferencesFailClosedEvenWhenTheyAreOutsideRequestedRoots() throws Exception {
    final Path candidateJar = compileFixtureJar(true);

    assertThatThrownBy(
            () -> analyze(candidateJar, List.of(writeSiblingJar()), List.of("fixture.A")))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining("fixture/Ghost");
  }

  @Test
  @DisplayName("ADR-0003: reachable sibling hierarchy gaps fail closed")
  void unresolvedReachableSiblingHierarchyFailsClosed() throws Exception {
    final Path candidateJar = compileFixtureJar(false);
    final Path siblingJar = writeSiblingJar(false);

    assertThatThrownBy(() -> analyze(candidateJar, List.of(siblingJar), List.of("fixture.A")))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining("fixture/lib/LibChild -> class fixture/lib/LibParent");
  }

  @Test
  @DisplayName("ADR-0003: refuses ambiguous multi-release sibling class definitions")
  void multiReleaseSiblingLibrariesFailClosed() throws Exception {
    final Path candidateJar = compileFixtureJar(false);
    final Path multiReleaseJar = writeMultiReleaseSiblingJar();

    assertThatThrownBy(() -> analyze(candidateJar, List.of(multiReleaseJar), List.of("fixture.A")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("multi-release library JAR");
  }

  @Test
  @DisplayName("ADR-0003: candidate module and multi-release archives fail closed")
  void candidateModuleAndMultiReleaseArchivesFailClosed() throws Exception {
    final Path modularJar = writeBoundaryJar("modular.jar", "module-info.class");
    final Path multiReleaseJar =
        writeBoundaryJar("multi-release.jar", "META-INF/versions/9/fixture/A.class");
    final Path nestedArchive = writeBoundaryJar("nested.jar", "lib/inner.jar");

    assertThatThrownBy(() -> analyze(modularJar, List.of("fixture.A")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("explicit modular JAR");
    assertThatThrownBy(() -> analyze(multiReleaseJar, List.of("fixture.A")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("multi-release candidate JAR");
    assertThatThrownBy(() -> analyze(nestedArchive, List.of("fixture.A")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Nested archives are not supported");
  }

  private Path compileFixtureJar(final boolean omitGhost) throws IOException {
    final Path sourceDirectory = temporaryDirectory.resolve(omitGhost ? "unresolved-src" : "src");
    final Path outputDirectory =
        temporaryDirectory.resolve(omitGhost ? "unresolved-classes" : "classes");
    fixtureOutputDirectory = outputDirectory;
    Files.createDirectories(sourceDirectory.resolve("fixture"));
    Files.createDirectories(sourceDirectory.resolve("fixture/lib"));
    Files.createDirectories(outputDirectory);
    Files.writeString(
        sourceDirectory.resolve("fixture/Ghost.java"), SOURCE_ROOT + "public class Ghost {}");
    final Map<String, String> sources =
        Map.ofEntries(
            Map.entry(
                "A.java",
                SOURCE_ROOT
                    + "public class A extends InternalBase implements InternalMarker { "
                    + "public B value() throws Problem { "
                    + "Runnable r = () -> new DynamicOnly().touch(); "
                    + "r.run(); return new B(); } "
                    + "public Outer.Inner inner() { return new Outer.Inner(); } "
                    + "public java.util.List<B> generic() { return java.util.List.of(new B()); } "
                    + "public RecordHolder record() { return new RecordHolder(new B()); } "
                    + "public SignatureOnly<?> signature() { return null; } "
                    + "public fixture.lib.Creator creator; "
                    + "public Object dynamic() { return CondyUse.value(); } }"),
            Map.entry(
                "B.java",
                SOURCE_ROOT + "public class B { public Helper helper() { return new Helper(); } }"),
            Map.entry("C.java", SOURCE_ROOT + "public class C {}"),
            Map.entry(
                "DynamicOnly.java",
                SOURCE_ROOT + "public class DynamicOnly { public void touch() {} }"),
            Map.entry("Helper.java", SOURCE_ROOT + "public class Helper {}"),
            Map.entry(
                "Outer.java", SOURCE_ROOT + "public class Outer { public static class Inner {} }"),
            Map.entry("Problem.java", SOURCE_ROOT + "public class Problem extends Exception {}"),
            Map.entry(
                "RecordHolder.java",
                SOURCE_ROOT
                    + "public record RecordHolder(@RecordOnly(RecordOnlyType.class) B value) {}"),
            Map.entry(
                "RecordOnly.java",
                SOURCE_ROOT
                    + "@java.lang.annotation.Target("
                    + "java.lang.annotation.ElementType.RECORD_COMPONENT) "
                    + "@java.lang.annotation.Retention("
                    + "java.lang.annotation.RetentionPolicy.RUNTIME) "
                    + "public @interface RecordOnly { Class<?> value(); }"),
            Map.entry("RecordOnlyType.java", SOURCE_ROOT + "public class RecordOnlyType {}"),
            Map.entry(
                "SignatureOnly.java",
                SOURCE_ROOT + "public class SignatureOnly<T extends SignatureBound> {}"),
            Map.entry("SignatureBound.java", SOURCE_ROOT + "public class SignatureBound {}"),
            Map.entry(
                "CondyUse.java",
                SOURCE_ROOT
                    + "public class CondyUse { public static Object value() { return null; } }"),
            Map.entry("CondyOnly.java", SOURCE_ROOT + "public class CondyOnly {}"),
            Map.entry(
                "InternalBase.java",
                SOURCE_ROOT + "public class InternalBase extends InternalGrandparent {}"),
            Map.entry(
                "InternalGrandparent.java", SOURCE_ROOT + "public class InternalGrandparent {}"),
            Map.entry("InternalMarker.java", SOURCE_ROOT + "public interface InternalMarker {}"),
            Map.entry("HierarchyBase.java", SOURCE_ROOT + "public class HierarchyBase {}"),
            Map.entry("SiblingOnly.java", SOURCE_ROOT + "public class SiblingOnly {}"),
            Map.entry(
                "SiblingRoot.java",
                SOURCE_ROOT + "public class SiblingRoot extends fixture.lib.LibChild {}"),
            Map.entry(
                "lib/LibChild.java",
                "package fixture.lib; public class LibChild extends LibParent {}"),
            Map.entry(
                "lib/LibParent.java",
                "package fixture.lib; public class LibParent extends fixture.HierarchyBase { "
                    + "public fixture.SiblingOnly inherited() { "
                    + "return new fixture.SiblingOnly(); } }"),
            Map.entry(
                "lib/Creator.java",
                "package fixture.lib; public class Creator { "
                    + "public LibChild create() { return new LibChild(); } }"),
            Map.entry(
                "GhostUser.java",
                SOURCE_ROOT
                    + "public class GhostUser { public Ghost missing() { return null; } }"));
    for (final Map.Entry<String, String> source : sources.entrySet()) {
      Files.writeString(sourceDirectory.resolve("fixture/" + source.getKey()), source.getValue());
    }

    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IllegalStateException("Tests require a JDK compiler");
    }
    final List<String> arguments =
        List.of(
            "--release",
            "21",
            "-d",
            outputDirectory.toString(),
            sourceDirectory.resolve("fixture/Ghost.java").toString(),
            sourceDirectory.resolve("fixture/A.java").toString(),
            sourceDirectory.resolve("fixture/B.java").toString(),
            sourceDirectory.resolve("fixture/C.java").toString(),
            sourceDirectory.resolve("fixture/DynamicOnly.java").toString(),
            sourceDirectory.resolve("fixture/Helper.java").toString(),
            sourceDirectory.resolve("fixture/Outer.java").toString(),
            sourceDirectory.resolve("fixture/Problem.java").toString(),
            sourceDirectory.resolve("fixture/RecordHolder.java").toString(),
            sourceDirectory.resolve("fixture/RecordOnly.java").toString(),
            sourceDirectory.resolve("fixture/RecordOnlyType.java").toString(),
            sourceDirectory.resolve("fixture/SignatureOnly.java").toString(),
            sourceDirectory.resolve("fixture/SignatureBound.java").toString(),
            sourceDirectory.resolve("fixture/CondyUse.java").toString(),
            sourceDirectory.resolve("fixture/CondyOnly.java").toString(),
            sourceDirectory.resolve("fixture/InternalBase.java").toString(),
            sourceDirectory.resolve("fixture/InternalGrandparent.java").toString(),
            sourceDirectory.resolve("fixture/InternalMarker.java").toString(),
            sourceDirectory.resolve("fixture/HierarchyBase.java").toString(),
            sourceDirectory.resolve("fixture/SiblingOnly.java").toString(),
            sourceDirectory.resolve("fixture/SiblingRoot.java").toString(),
            sourceDirectory.resolve("fixture/lib/LibChild.java").toString(),
            sourceDirectory.resolve("fixture/lib/LibParent.java").toString(),
            sourceDirectory.resolve("fixture/lib/Creator.java").toString(),
            sourceDirectory.resolve("fixture/GhostUser.java").toString());
    if (compiler.run(null, null, null, arguments.toArray(String[]::new)) != 0) {
      throw new IOException("Could not compile ProGuard Core test fixture");
    }
    Files.write(outputDirectory.resolve("fixture/CondyUse.class"), condyUseClass());
    final Path jarPath = temporaryDirectory.resolve(omitGhost ? "unresolved.jar" : "candidate.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath));
        java.util.stream.Stream<Path> classFiles = Files.walk(outputDirectory)) {
      for (final Path classFile :
          classFiles.filter(path -> path.toString().endsWith(".class")).toList()) {
        if (omitGhost && "Ghost.class".equals(classFile.getFileName().toString())) {
          continue;
        }
        if (classFile.toString().contains("fixture/lib/")) {
          continue;
        }
        final String entryName =
            outputDirectory
                .relativize(classFile)
                .toString()
                .replace(java.io.File.separatorChar, '/');
        output.putNextEntry(new JarEntry(entryName));
        Files.copy(classFile, output);
        output.closeEntry();
      }
    }
    return jarPath;
  }

  private Path writeRetainedJar(final Path candidateJar, final Set<String> retainedNames)
      throws IOException {
    final Path outputJar = temporaryDirectory.resolve("retained.jar");
    final Set<String> retainedEntries =
        retainedNames.stream()
            .map(name -> name + ".class")
            .collect(java.util.stream.Collectors.toSet());
    try (java.util.jar.JarFile input = new java.util.jar.JarFile(candidateJar.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(outputJar))) {
      for (final JarEntry entry : java.util.Collections.list(input.entries())) {
        if (retainedEntries.contains(entry.getName())) {
          output.putNextEntry(new JarEntry(entry.getName()));
          try (java.io.InputStream stream = input.getInputStream(entry)) {
            stream.transferTo(output);
          }
          output.closeEntry();
        }
      }
    }
    return outputJar;
  }

  private Path writeSiblingJar() throws IOException {
    return writeSiblingJar(true);
  }

  private Path writeSiblingJar(final boolean includeParent) throws IOException {
    final Path siblingJar = temporaryDirectory.resolve("sibling.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(siblingJar))) {
      final List<String> names =
          includeParent
              ? List.of("Creator", "LibChild", "LibParent")
              : List.of("Creator", "LibChild");
      for (final String name : names) {
        final String entryName = "fixture/lib/" + name + ".class";
        output.putNextEntry(new JarEntry(entryName));
        Files.copy(fixtureOutputDirectory.resolve(entryName), output);
        output.closeEntry();
      }
    }
    return siblingJar;
  }

  private Path writeBoundaryJar(final String fileName, final String classEntry) throws IOException {
    final Path candidateJar = temporaryDirectory.resolve(fileName);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(candidateJar))) {
      output.putNextEntry(new JarEntry(classEntry));
      output.write(new byte[0]);
      output.closeEntry();
    }
    return candidateJar;
  }

  private Path writeMultiReleaseSiblingJar() throws IOException {
    final Path siblingJar = temporaryDirectory.resolve("multi-release-sibling.jar");
    final Path classFile = fixtureOutputDirectory.resolve("fixture/lib/LibChild.class");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(siblingJar))) {
      output.putNextEntry(new JarEntry("META-INF/MANIFEST.MF"));
      output.write(
          "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n".getBytes(StandardCharsets.UTF_8));
      output.closeEntry();
      output.putNextEntry(new JarEntry("META-INF/versions/9/fixture/lib/LibChild.class"));
      Files.copy(classFile, output);
      output.closeEntry();
    }
    return siblingJar;
  }

  private byte[] condyUseClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "fixture/CondyUse", null, "java/lang/Object", null);
    final org.objectweb.asm.MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "value", "()Ljava/lang/Object;", null, null);
    method.visitCode();
    method.visitLdcInsn(
        new ConstantDynamic(
            "missingOnlyInCondy",
            "Lfixture/CondyOnly;",
            new Handle(
                Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/ConstantBootstraps",
                "nullConstant",
                "(Ljava/lang/invoke/MethodHandles$Lookup;"
                    + "Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;",
                false)));
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static DependencyJarTrimmer.TrimAnalysis analyze(
      final Path candidateJar, final List<Path> siblingLibraries, final List<String> roots)
      throws IOException {
    return new DependencyJarTrimmer()
        .analyze(candidateJar, siblingLibraries, jdkLibraryPool, roots);
  }

  private static DependencyJarTrimmer.TrimAnalysis analyze(
      final Path candidateJar, final List<String> roots) throws IOException {
    return analyze(candidateJar, List.of(), roots);
  }
}
