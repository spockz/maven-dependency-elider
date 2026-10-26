/* WHY: Proves sibling declaration parsing is cached without sharing graph-local ProGuard state. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;
import proguard.classfile.kotlin.KotlinClassKindMetadata;
import proguard.classfile.kotlin.KotlinMetadata;

/** Tests per-snapshot declaration caching and fresh graph-local classes. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods",
  "PMD.LawOfDemeter",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
class ArchiveSnapshotTemplateTest {
  /** Platform declarations used to resolve generated fixture roots. */
  private static ClassPool objectPool;

  /** Isolates generated archive fixtures. */
  @TempDir Path temporaryDirectory;

  @BeforeAll
  static void readObjectClass() throws IOException {
    objectPool = new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 21);
  }

  @Test
  @DisplayName(
      "ADR-0003: sibling declarations parse once and materialize isolated initialized pools")
  void declarationTemplatesAreCachedAndMaterializedFresh() throws Exception {
    final byte[] ownerData = ownerBytes("fixture/Owner", "fixture/Base", "fixture/Contract");
    final Path archive =
        writeJar(
            "symbolic-library.jar",
            Map.of(
                "fixture/Base", classBytes("fixture/Base", Opcodes.ACC_PUBLIC, "java/lang/Object"),
                "fixture/Contract",
                    classBytes(
                        "fixture/Contract",
                        Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE,
                        "java/lang/Object"),
                "fixture/Owner", ownerData,
                "fixture/Target",
                    classBytes("fixture/Target", Opcodes.ACC_PUBLIC, "java/lang/Object")));
    final ArchiveSnapshot snapshot = ArchiveSnapshot.read(archive, false);

    final ClassPool first = snapshot.newLibraryClassPool();
    assertThat(snapshot.libraryDeclarationParseCount()).isEqualTo(4);
    final ClassPool second = snapshot.newLibraryClassPool();
    assertThat(snapshot.libraryDeclarationParseCount()).isEqualTo(4);
    assertThat(first).isNotSameAs(second);

    final LibraryClass firstOwner = (LibraryClass) first.getClass("fixture/Owner");
    final LibraryClass secondOwner = (LibraryClass) second.getClass("fixture/Owner");
    assertThat(firstOwner.getName()).isEqualTo("fixture/Owner");
    assertThat(firstOwner).isNotSameAs(secondOwner);
    assertThat(firstOwner.interfaceNames).isNotSameAs(secondOwner.interfaceNames);
    assertThat(firstOwner.fields).isNotSameAs(secondOwner.fields);
    assertThat(firstOwner.methods).isNotSameAs(secondOwner.methods);
    assertThat(firstOwner.fields[0]).isNotSameAs(secondOwner.fields[0]);
    assertThat(firstOwner.methods[0]).isNotSameAs(secondOwner.methods[0]);
    assertThat(firstOwner.interfaceNames).containsExactly("fixture/Contract");

    index(first);
    index(second);

    assertThat(firstOwner.superClass).isSameAs(first.getClass("fixture/Base"));
    assertThat(secondOwner.superClass).isSameAs(second.getClass("fixture/Base"));
    assertThat(firstOwner.superClass).isNotSameAs(secondOwner.superClass);
    assertThat(secondOwner.interfaceNames).containsExactly("fixture/Contract");
    assertThat(firstOwner.interfaceClasses).isNotEmpty();
    assertThat(secondOwner.interfaceClasses).isNotEmpty();
    assertThat(firstOwner.interfaceClasses[0]).isSameAs(first.getClass("fixture/Contract"));
    assertThat(secondOwner.interfaceClasses[0]).isSameAs(second.getClass("fixture/Contract"));
    assertThat(firstOwner.fields[0].referencedClass).isSameAs(first.getClass("fixture/Base"));
    assertThat(secondOwner.fields[0].referencedClass).isSameAs(second.getClass("fixture/Base"));
    assertThat(firstOwner.fields[0].referencedClass)
        .isNotSameAs(secondOwner.fields[0].referencedClass);
    assertThat(firstOwner.methods[0].referencedClasses[0])
        .isSameAs(first.getClass("fixture/Target"));
    assertThat(secondOwner.methods[0].referencedClasses[0])
        .isSameAs(second.getClass("fixture/Target"));
    assertThat(firstOwner.methods[0].referencedClasses)
        .isNotSameAs(secondOwner.methods[0].referencedClasses);
  }

  @Test
  @DisplayName("ADR-0003: empty-root queries leave sibling declaration templates lazy")
  void emptyRootsDeferLibraryDeclarationParsing() throws Exception {
    final Path candidatePath =
        writeJar(
            "rootless-candidate.jar",
            Map.of(
                "fixture/Root",
                classBytes("fixture/Root", Opcodes.ACC_PUBLIC, "java/lang/Object")));
    final Path siblingPath =
        writeJar(
            "rootless-sibling.jar",
            Map.of(
                "fixture/Unused",
                classBytes("fixture/Unused", Opcodes.ACC_PUBLIC, "java/lang/Object")));
    final ArchiveSnapshot candidate = ArchiveSnapshot.read(candidatePath, true);
    final ArchiveSnapshot sibling = ArchiveSnapshot.read(siblingPath, false);
    final PreparedAnalysisState prepared =
        ReferenceGraphBuilder.prepare(
            candidatePath,
            List.of(siblingPath),
            objectPool,
            false,
            Set.of(),
            (path, isCandidate) -> isCandidate ? candidate : sibling);

    assertThat(prepared.analyze(List.of()).retainedClasses()).containsExactly("fixture/Root");
    assertThat(sibling.libraryDeclarationParseCount()).isZero();

    prepared.analyze(List.of("fixture.Root"));

    assertThat(sibling.libraryDeclarationParseCount()).isEqualTo(1);
  }

  @Test
  @DisplayName("ADR-0003: metadata-bearing library declarations are freshly parsed per context")
  void metadataClassesUseFreshLibraryReadsPerContext() throws Exception {
    final byte[] metadataData = classResource("kotlin/Unit.class");
    final Path archive = writeJar("metadata-library.jar", Map.of("kotlin/Unit", metadataData));
    final ArchiveSnapshot snapshot = ArchiveSnapshot.read(archive, false);

    final ClassPool first = snapshot.newLibraryClassPool();
    assertThat(snapshot.libraryDeclarationParseCount()).isEqualTo(2);
    final ClassPool second = snapshot.newLibraryClassPool();
    assertThat(snapshot.libraryDeclarationParseCount()).isEqualTo(3);

    final LibraryClass firstOwner = (LibraryClass) first.getClass("kotlin/Unit");
    final LibraryClass secondOwner = (LibraryClass) second.getClass("kotlin/Unit");
    assertThat(firstOwner.kotlinMetadata).isInstanceOf(KotlinMetadata.class);
    assertThat(firstOwner.kotlinMetadata).isNotSameAs(secondOwner.kotlinMetadata);

    index(first);
    index(second);

    assertThat(((KotlinClassKindMetadata) firstOwner.kotlinMetadata).referencedClass)
        .isSameAs(firstOwner);
    assertThat(((KotlinClassKindMetadata) secondOwner.kotlinMetadata).referencedClass)
        .isSameAs(secondOwner);
    assertThat(((KotlinClassKindMetadata) firstOwner.kotlinMetadata).referencedClass)
        .isNotSameAs(((KotlinClassKindMetadata) secondOwner.kotlinMetadata).referencedClass);
    assertThat(firstOwner.fields[0].referencedClass).isSameAs(firstOwner);
    assertThat(secondOwner.fields[0].referencedClass).isSameAs(secondOwner);
    assertThat(firstOwner.fields[0].referencedClass)
        .isNotSameAs(secondOwner.fields[0].referencedClass);
  }

  @Test
  @DisplayName("ADR-0003: malformed Kotlin metadata reports a fail-closed diagnostic")
  void malformedKotlinMetadataIsNotSilentlyIgnored() throws Exception {
    final Path archive =
        writeJar(
            "malformed-metadata-library.jar",
            Map.of("fixture/UnsupportedMetadata", unsupportedMetadataClass()));
    final ArchiveSnapshot snapshot = ArchiveSnapshot.read(archive, false);

    assertThatThrownBy(snapshot::newLibraryClassPool)
        .isInstanceOf(IOException.class)
        .hasMessageContaining(
            "Could not safely read Kotlin metadata for fixture/UnsupportedMetadata")
        .hasMessageContaining("Encountered corrupt @kotlin/Metadata");
  }

  private static byte[] classResource(final String path) throws IOException {
    try (InputStream input = ClassLoader.getSystemResourceAsStream(path)) {
      if (input == null) {
        throw new IOException("Missing class resource: " + path);
      }
      return input.readAllBytes();
    }
  }

  private Path writeJar(final String name, final Map<String, byte[]> classes) throws IOException {
    final Path archive = temporaryDirectory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return archive;
  }

  private static void index(final ClassPool libraries) {
    new ReferenceGraphIndexer(new ClassPool(), libraries, Set.of()).build();
  }

  private static byte[] ownerBytes(
      final String name, final String superName, final String interfaceName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
        name,
        null,
        superName,
        new String[] {interfaceName});
    writer.visitField(Opcodes.ACC_PUBLIC, "base", "Lfixture/Base;", null, null).visitEnd();
    writer.visitMethod(
        Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "target", "()Lfixture/Target;", null, null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classBytes(final String name, final int access, final String superName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, access, name, null, superName, null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] unsupportedMetadataClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "fixture/UnsupportedMetadata",
        null,
        "java/lang/Object",
        null);
    final AnnotationVisitor metadata = writer.visitAnnotation("Lkotlin/Metadata;", true);
    metadata.visit("k", 1);
    final AnnotationVisitor version = metadata.visitArray("mv");
    version.visit(null, 99);
    version.visit(null, 0);
    version.visit(null, 0);
    version.visitEnd();
    final AnnotationVisitor data1 = metadata.visitArray("d1");
    data1.visit(null, "");
    data1.visitEnd();
    final AnnotationVisitor data2 = metadata.visitArray("d2");
    data2.visit(null, "");
    data2.visitEnd();
    metadata.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }
}
