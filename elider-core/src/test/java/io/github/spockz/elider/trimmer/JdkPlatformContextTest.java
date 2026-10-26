/* WHY: Proves a platform snapshot binds fingerprints and deferred parsing to one exact archive
 * capture while keeping each ProGuard class pool mutable and local to its analysis. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.LibraryClass;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.TooManyMethods",
  "PMD.DoNotUseThreads",
  "PMD.LawOfDemeter",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidDuplicateLiterals"
})
class JdkPlatformContextTest {
  private static final int RELEASE_17 = 17;
  private static final int RELEASE_21 = 21;
  private static final String CLASS_NAME = "fixture/Api";

  @TempDir Path temporaryDirectory;

  @Test
  @DisplayName("ADR-0003: changed source bytes get a fresh identity despite stable size and mtime")
  void exactIdentityChangesWithSameSizeRestoredTimestamp() throws Exception {
    final Path javaHome = javaHome("changed-content");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    writeCtSym(
        ctSym, "H/java.base/" + CLASS_NAME + ".sig", classBytes(CLASS_NAME, Opcodes.ACC_PUBLIC));
    final long sourceSize = Files.size(ctSym);
    final FileTime sourceTime = Files.getLastModifiedTime(ctSym);
    final String firstIdentity;
    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      final JdkPlatformContext.PlatformSnapshot snapshot = context.snapshot(RELEASE_17);
      firstIdentity = snapshot.identity();
      assertThat(context.capturedStorageBytes()).isEqualTo(sourceSize);
    }

    writeCtSym(
        ctSym,
        "H/java.base/" + CLASS_NAME + ".sig",
        classBytes(CLASS_NAME, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL));
    Files.setLastModifiedTime(ctSym, sourceTime);
    assertThat(Files.size(ctSym)).isEqualTo(sourceSize);
    assertThat(Files.getLastModifiedTime(ctSym)).isEqualTo(sourceTime);

    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      assertThat(context.snapshot(RELEASE_17).identity()).isNotEqualTo(firstIdentity);
    }
  }

  @Test
  @DisplayName(
      "ADR-0003: deferred parsing consumes the captured bytes after the live JDK file changes")
  void deferredParseUsesCapturedArchiveBytes() throws Exception {
    final Path javaHome = javaHome("deferred-parse");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    writeCtSym(
        ctSym, "L/java.base/fixture/Before.sig", classBytes("fixture/Before", Opcodes.ACC_PUBLIC));

    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      final JdkPlatformContext.PlatformSnapshot snapshot = context.snapshot(RELEASE_21);
      writeCtSym(
          ctSym, "L/java.base/fixture/After.sig", classBytes("fixture/After", Opcodes.ACC_PUBLIC));

      final ClassPool classes = new JdkApiClassPoolReader().read(snapshot);
      assertThat(classes.getClass("fixture/Before")).isNotNull();
      assertThat(classes.getClass("fixture/After")).isNull();
    }
  }

  @Test
  @DisplayName("ADR-0003: release and JDK location are part of platform source identity")
  void releaseAndJdkLocationDoNotCollide() throws Exception {
    final Path javaHome = javaHome("release-identity");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    writeZip(
        ctSym,
        Map.of(
            "H/java.base/fixture/Api17.sig", classBytes("fixture/Api17", Opcodes.ACC_PUBLIC),
            "L/java.base/fixture/Api21.sig", classBytes("fixture/Api21", Opcodes.ACC_PUBLIC)));
    final Path otherJdk = javaHome("other-release-identity");
    Files.copy(ctSym, otherJdk.resolve("lib/ct.sym"));

    try (JdkPlatformContext first = new JdkPlatformContext(javaHome);
        JdkPlatformContext second = new JdkPlatformContext(otherJdk)) {
      final JdkPlatformContext.PlatformSnapshot release17 = first.snapshot(RELEASE_17);
      final JdkPlatformContext.PlatformSnapshot release21 = first.snapshot(RELEASE_21);
      final JdkPlatformContext.PlatformSnapshot otherHome = second.snapshot(RELEASE_17);
      assertThat(release17.identity()).isNotEqualTo(release21.identity());
      assertThat(release17.identity()).isNotEqualTo(otherHome.identity());
      assertThat(first.capturedStorageBytes()).isEqualTo(Files.size(ctSym));
    }
  }

  @Test
  @DisplayName(
      "ADR-0003: JMOD fallback identity binds release evidence and the ordered module inventory")
  void jmodFallbackCapturesReleaseAndEveryModule() throws Exception {
    final Path firstHome = jmodHome("jmod-first", "fixture/First");
    final Path secondHome = jmodHome("jmod-second", "fixture/First", "fixture/Second");

    try (JdkPlatformContext first = new JdkPlatformContext(firstHome);
        JdkPlatformContext second = new JdkPlatformContext(secondHome)) {
      final JdkPlatformContext.PlatformSnapshot firstSnapshot =
          first.snapshot(Runtime.version().feature());
      final JdkPlatformContext.PlatformSnapshot secondSnapshot =
          second.snapshot(Runtime.version().feature());
      assertThat(firstSnapshot.sourceKind()).isEqualTo("jmods");
      assertThat(firstSnapshot.identity()).isNotEqualTo(secondSnapshot.identity());
      assertThat(firstSnapshot.sourceIdentities()).hasSize(3);
      assertThat(secondSnapshot.sourceIdentities()).hasSize(4);
      assertThat(first.capturedStorageBytes())
          .isEqualTo(
              firstSnapshot.sourceIdentities().stream()
                  .mapToLong(JdkPlatformContext.SourceIdentity::size)
                  .sum());
      final ClassPool classes = new JdkApiClassPoolReader().read(firstSnapshot);
      assertThat(classes.getClass("fixture/First")).isNotNull();
    }
  }

  @Test
  @DisplayName("ADR-0003: concurrent same-key release requests publish one complete snapshot")
  void concurrentCaptureReturnsOneSnapshot() throws Exception {
    final Path javaHome = javaHome("concurrent-capture");
    writeCtSym(
        javaHome.resolve("lib/ct.sym"),
        "L/java.base/" + CLASS_NAME + ".sig",
        classBytes(CLASS_NAME, Opcodes.ACC_PUBLIC));
    try (JdkPlatformContext context = new JdkPlatformContext(javaHome);
        ExecutorService executor = Executors.newFixedThreadPool(8)) {
      final CountDownLatch ready = new CountDownLatch(8);
      final CountDownLatch start = new CountDownLatch(1);
      final List<Future<JdkPlatformContext.PlatformSnapshot>> results = new ArrayList<>();
      for (int index = 0; index < 8; index++) {
        results.add(
            executor.submit(
                () -> {
                  ready.countDown();
                  start.await();
                  return context.snapshot(RELEASE_21);
                }));
      }
      ready.await();
      start.countDown();
      final JdkPlatformContext.PlatformSnapshot published = results.getFirst().get();
      for (final Future<JdkPlatformContext.PlatformSnapshot> result : results) {
        assertThat(result.get()).isSameAs(published);
      }
      assertThat(context.capturedStorageBytes())
          .isEqualTo(Files.size(javaHome.resolve("lib/ct.sym")));
    }
  }

  @Test
  @DisplayName("ADR-0003: failed platform capture leaves no partial value and can be retried")
  void failedCaptureCanRetryWithoutPartialStorage() throws Exception {
    final Path javaHome = javaHome("retry-capture");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    Files.writeString(ctSym, "not-a-zip");

    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      assertThatThrownBy(() -> context.snapshot(RELEASE_21)).isInstanceOf(IOException.class);
      assertThat(context.capturedStorageBytes()).isZero();
      writeCtSym(
          ctSym, "L/java.base/" + CLASS_NAME + ".sig", classBytes(CLASS_NAME, Opcodes.ACC_PUBLIC));
      assertThat(context.snapshot(RELEASE_21).sourceIdentities()).hasSize(1);
      assertThat(context.capturedStorageBytes()).isEqualTo(Files.size(ctSym));
    }
  }

  @Test
  @DisplayName("ADR-0003: failed cleanup leaves the context closed and permits cleanup retry")
  @SuppressWarnings("PMD.UseTryWithResources")
  void failedCleanupCanRetry() throws Exception {
    final AtomicBoolean failFirstDelete = new AtomicBoolean(true);
    final AtomicReference<Path> snapshotDirectory = new AtomicReference<>();
    final JdkPlatformContext context =
        new JdkPlatformContext(
            temporaryDirectory,
            path -> {
              snapshotDirectory.compareAndSet(null, path);
              if (failFirstDelete.compareAndSet(true, false)) {
                throw new IOException("injected deletion failure");
              }
              return Files.deleteIfExists(path);
            });
    try {
      assertThatThrownBy(context::close)
          .isInstanceOf(IOException.class)
          .hasMessage("injected deletion failure");
      final Path failedPath = snapshotDirectory.get();
      assertThat(failedPath).isNotNull();
      assertThat(Files.exists(failedPath)).isTrue();
      assertThatThrownBy(() -> context.snapshot(RELEASE_21))
          .isInstanceOf(IllegalStateException.class)
          .hasMessage("JDK platform context is closed");

      context.close();
      assertThat(Files.exists(failedPath)).isFalse();
    } finally {
      context.close();
    }
  }

  @Test
  @DisplayName(
      "ADR-0003: archive capture defers class declaration parsing and readers get isolated pools")
  void captureDefersParsingAndReadersDoNotShareMutableClasses() throws Exception {
    final Path javaHome = javaHome("deferred-malformed-class");
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    writeCtSym(ctSym, "L/java.base/fixture/Broken.sig", new byte[] {1, 2, 3});

    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      final JdkPlatformContext.PlatformSnapshot malformed = context.snapshot(RELEASE_21);
      assertThat(malformed.identity()).isNotBlank();
      assertThatThrownBy(() -> new JdkApiClassPoolReader().read(malformed))
          .isInstanceOf(IOException.class);
    }

    writeCtSym(
        ctSym,
        "L/java.base/fixture/Api.sig",
        classBytes("fixture/Api", Opcodes.ACC_PUBLIC, "fixture/Parent", true));
    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      final JdkPlatformContext.PlatformSnapshot snapshot = context.snapshot(RELEASE_21);
      final JdkApiClassPoolReader reader = new JdkApiClassPoolReader();
      final ClassPool firstPool = reader.read(snapshot);
      final ClassPool secondPool = reader.read(snapshot);
      final LibraryClass first = (LibraryClass) firstPool.getClass("fixture/Api");
      final LibraryClass second = (LibraryClass) secondPool.getClass("fixture/Api");
      assertThat(firstPool).isNotSameAs(secondPool);
      assertThat(first).isNotSameAs(second);
      assertThat(first.fields).isNotSameAs(second.fields);
      assertThat(first.fields[0]).isNotSameAs(second.fields[0]);
      first.superClass =
          new LibraryClass(Opcodes.ACC_PUBLIC, "fixture/Mutated", "java/lang/Object");
      first.fields[0].u2accessFlags = 0;
      assertThat(second.superClass).isNull();
      assertThat(second.fields[0].u2accessFlags).isEqualTo(Opcodes.ACC_PUBLIC);
    }
  }

  private Path javaHome(final String name) throws IOException {
    final Path home = temporaryDirectory.resolve(name);
    Files.createDirectories(home.resolve("lib"));
    return home;
  }

  private Path jmodHome(final String name, final String... classNames) throws IOException {
    final Path home = javaHome(name);
    writeZip(
        home.resolve("lib/ct.sym"),
        Map.of("Z/java.base/unused/Other.sig", classBytes("unused/Other", Opcodes.ACC_PUBLIC)));
    Files.writeString(
        home.resolve("release"), "JAVA_VERSION=\"" + Runtime.version().feature() + "\"\n");
    final Path jmods = Files.createDirectories(home.resolve("jmods"));
    for (int index = 0; index < classNames.length; index++) {
      writeZip(
          jmods.resolve("module-" + index + ".jmod"),
          Map.of(
              "classes/" + classNames[index] + ".class",
              classBytes(classNames[index], Opcodes.ACC_PUBLIC)));
    }
    return home;
  }

  private static void writeCtSym(final Path path, final String entryName, final byte[] classBytes)
      throws IOException {
    writeZip(path, Map.of(entryName, classBytes));
  }

  private static void writeZip(final Path path, final Map<String, byte[]> entries)
      throws IOException {
    Files.createDirectories(path.getParent());
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      for (final Map.Entry<String, byte[]> entry : entries.entrySet()) {
        final CRC32 crc = new CRC32();
        crc.update(entry.getValue());
        final ZipEntry zipEntry = new ZipEntry(entry.getKey());
        zipEntry.setMethod(ZipEntry.STORED);
        zipEntry.setSize(entry.getValue().length);
        zipEntry.setCompressedSize(entry.getValue().length);
        zipEntry.setCrc(crc.getValue());
        output.putNextEntry(zipEntry);
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
  }

  private static byte[] classBytes(final String name, final int access) {
    return classBytes(name, access, "java/lang/Object", false);
  }

  private static byte[] classBytes(
      final String name, final int access, final String superName, final boolean includeField) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, access, name, null, superName, null);
    if (includeField) {
      writer.visitField(Opcodes.ACC_PUBLIC, "value", "I", null, null).visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }
}
