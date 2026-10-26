/* WHY: Verifies that trimmed JARs keep selected classes and resources while removing invalid
 * signatures and producing complete immutable hash provenance. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import proguard.classfile.ClassPool;

/** Checks content, signature cleanup, and provenance of the archive writer. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier"
})
class ArchiveSanitizerTest {
  /** Identifies the digest algorithm used to bind replacement JARs to their analysis. */
  private static final String SHA_256 = "SHA-256";

  /** Identifies the source digest algorithm recorded alongside SHA-256. */
  private static final String SHA_1 = "SHA-1";

  /** Value preserved in the fixture manifest and publication sentinel. */
  private static final String PRESERVED_VALUE = "preserve";

  /** Package used for independently compiled fixture types. */
  private static final String FIXTURE_PACKAGE = "fixture";

  /** Binary name used as the fixture retention root. */
  private static final String ROOT_CLASS_NAME = "fixture.Keep";

  /** JAR entry path for the retained fixture type. */
  private static final String KEEP_CLASS_ENTRY = "fixture/Keep.class";

  /** Isolates test archive and compiler files. */
  @TempDir Path temporaryDirectory;

  /** Java 21 API pool used to validate the fixture class hierarchy. */
  private static ClassPool platformPool;

  @BeforeAll
  static void loadPlatformClasses() throws IOException {
    platformPool = new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 21);
  }

  @Test
  void writesRetainedClassesResourcesCleanManifestAndHashRecord()
      throws IOException, NoSuchAlgorithmException {
    final Path candidate = createCandidateJar();
    final byte[] originalBytes = Files.readAllBytes(candidate);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(candidate, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path trimmed = temporaryDirectory.resolve("result/fixture-1-trimmed.jar");
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1");

    final ArtifactTrimRecord record =
        new ArchiveSanitizer().sanitize(candidate, trimmed, coordinate, analysis);
    final Path repeat = temporaryDirectory.resolve("repeat/fixture-1-trimmed.jar");
    final ArtifactTrimRecord repeatRecord =
        new ArchiveSanitizer().sanitize(candidate, repeat, coordinate, analysis);

    assertThat(Files.readAllBytes(candidate)).isEqualTo(originalBytes);
    assertThat(record.coordinate()).isEqualTo(coordinate);
    assertThat(record.totalClasses()).isEqualTo(2);
    assertThat(record.retainedClasses()).isEqualTo(1);
    assertThat(record.prunedClassBytes())
        .isEqualTo(classEntrySize(candidate, "fixture/Drop.class"));
    assertThat(record.originalSha256()).isEqualTo(digest(originalBytes, SHA_256));
    assertThat(record.originalSha1()).isEqualTo(digest(originalBytes, SHA_1));
    assertThat(record.trimmedSha256()).isEqualTo(digest(Files.readAllBytes(trimmed), SHA_256));
    assertThat(record.trimmedSha1()).isEqualTo(digest(Files.readAllBytes(trimmed), SHA_1));
    assertThat(repeatRecord.trimmedSha256()).isEqualTo(record.trimmedSha256());

    try (JarFile output = new JarFile(trimmed.toFile())) {
      assertThat(output.getEntry(KEEP_CLASS_ENTRY)).isNotNull();
      assertThat(output.getEntry(FIXTURE_PACKAGE + "/Drop.class")).isNull();
      assertThat(output.getEntry("META-INF/services/example.Service")).isNotNull();
      assertThat(output.getEntry("META-INF/LICENSE.txt")).isNotNull();
      assertThat(output.getEntry("config/application.properties")).isNotNull();
      assertThat(output.getEntry("META-INF/TEST.SF")).isNull();
      assertThat(output.getEntry("META-INF/TEST.RSA")).isNull();
      assertThat(output.getEntry("META-INF/TEST.DSA")).isNull();
      assertThat(output.getEntry("META-INF/Test.eC")).isNull();
      assertThat(output.getEntry("META-INF/SIG-CUSTOM")).isNull();
      assertThat(output.getEntry("META-INF/LICENSE.txt").getSize()).isEqualTo(8);
      assertThat(output.getEntry("META-INF/services/example.Service").getSize()).isEqualTo(13);
      final Manifest manifest = output.getManifest();
      assertThat(manifest.getMainAttributes().getValue("Main-Class")).isEqualTo(ROOT_CLASS_NAME);
      assertThat(manifest.getMainAttributes().getValue("SHA-256-Digest-Manifest")).isNull();
      assertThat(manifest.getEntries()).containsKey(KEEP_CLASS_ENTRY);
      assertThat(manifest.getEntries().get(KEEP_CLASS_ENTRY).getValue("SHA-256-Digest")).isNull();
      assertThat(manifest.getEntries().get(KEEP_CLASS_ENTRY).getValue("X-Note"))
          .isEqualTo(PRESERVED_VALUE);
      assertThat(manifest.getEntries()).doesNotContainKey(FIXTURE_PACKAGE + "/Drop.class");
    }
  }

  @Test
  void rejectsReplacementJarBeforeStagingStaleAnalysisOutput() throws Exception {
    final Path original = createCandidateJar();
    final byte[] initialBytes = Files.readAllBytes(original);
    final String initialSha256 = digest(initialBytes, SHA_256);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(original, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path replacement = createCandidateJar("replacement.jar", "Live");
    final byte[] replacementBytes = Files.readAllBytes(replacement);
    Files.write(original, replacementBytes);
    final Path output = temporaryDirectory.resolve("stale-analysis-trimmed.jar");

    assertThatThrownBy(
            () ->
                new ArchiveSanitizer()
                    .prepare(
                        original,
                        output,
                        ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
                        analysis,
                        initialSha256))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("changed during trim analysis");

    assertThat(Files.readAllBytes(original)).isEqualTo(replacementBytes);
    assertThat(output).doesNotExist();
    try (JarFile replacementJar = new JarFile(original.toFile())) {
      assertThat(replacementJar.getEntry("fixture/Live.class")).isNotNull();
    }
  }

  @Test
  void capturedProvenancePreservesSourceAndOutputDigests() throws Exception {
    final Path original = createCandidateJar();
    final ArtifactDigests sourceDigests = ArtifactDigests.read(original);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(original, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path output = temporaryDirectory.resolve("captured-provenance-trimmed.jar");
    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final ArchiveSanitizer.PreparedOutput prepared =
        sanitizer.prepareWithProvenance(
            original,
            output,
            ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
            analysis,
            sourceDigests);

    final ArtifactTrimRecord record = sanitizer.publish(prepared);

    assertThat(record.originalSha256()).isEqualTo(sourceDigests.sha256());
    assertThat(record.originalSha1()).isEqualTo(sourceDigests.sha1());
    assertThat(record.originalSha256()).isEqualTo(digest(Files.readAllBytes(original), SHA_256));
    assertThat(record.originalSha1()).isEqualTo(digest(Files.readAllBytes(original), SHA_1));
    assertThat(record.trimmedSha256()).isEqualTo(digest(Files.readAllBytes(output), SHA_256));
    assertThat(record.trimmedSha1()).isEqualTo(digest(Files.readAllBytes(output), SHA_1));
  }

  @Test
  void capturedProvenanceMatchesNormalizedPathWithoutRehashingSource() throws Exception {
    final Path original = createCandidateJar();
    final ArtifactDigests sourceDigests = ArtifactDigests.read(original);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(original, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final byte[] originalBytes = Files.readAllBytes(original);
    Files.write(original, new byte[] {0}, java.nio.file.StandardOpenOption.APPEND);
    assertThat(Files.readAllBytes(original)).isNotEqualTo(originalBytes);

    final Path normalizedAlias = original.getParent().resolve(".").resolve(original.getFileName());
    final Path output = temporaryDirectory.resolve("captured-path-trimmed.jar");
    final ArchiveSanitizer.PreparedOutput prepared =
        new ArchiveSanitizer()
            .prepareWithProvenance(
                normalizedAlias,
                output,
                ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
                analysis,
                sourceDigests);

    assertThat(new ArchiveSanitizer().publish(prepared).originalSha256())
        .isEqualTo(sourceDigests.sha256());
  }

  @Test
  void capturedProvenanceRejectsDifferentSourcePath() throws Exception {
    final Path original = createCandidateJar();
    final Path other = createCandidateJar("different-source.jar", "Drop");
    final ArtifactDigests sourceDigests = ArtifactDigests.read(original);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(other, List.of(), platformPool, List.of(ROOT_CLASS_NAME));

    assertThatThrownBy(
            () ->
                new ArchiveSanitizer()
                    .prepareWithProvenance(
                        other,
                        temporaryDirectory.resolve("mismatched-path-trimmed.jar"),
                        ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
                        analysis,
                        sourceDigests))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("belong to a different path");
  }

  @Test
  void detectsStagedOutputCorruptionWhenPublishing() throws Exception {
    final Path original = createCandidateJar();
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(original, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path output = temporaryDirectory.resolve("corrupt-staged-trimmed.jar");
    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final ArchiveSanitizer.PreparedOutput prepared =
        sanitizer.prepare(
            original,
            output,
            ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
            analysis,
            null);
    Files.writeString(prepared.temporaryJar(), "corrupt staged output");

    assertThatThrownBy(() -> sanitizer.publish(prepared))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("changed while being published");

    assertThat(Files.readString(output)).isEqualTo("corrupt staged output");
    assertThat(prepared.temporaryJar()).doesNotExist();
  }

  @Test
  void failedAtomicPublicationKeepsExistingOutputAndAllowsStagingCleanup() throws Exception {
    final Path original = createCandidateJar();
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(original, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path output = temporaryDirectory.resolve("non-empty-output-directory");
    Files.createDirectory(output);
    final Path sentinel = output.resolve("existing-output");
    Files.writeString(sentinel, PRESERVED_VALUE);
    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final ArchiveSanitizer.PreparedOutput prepared =
        sanitizer.prepare(
            original,
            output,
            ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
            analysis,
            null);

    assertThatThrownBy(() -> sanitizer.publish(prepared)).isInstanceOf(IOException.class);

    assertThat(Files.readString(sentinel)).isEqualTo(PRESERVED_VALUE);
    assertThat(prepared.temporaryJar()).exists();
    sanitizer.discard(prepared);
    assertThat(prepared.temporaryJar()).doesNotExist();
  }

  private Path createCandidateJar() throws IOException {
    return createCandidateJar("original.jar", "Drop");
  }

  private Path createCandidateJar(final String jarName, final String secondClassName)
      throws IOException {
    final Path sourceRoot = temporaryDirectory.resolve(jarName + "-sources");
    final Path packageDirectory = sourceRoot.resolve("fixture");
    final Path classes = temporaryDirectory.resolve(jarName + "-classes");
    Files.createDirectories(packageDirectory);
    Files.createDirectories(classes);
    Files.writeString(
        packageDirectory.resolve("Keep.java"), "package fixture; public class Keep {}\n");
    Files.writeString(
        packageDirectory.resolve(secondClassName + ".java"),
        "package fixture; public class " + secondClassName + " {}\n");
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null
        || compiler.run(
                null,
                null,
                null,
                "-d",
                classes.toString(),
                packageDirectory.resolve("Keep.java").toString(),
                packageDirectory.resolve(secondClassName + ".java").toString())
            != 0) {
      throw new IOException("Could not compile archive sanitizer test fixture");
    }

    final Path jar = temporaryDirectory.resolve(jarName);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      writeEntry(output, "META-INF/MANIFEST.MF", manifestBytes());
      try (Stream<Path> classFiles = Files.list(classes.resolve("fixture"))) {
        for (final Path classFile : classFiles.toList()) {
          writeEntry(output, "fixture/" + classFile.getFileName(), Files.readAllBytes(classFile));
        }
      }
      writeEntry(
          output,
          "META-INF/services/example.Service",
          (ROOT_CLASS_NAME + "\n").getBytes(StandardCharsets.UTF_8));
      writeEntry(output, "META-INF/LICENSE.txt", "license\n".getBytes(StandardCharsets.UTF_8));
      writeEntry(
          output,
          "config/application.properties",
          "mode=fixture\n".getBytes(StandardCharsets.UTF_8));
      writeEntry(output, "META-INF/TEST.SF", "signature\n".getBytes(StandardCharsets.UTF_8));
      writeEntry(output, "META-INF/TEST.RSA", new byte[] {1, 2, 3});
      writeEntry(output, "META-INF/TEST.DSA", new byte[] {2, 3, 4});
      writeEntry(output, "META-INF/Test.eC", new byte[] {3, 4, 5});
      writeEntry(output, "META-INF/SIG-CUSTOM", new byte[] {4, 5, 6});
    }
    return jar;
  }

  private static long classEntrySize(final Path archivePath, final String entryName)
      throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.getEntry(entryName).getSize();
    }
  }

  @Test
  void rejectsSymlinkedOutputAliasWithoutChangingOriginal() throws IOException {
    final Path candidate = createCandidateJar();
    final byte[] originalBytes = Files.readAllBytes(candidate);
    final Path aliasDirectory = temporaryDirectory.resolve("source-alias");
    Files.createSymbolicLink(aliasDirectory, candidate.getParent());
    final Path alias = aliasDirectory.resolve(candidate.getFileName());

    assertThatThrownBy(
            () ->
                new ArchiveSanitizer()
                    .sanitize(
                        candidate,
                        alias,
                        ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
                        new DependencyJarTrimmer.TrimAnalysis(
                            0, java.util.Set.of(), java.util.Set.of())))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("must not overwrite its original");
    assertThat(Files.readAllBytes(candidate)).isEqualTo(originalBytes);
  }

  @Test
  void rejectsMultiReleaseInputAndPreservesExistingOutputAndTemporaryFiles() throws IOException {
    final Path candidate = createCandidateJar();
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(candidate, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path multiRelease = temporaryDirectory.resolve("multi-release.jar");
    copyWithMultiReleaseClass(candidate, multiRelease);
    final byte[] originalBytes = Files.readAllBytes(multiRelease);
    final Path outputDirectory = temporaryDirectory.resolve("existing-output");
    Files.createDirectories(outputDirectory);
    final Path output = outputDirectory.resolve("trimmed.jar");
    final byte[] existingOutput = "previous output".getBytes(StandardCharsets.UTF_8);
    Files.write(output, existingOutput);

    assertThatThrownBy(
            () ->
                new ArchiveSanitizer()
                    .sanitize(
                        multiRelease,
                        output,
                        ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
                        analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported modular or multi-release entry");

    assertThat(Files.readAllBytes(multiRelease)).isEqualTo(originalBytes);
    assertThat(Files.readAllBytes(output)).isEqualTo(existingOutput);
    try (Stream<Path> entries = Files.list(outputDirectory)) {
      assertThat(entries.map(path -> path.getFileName().toString()))
          .noneMatch(name -> name.startsWith(".trimmed-"));
    }
  }

  @Test
  void acceptsModuleDescriptorOnlyMultiReleaseJarAsClasspathInput() throws Exception {
    final Path candidate = createCandidateJar();
    final Path multiRelease = temporaryDirectory.resolve("module-info-only.jar");
    copyWithVersionedModuleDescriptor(candidate, multiRelease);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer()
            .analyze(multiRelease, List.of(), platformPool, List.of(ROOT_CLASS_NAME));
    final Path trimmed = temporaryDirectory.resolve("module-info-only-trimmed.jar");

    new ArchiveSanitizer()
        .sanitize(
            multiRelease,
            trimmed,
            ArtifactCoordinate.of(FIXTURE_PACKAGE, FIXTURE_PACKAGE, "1"),
            analysis);

    try (JarFile output = new JarFile(trimmed.toFile());
        java.net.URLClassLoader loader =
            new java.net.URLClassLoader(new java.net.URL[] {trimmed.toUri().toURL()}, null)) {
      assertThat(output.getEntry("META-INF/versions/9/module-info.class")).isNull();
      assertThat(output.getEntry(KEEP_CLASS_ENTRY)).isNotNull();
      assertThat(loader.loadClass(ROOT_CLASS_NAME)).isNotNull();
    }
  }

  @SuppressWarnings("PMD.LooseCoupling")
  private static byte[] manifestBytes() throws IOException {
    final Manifest manifest = new Manifest();
    final Attributes main = manifest.getMainAttributes();
    main.putValue("Manifest-Version", "1.0");
    main.putValue("Main-Class", ROOT_CLASS_NAME);
    main.putValue("SHA-256-Digest-Manifest", "invalidated");
    final Attributes keep = new Attributes();
    keep.putValue("SHA-256-Digest", "invalidated");
    keep.putValue("X-Note", PRESERVED_VALUE);
    manifest.getEntries().put(KEEP_CLASS_ENTRY, keep);
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    manifest.write(output);
    return output.toByteArray();
  }

  private static void copyWithMultiReleaseClass(final Path source, final Path destination)
      throws IOException {
    try (JarFile input = new JarFile(source.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(destination))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        copyEntry(input, output, entry);
      }
      output.putNextEntry(new JarEntry("META-INF/versions/9/fixture/Extra.class"));
      try (InputStream content = input.getInputStream(input.getEntry(KEEP_CLASS_ENTRY))) {
        content.transferTo(output);
      }
      output.closeEntry();
    }
  }

  private void copyWithVersionedModuleDescriptor(final Path source, final Path destination)
      throws IOException {
    final Path moduleSource = temporaryDirectory.resolve("module-source/module-info.java");
    final Path moduleOutput = Files.createDirectories(temporaryDirectory.resolve("module-classes"));
    Files.createDirectories(moduleSource.getParent());
    Files.writeString(moduleSource, "module fixture.module {}\n");
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null
        || compiler.run(null, null, null, "-d", moduleOutput.toString(), moduleSource.toString())
            != 0) {
      throw new IOException("Could not compile versioned module descriptor fixture");
    }
    try (JarFile input = new JarFile(source.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(destination))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        copyEntry(input, output, entries.nextElement());
      }
      writeEntry(
          output,
          "META-INF/versions/9/module-info.class",
          Files.readAllBytes(moduleOutput.resolve("module-info.class")));
    }
  }

  private static void copyEntry(
      final JarFile input, final JarOutputStream output, final JarEntry entry) throws IOException {
    output.putNextEntry(new JarEntry(entry.getName()));
    if (!entry.isDirectory()) {
      try (InputStream content = input.getInputStream(entry)) {
        content.transferTo(output);
      }
    }
    output.closeEntry();
  }

  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] contents) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(contents);
    output.closeEntry();
  }

  private static String digest(final byte[] bytes, final String algorithm)
      throws NoSuchAlgorithmException {
    final byte[] value = java.security.MessageDigest.getInstance(algorithm).digest(bytes);
    final StringBuilder result = new StringBuilder(value.length * 2);
    for (final byte item : value) {
      result.append(String.format(java.util.Locale.ROOT, "%02x", item));
    }
    return result.toString();
  }
}
