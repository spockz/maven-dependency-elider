/* WHY: Proves target-release elevation preserves MRJAR overlays and rejects unsafe layouts. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.test.CompilationFixtureSupport;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks physical entry planning, output semantics, and JAR validation. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods",
  "PMD.CommentRequired",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.LawOfDemeter",
  "PMD.AvoidDuplicateLiterals",
  "PMD.SignatureDeclareThrowsException",
  "PMD.UnusedFormalParameter"
})
final class MultiReleaseArchivePlanTest {
  private static final String API_NAME = "fixture/Api";
  private static final String API_SOURCE =
      "package fixture; public class Api { public static String value() { return \"VALUE\"; } }";

  @TempDir private Path temporaryDirectory;

  @Test
  void elevatesTargetTierTrimsBaseAndPreservesHigherTierClosureEntries() throws Exception {
    final Fixture fixture = multiReleaseFixture("target-eleven", "VALUE");
    final MultiReleaseArchivePlan plan =
        MultiReleaseArchivePlan.create(
            fixture.jar(), 11, Set.of("fixture.Api"), Set.of("fixture.Drop"));
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer.TrimAnalysis(3, Set.of(API_NAME), Set.of(API_NAME));
    final Path output = temporaryDirectory.resolve("target-eleven-output.jar");
    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final ArchiveSanitizer.PreparedOutput prepared =
        sanitizer.prepareMultiRelease(
            fixture.jar(),
            output,
            ArtifactCoordinate.of("org.example", "fixture", "1"),
            analysis,
            plan,
            null);

    final ArtifactTrimRecord record;
    try {
      record = sanitizer.publish(prepared);
    } finally {
      sanitizer.discard(prepared);
    }

    assertThat(record.totalClasses()).isEqualTo(3);
    assertThat(record.retainedClasses()).isEqualTo(2);
    assertThat(record.mrjarStatus()).isEqualTo("elevated_and_trimmed");
    assertThat(record.originalPhysicalEntries()).hasValue(countEntries(fixture.jar()));
    assertThat(record.trimmedPhysicalEntries()).hasValue(countEntries(output));
    try (JarFile archive = new JarFile(output.toFile())) {
      assertThat(readEntry(archive, "fixture/Api.class"))
          .isEqualTo(Files.readAllBytes(fixture.versionNineApi()));
      assertThat(archive.getEntry("fixture/Drop.class")).isNull();
      assertThat(archive.getEntry("META-INF/versions/9/fixture/Api.class")).isNull();
      assertThat(archive.getEntry("META-INF/versions/17/fixture/Api.class")).isNotNull();
      assertThat(archive.getEntry("META-INF/versions/17/fixture/UpperOnly.class")).isNotNull();
      assertThat(archive.getEntry("fixture/UpperOnly.class")).isNotNull();
      assertThat(archive.getEntry("META-INF/versions/17/module-info.class")).isNull();
      assertThat(archive.getEntry("config/value.txt")).isNotNull();
      assertThat(readEntry(archive, "config/value.txt")).isEqualTo(bytes("nine"));
      assertThat(archive.getEntry("META-INF/versions/9/config/value.txt")).isNull();
      assertThat(archive.getEntry("META-INF/versions/17/config/value.txt")).isNotNull();
      assertThat(readEntry(archive, "META-INF/services/example.Service"))
          .isEqualTo(bytes("outside.Provider\nfixture.Api\n"));
      assertThat(archive.getEntry("META-INF/TEST.SF")).isNull();
      assertThat(archive.getManifest().getMainAttributes().getValue("Multi-Release"))
          .isEqualTo("true");
    }
    assertJarValid(output);
  }

  @Test
  void collapsesAllTiersAtTargetAndRemovesMultiReleaseManifestAttribute() throws Exception {
    final Fixture fixture = multiReleaseFixture("target-twenty-one", "VALUE");
    final MultiReleaseArchivePlan plan =
        MultiReleaseArchivePlan.create(fixture.jar(), 21, Set.of("fixture.Api"), Set.of());
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer.TrimAnalysis(3, Set.of(API_NAME), Set.of(API_NAME));
    final Path output = temporaryDirectory.resolve("target-twenty-one-output.jar");
    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final ArchiveSanitizer.PreparedOutput prepared =
        sanitizer.prepareMultiRelease(
            fixture.jar(),
            output,
            ArtifactCoordinate.of("org.example", "fixture", "1"),
            analysis,
            plan,
            null);
    try {
      final ArtifactTrimRecord record = sanitizer.publish(prepared);
      assertThat(record.totalClasses()).isEqualTo(3);
      assertThat(record.retainedClasses()).isEqualTo(1);
      assertThat(record.mrjarStatus()).isEqualTo("elevated_and_trimmed");
    } finally {
      sanitizer.discard(prepared);
    }

    try (JarFile archive = new JarFile(output.toFile());
        Stream<JarEntry> entries = archive.stream()) {
      assertThat(archive.getManifest().getMainAttributes().getValue("Multi-Release")).isNull();
      assertThat(entries.map(JarEntry::getName))
          .noneMatch(name -> name.startsWith("META-INF/versions/"));
      assertThat(readEntry(archive, "fixture/Api.class"))
          .isEqualTo(Files.readAllBytes(fixture.versionSeventeenApi()));
    }
    assertJarValid(output);
  }

  @Test
  void rejectsVersionedMetaInfResourcesAndNonCanonicalVersionDirectories() throws Exception {
    final Fixture fixture = multiReleaseFixture("invalid-layout", "VALUE");
    final Path invalidMetaInf =
        copyWithEntry(
            fixture.jar(),
            temporaryDirectory.resolve("versioned-meta-inf.jar"),
            "META-INF/versions/17/META-INF/services/example.Service",
            bytes("fixture.Api\n"));
    assertThatThrownBy(
            () -> MultiReleaseArchivePlan.create(invalidMetaInf, 11, Set.of(API_NAME), Set.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Versioned META-INF resources are not supported");

    final Path nonCanonical =
        copyWithEntry(
            fixture.jar(),
            temporaryDirectory.resolve("noncanonical-version.jar"),
            "META-INF/versions/09/fixture/Other.class",
            Files.readAllBytes(fixture.versionNineApi()));
    assertThatThrownBy(
            () -> MultiReleaseArchivePlan.create(nonCanonical, 11, Set.of(API_NAME), Set.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Invalid multi-release version directory");
  }

  @Test
  void rejectsVersionedClassesWithoutManifestActivationAndIncompatibleUpperApi() throws Exception {
    final Fixture fixture = multiReleaseFixture("invalid-manifest", "VALUE");
    final Path noMultiReleaseManifest =
        copyWithManifestAndEntry(
            fixture.jar(),
            temporaryDirectory.resolve("missing-mr-manifest.jar"),
            false,
            null,
            null);
    assertThatThrownBy(
            () ->
                MultiReleaseArchivePlan.create(
                    noMultiReleaseManifest, 11, Set.of(API_NAME), Set.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Versioned entries require Multi-Release: true");

    final Path incompatibleApi =
        compileClass(
            "api-seventeen-extra",
            17,
            "package fixture; public class Api { public static String value() { return \"x\"; } "
                + "public static void added() {} }");
    final Path apiMismatch =
        copyWithManifestAndEntry(
            fixture.jar(),
            temporaryDirectory.resolve("api-mismatch.jar"),
            true,
            "META-INF/versions/17/fixture/Api.class",
            Files.readAllBytes(incompatibleApi));
    assertThatThrownBy(
            () -> MultiReleaseArchivePlan.create(apiMismatch, 11, Set.of(API_NAME), Set.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Upper-tier public API differs");
  }

  private Fixture multiReleaseFixture(final String name, final String value) throws IOException {
    final Path rootApi = compileClass(name + "-root-api", 8, API_SOURCE.replace("VALUE", "base"));
    final Path rootDrop =
        compileClass(name + "-root-drop", 8, "package fixture; public class Drop {} ");
    final Path rootUpperOnly =
        compileClass(
            name + "-root-upper",
            8,
            "package fixture; public class UpperOnly { public int value() { return 8; } }");
    final Path nineApi = compileClass(name + "-nine-api", 9, API_SOURCE.replace("VALUE", "nine"));
    final Path seventeenApi =
        compileClass(name + "-seventeen-api", 17, API_SOURCE.replace("VALUE", "seventeen"));
    final Path upperOnly =
        compileClass(
            name + "-upper-only",
            17,
            "package fixture; public class UpperOnly { public int value() { return 17; } }");
    final Path moduleDescriptor = compileModule(name + "-module", 9);
    final Path jar = temporaryDirectory.resolve(name + ".jar");
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
      add(output, "fixture/Api.class", rootApi);
      add(output, "fixture/Drop.class", rootDrop);
      add(output, "fixture/UpperOnly.class", rootUpperOnly);
      write(output, "config/value.txt", bytes("base"));
      write(
          output,
          "META-INF/services/example.Service",
          bytes("fixture.Drop\noutside.Provider\nfixture.Api\n"));
      write(output, "META-INF/TEST.SF", bytes("signature"));
      add(output, "META-INF/versions/9/fixture/Api.class", nineApi);
      write(output, "META-INF/versions/9/config/value.txt", bytes("nine"));
      add(output, "META-INF/versions/17/fixture/Api.class", seventeenApi);
      add(output, "META-INF/versions/17/fixture/UpperOnly.class", upperOnly);
      write(output, "META-INF/versions/17/config/value.txt", bytes("seventeen"));
      add(output, "META-INF/versions/17/module-info.class", moduleDescriptor);
    }
    return new Fixture(jar, nineApi, seventeenApi);
  }

  private Path compileClass(final String name, final int release, final String source)
      throws IOException {
    final Path sourcePath =
        temporaryDirectory.resolve(name).resolve("fixture/" + className(source) + ".java");
    final Path outputDirectory = temporaryDirectory.resolve(name + "-classes");
    Files.createDirectories(sourcePath.getParent());
    Files.writeString(sourcePath, source);
    CompilationFixtureSupport.compile(
        outputDirectory, List.of(sourcePath), "--release", Integer.toString(release));
    return outputDirectory.resolve("fixture").resolve(className(source) + ".class");
  }

  private Path compileModule(final String name, final int release) throws IOException {
    final Path sourcePath = temporaryDirectory.resolve(name).resolve("module-info.java");
    final Path outputDirectory = temporaryDirectory.resolve(name + "-classes");
    Files.createDirectories(sourcePath.getParent());
    Files.writeString(sourcePath, "module fixture.module {}\n");
    CompilationFixtureSupport.compile(
        outputDirectory, List.of(sourcePath), "--release", Integer.toString(release));
    return outputDirectory.resolve("module-info.class");
  }

  private Path copyWithEntry(
      final Path source, final Path destination, final String name, final byte[] contents)
      throws IOException {
    return copyWithManifestAndEntry(source, destination, true, name, contents);
  }

  private Path copyWithManifestAndEntry(
      final Path source,
      final Path destination,
      final boolean multiRelease,
      final String addedName,
      final byte[] addedContents)
      throws IOException {
    try (JarFile input = new JarFile(source.toFile());
        JarOutputStream output =
            new JarOutputStream(Files.newOutputStream(destination), manifestFor(multiRelease))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if ("META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName())
            || entry.getName().equals(addedName)) {
          continue;
        }
        copyEntry(input, output, entry);
      }
      if (addedName != null) {
        write(output, addedName, addedContents);
      }
    }
    return destination;
  }

  private static Manifest manifestFor(final boolean multiRelease) {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (multiRelease) {
      manifest.getMainAttributes().putValue("Multi-Release", "true");
    }
    return manifest;
  }

  private static String className(final String source) {
    final int classIndex = source.indexOf("class ") + "class ".length();
    final int end =
        source.indexOf(' ', classIndex) < 0
            ? source.indexOf('{', classIndex)
            : source.indexOf(' ', classIndex);
    return source.substring(classIndex, end).trim();
  }

  private static void add(final JarOutputStream output, final String name, final Path classFile)
      throws IOException {
    write(output, name, Files.readAllBytes(classFile));
  }

  private static void write(final JarOutputStream output, final String name, final byte[] contents)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(contents);
    output.closeEntry();
  }

  private static void copyEntry(
      final JarFile input, final JarOutputStream output, final JarEntry entry) throws IOException {
    output.putNextEntry(new JarEntry(entry.getName()));
    if (!entry.isDirectory()) {
      try (InputStream contents = input.getInputStream(entry)) {
        contents.transferTo(output);
      }
    }
    output.closeEntry();
  }

  private static byte[] readEntry(final JarFile archive, final String name) throws IOException {
    try (InputStream contents = archive.getInputStream(archive.getJarEntry(name))) {
      return contents.readAllBytes();
    }
  }

  private static byte[] bytes(final String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static int countEntries(final Path path) throws IOException {
    int count = 0;
    try (JarFile archive = new JarFile(path.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        entries.nextElement();
        count++;
      }
    }
    return count;
  }

  private static void assertJarValid(final Path path) throws Exception {
    final Path jarTool = Path.of(System.getProperty("java.home"), "bin", "jar");
    final Process process =
        new ProcessBuilder(jarTool.toString(), "--validate", "--file", path.toString())
            .redirectErrorStream(true)
            .start();
    final String output;
    try (InputStream stream = process.getInputStream()) {
      output = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    }
    assertThat(process.waitFor()).as(output).isZero();
    assertThat(output).doesNotContainIgnoringCase("warning");
  }

  private record Fixture(Path jar, Path versionNineApi, Path versionSeventeenApi) {}
}
