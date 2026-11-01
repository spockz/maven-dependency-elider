// WHY: Proves application and artifact Javac plugins cannot run during source attribution.

package io.github.spockz.elider.correspondence;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks Javac isolation against artifact and application plugin services. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class JavacPluginServiceIsolationTest {
  /** Control mode with provider stored in the original artifact. */
  private static final String ARTIFACT_MODE = "artifact";

  /** Control mode with provider stored on the child application classpath. */
  private static final String AMBIENT_MODE = "ambient";

  /** Explicit source input in each positive reproduction fixture. */
  private static final String SOURCE_ENTRY = "src/main/java/org/example/Outer.java";

  /** Ordinary class that remains reproducible with a plugin provider in the artifact. */
  private static final String SOURCE = "package org.example; public class Outer {}";

  /** Service descriptor used by automatic Javac plugin discovery. */
  private static final String PLUGIN_SERVICE = "META-INF/services/com.sun.source.util.Plugin";

  /** Marker set only when Javac initializes the provider. */
  private static final String PLUGIN_MARKER = "elider.test.javacPluginExecuted";

  /** Isolated archives and child JVM fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void artifactServiceProviderCannotExecuteDuringProductionReproduction() throws IOException {
    final String pluginSource = artifactPluginSource();
    final SourceReproductionTestArchives.Archives archives =
        SourceReproductionTestArchives.write(
            temporaryDirectory.resolve("artifact-plugin"),
            SOURCE_ENTRY,
            SOURCE,
            false,
            Optional.of(
                new SourceReproductionTestArchives.AdditionalSource(
                    "src/main/java/org/example/MarkerPlugin.java", pluginSource)),
            false);
    SourceReproductionTestArchives.addEntryInPlace(
        archives.originalJar(),
        PLUGIN_SERVICE,
        "org.example.MarkerPlugin\n".getBytes(StandardCharsets.UTF_8));

    assertProbe(ARTIFACT_MODE, archives.originalJar(), archives.sourcesJar(), null);
  }

  @Test
  void ambientApplicationServiceProviderCannotExecuteDuringProductionReproduction()
      throws IOException {
    final SourceReproductionTestArchives.Archives archives =
        SourceReproductionTestArchives.write(
            temporaryDirectory.resolve("ambient-plugin"),
            SOURCE_ENTRY,
            SOURCE,
            false,
            Optional.empty(),
            false);
    final Path providerJar = writeAmbientProviderJar();

    assertProbe(AMBIENT_MODE, archives.originalJar(), archives.sourcesJar(), providerJar);
  }

  @SuppressWarnings(
      "PMD.DoNotUseThreads") // Preserve interruption while bounding the child process.
  private void assertProbe(
      final String mode, final Path original, final Path sources, final Path provider)
      throws IOException {
    final String classPath =
        provider == null
            ? System.getProperty("java.class.path")
            : System.getProperty("java.class.path") + java.io.File.pathSeparator + provider;
    final Path java = Path.of(System.getProperty("java.home"), "bin", "java");
    final Path probeOutput = temporaryDirectory.resolve(mode + "-probe-output.txt");
    final Process process =
        new ProcessBuilder(
                java.toString(),
                "-cp",
                classPath,
                JavacPluginIsolationProbe.class.getName(),
                mode,
                original.toString(),
                sources.toString(),
                SOURCE_ENTRY,
                temporaryDirectory.resolve(mode + "-probe-workspace").toString())
            .redirectErrorStream(true)
            .redirectOutput(probeOutput.toFile())
            .start();
    try {
      if (!process.waitFor(30, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        throw new IOException("Timed out while checking isolated Javac plugin execution");
      }
    } catch (final InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new IOException(
          "Interrupted while checking isolated Javac plugin execution", exception);
    }
    final String output = Files.readString(probeOutput, StandardCharsets.UTF_8);
    assertThat(process.exitValue()).as(output).isZero();
  }

  @SuppressWarnings(
      "PMD.LawOfDemeter") // This fixture copies the provider class from the active test
  // classloader.
  private Path writeAmbientProviderJar() throws IOException {
    final Path archive = temporaryDirectory.resolve("ambient-provider.jar");
    final String providerName = JavacPluginIsolationProbe.AmbientClasspathPlugin.class.getName();
    final String classEntry = providerName.replace('.', '/') + ".class";
    final byte[] classBytes;
    try (InputStream input =
        Thread.currentThread().getContextClassLoader().getResourceAsStream(classEntry)) {
      if (input == null) {
        throw new IOException("Ambient Javac plugin class bytes are unavailable");
      }
      classBytes = input.readAllBytes();
    }
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
      writeEntry(output, PLUGIN_SERVICE, (providerName + "\n").getBytes(StandardCharsets.UTF_8));
      writeEntry(output, classEntry, classBytes);
    }
    return archive;
  }

  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] bytes) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }

  private static String artifactPluginSource() {
    return "package org.example;\n"
        + "import com.sun.source.util.JavacTask;\n"
        + "import com.sun.source.util.Plugin;\n"
        + "public final class MarkerPlugin implements Plugin {\n"
        + " public String getName() { return \"artifact-marker\"; }\n"
        + " public boolean autoStart() { return true; }\n"
        + " public void init(JavacTask task, String... args) {"
        + " System.setProperty(\""
        + PLUGIN_MARKER
        + "\", \"executed\"); }\n"
        + "}\n";
  }
}
