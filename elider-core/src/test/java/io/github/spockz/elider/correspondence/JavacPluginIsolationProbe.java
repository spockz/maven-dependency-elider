// WHY: Runs plugin-loader controls in a child JVM with a real application classpath.

package io.github.spockz.elider.correspondence;

import com.sun.source.util.JavacTask;
import com.sun.source.util.Plugin;
import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

/** Child process proving unsafe discovery controls and production isolation. */
public final class JavacPluginIsolationProbe {
  /** Expected child-process argument count. */
  private static final int EXPECTED_ARGUMENTS = 5;

  /** Control mode for a plugin service inside the original archive. */
  private static final String ARTIFACT_MODE = "artifact";

  /** Control mode for a plugin service on the application classpath. */
  private static final String AMBIENT_MODE = "ambient";

  /** Marker set by the benign provider in the control compilation. */
  private static final String MARKER = "elider.test.javacPluginExecuted";

  private JavacPluginIsolationProbe() {
    throw new AssertionError("No instances");
  }

  /** Runs an unisolated control followed by production reproduction in the child JVM. */
  public static void main(final String[] arguments) throws IOException {
    if (arguments.length != EXPECTED_ARGUMENTS) {
      throw new IllegalArgumentException("Expected mode, archives, and source entry");
    }
    final String mode = arguments[0];
    final Path original = Path.of(arguments[1]);
    final Path sources = Path.of(arguments[2]);
    final String sourceEntry = arguments[3];
    final Path workspace = Path.of(arguments[4]);
    Files.createDirectories(workspace);
    proveUnisolatedControlStartsPlugin(mode, original, workspace);
    System.clearProperty(MARKER);

    final SourceReproductionRequest request =
        new SourceReproductionRequest(
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            new ArtifactCoordinate("org.example", "demo", "1.0", "jar", "sources", "compile"),
            original,
            sources,
            "remote:javac-plugin-probe",
            List.of(sourceEntry),
            List.of(),
            true);
    final SourceReproductionResult result =
        SourceReproductionEngine.forCurrentJdk().reproduce(request);
    if (!(result instanceof SourceReproductionResult.Completed)) {
      throw new IOException(
          "Production reproduction failed: "
              + ((SourceReproductionResult.Abstained) result).rationale());
    }
    if (System.getProperty(MARKER) != null) {
      throw new IOException("Production source reproduction executed a Javac plugin");
    }
  }

  private static void proveUnisolatedControlStartsPlugin(
      final String mode, final Path original, final Path workspace) throws IOException {
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IOException("Pinned child JVM has no Javac compiler");
    }
    final Path source = workspace.resolve("Control.java");
    final Path output = Files.createDirectory(workspace.resolve("classes"));
    final Path emptyProcessorPath = Files.createDirectory(workspace.resolve("empty-processor"));
    Files.writeString(source, "final class Control {}", StandardCharsets.UTF_8);
    final List<String> options =
        List.of(
            "--release",
            "21",
            "-proc:none",
            "-d",
            output.toString(),
            "-classpath",
            ARTIFACT_MODE.equals(mode) ? original.toString() : "");
    try (StandardJavaFileManager fileManager =
        compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
      if (AMBIENT_MODE.equals(mode)) {
        fileManager.setLocationFromPaths(
            StandardLocation.ANNOTATION_PROCESSOR_PATH, List.of(emptyProcessorPath));
      }
      final boolean compiled =
          compiler
              .getTask(
                  null,
                  fileManager,
                  null,
                  options,
                  null,
                  fileManager.getJavaFileObjects(source.toFile()))
              .call();
      if (!compiled || !"executed".equals(System.getProperty(MARKER))) {
        throw new IOException("Unisolated control did not execute the auto-start Javac plugin");
      }
    }
  }

  /** Provider proving that unisolated Javac discovers application services. */
  public static final class AmbientClasspathPlugin implements Plugin {
    @Override
    public String getName() {
      return "ambient-marker";
    }

    @Override
    public boolean autoStart() {
      return true;
    }

    @Override
    public void init(final JavacTask task, final String... args) {
      System.setProperty(MARKER, "executed");
    }
  }
}
