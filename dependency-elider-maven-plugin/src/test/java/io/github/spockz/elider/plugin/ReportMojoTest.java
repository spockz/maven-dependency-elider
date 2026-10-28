// WHY: Verifies the standalone report goal reads saved metrics without analysis inputs.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the report Mojo reads saved data and validates project identity. */
@SuppressWarnings("PMD.AvoidAccessibilityAlteration")
final class ReportMojoTest {
  /** Temporary root for report snapshots and checkout identities. */
  @TempDir private Path temporaryDirectory;

  /** Creates the standalone report goal test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ReportMojoTest() {}

  @Test
  void reportsPersistedTotalsWithoutAnalysisInputs()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
    MavenElisionReportWriter.write(snapshotFile, snapshot());
    final List<String> messages = new ArrayList<>();
    final ReportMojo mojo = mojo(snapshotFile, project(), messages);

    mojo.execute();

    assertThat(messages)
        .contains(
            "Snapshot: last successful elide run at 2026-10-25T12:00:00Z",
            "Whole artifacts dropped: 1 (original JAR file bytes: 2.00 KiB)",
            "Program classes pruned from retained JARs: 3 (uncompressed omitted"
                + " .class payload bytes: "
                + "1.50 KiB; excludes module descriptors and archive metadata)");
  }

  @Test
  void rejectsMismatchedGav() throws IOException, ReflectiveOperationException {
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
    MavenElisionReportWriter.write(snapshotFile, snapshot());
    final List<String> messages = new ArrayList<>();
    final MavenProject mismatchedGav = project();
    mismatchedGav.setArtifactId("another-project");
    final ReportMojo gavMojo = mojo(snapshotFile, mismatchedGav, messages);

    assertThatThrownBy(gavMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("snapshot belongs to org.example:consumer:1.0");
  }

  @Test
  void rejectsAnotherCheckoutWithTheSameGav() throws IOException, ReflectiveOperationException {
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
    MavenElisionReportWriter.write(snapshotFile, snapshot());
    final List<String> messages = new ArrayList<>();
    final Path anotherCheckout = Files.createDirectory(temporaryDirectory.resolve("checkout"));
    final MavenProject mismatchedDirectory = project();
    mismatchedDirectory.setFile(anotherCheckout.resolve("pom.xml").toFile());
    final ReportMojo directoryMojo = mojo(snapshotFile, mismatchedDirectory, messages);
    assertThatThrownBy(directoryMojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("snapshot belongs to project directory");
  }

  private MavenElisionReportSnapshot snapshot() throws IOException {
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        "org.example",
        "consumer",
        "1.0",
        temporaryDirectory.toRealPath().toString(),
        "2026-10-25T12:00:00Z",
        1,
        2048,
        List.of(new MavenElisionReportSnapshot.DroppedArtifact("org.example:unused:jar:1.0", 2048)),
        List.of("org.example:unused:jar:1.0"),
        3,
        1536,
        List.of(
            new MavenElisionReportSnapshot.TrimmedArtifact(
                "org.example:partial:jar:1.0", 3, 1536)));
  }

  private MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    return project;
  }

  private static ReportMojo mojo(
      final Path snapshot, final MavenProject project, final List<String> messages)
      throws ReflectiveOperationException {
    final ReportMojo mojo = new ReportMojo();
    set(mojo, "project", project);
    set(mojo, "summaryFile", snapshot.toFile());
    mojo.setLog(recordingLog(messages));
    return mojo;
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static Log recordingLog(final List<String> messages) {
    return (Log)
        java.lang.reflect.Proxy.newProxyInstance(
            Log.class.getClassLoader(),
            new Class<?>[] {Log.class},
            (proxy, method, arguments) -> {
              if ("info".equals(method.getName())
                  && arguments != null
                  && arguments.length > 0
                  && arguments[0] instanceof CharSequence message) {
                messages.add(message.toString());
              }
              return method.getReturnType() == boolean.class ? false : null;
            });
  }

  private static void set(final Object target, final String fieldName, final Object value)
      throws ReflectiveOperationException {
    final java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }
}
