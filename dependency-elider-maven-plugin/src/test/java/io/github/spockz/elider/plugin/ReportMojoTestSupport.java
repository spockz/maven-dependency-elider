// WHY: Shares report snapshot and Mojo construction without repeating filesystem fixtures.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

/** Shared stateless report goal fixture. */
public final class ReportMojoTestSupport {
  /** WHY: The recording logger enables the expected report output path. */
  private static final String INFO_ENABLED_METHOD = "isInfoEnabled";

  private ReportMojoTestSupport() {
    throw new AssertionError("No instances");
  }

  /** Creates a report snapshot rooted in the supplied test directory. */
  public static MavenElisionReportSnapshot snapshot(
      final Path directory, final boolean layoutAssumed) throws IOException {
    final ArtifactCoordinate dropped = coordinate("unused");
    final ArtifactCoordinate trimmed = coordinate("partial");
    final MediatedGraphReport graph =
        MediatedGraphReportTestSupport.reportForOutputs(
            dropped, trimmed, "org.example:consumer:1.0");
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        "org.example",
        "consumer",
        "1.0",
        directory.toRealPath().toString(),
        "2026-10-25T12:00:00Z",
        new TrimExecutionEnvironment(21, Runtime.version().feature()),
        1,
        2048,
        0,
        0,
        List.of(new MavenElisionReportSnapshot.DroppedArtifact(dropped.toString(), 2048)),
        List.of(dropped.toString()),
        3,
        1536,
        List.of(new MavenElisionReportSnapshot.TrimmedArtifact(trimmed.toString(), 3, 1536)),
        graph,
        layoutAssumed,
        MavenElisionPolicyIdentityTestSupport.emptyPolicy(),
        ExclusionReview.unavailable("No pre-injection declaration capture is available"),
        List.of(),
        List.of(),
        List.of(),
        List.of());
  }

  /** Creates a project matching the fixture's saved report identity. */
  public static MavenProject project(final Path directory) {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setFile(directory.resolve("pom.xml").toFile());
    return project;
  }

  /** Creates the standalone report goal with a deterministic recording logger. */
  public static ReportMojo mojo(
      final Path snapshot, final MavenProject project, final List<String> messages)
      throws ReflectiveOperationException {
    final ReportMojo mojo = new ReportMojo();
    set(mojo, "project", project);
    set(mojo, "summaryFile", snapshot.toFile());
    mojo.setLog(recordingLog(messages));
    return mojo;
  }

  private static ArtifactCoordinate coordinate(final String artifactId) {
    return EffectiveGraphPolicyTestSupport.coordinate(
        artifactId, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static Log recordingLog(final List<String> messages) {
    return (Log)
        java.lang.reflect.Proxy.newProxyInstance(
            Log.class.getClassLoader(),
            new Class<?>[] {Log.class},
            (proxy, method, arguments) -> {
              if (INFO_ENABLED_METHOD.equals(method.getName())) {
                return true;
              }
              if ("info".equals(method.getName())
                  && arguments != null
                  && arguments.length > 0
                  && arguments[0] instanceof CharSequence message) {
                messages.add(message.toString());
              }
              return method.getReturnType() == boolean.class ? false : null;
            });
  }

  // WHY: Mojo test configuration is injected through private fields.
  @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
  private static void set(final Object target, final String fieldName, final Object value)
      throws ReflectiveOperationException {
    final java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }
}
