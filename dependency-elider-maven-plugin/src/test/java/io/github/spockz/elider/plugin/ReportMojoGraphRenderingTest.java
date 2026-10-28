// WHY: Verifies the standalone report goal reads saved metrics without analysis inputs.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the report Mojo renders only the graph saved by the elide goal. */
@SuppressWarnings("PMD.AvoidAccessibilityAlteration")
final class ReportMojoGraphRenderingTest {
  /** Maven group used by the report fixture. */
  private static final String GROUP_ID = "org.example";

  /** Maven project artifact identifier used by the report fixture. */
  private static final String PROJECT_ARTIFACT_ID = "consumer";

  /** Maven project version used by the report fixture. */
  private static final String PROJECT_VERSION = "1.0";

  /** Maven project coordinate used when constructing the persisted graph. */
  private static final String PROJECT_GAV =
      GROUP_ID + ":" + PROJECT_ARTIFACT_ID + ":" + PROJECT_VERSION;

  /** Artifact identifier repeated to prove occurrence-aware rendering. */
  private static final String REPEATED_ARTIFACT_ID = "unused";

  /** Display coordinate expected for each repeated dependency occurrence. */
  private static final String REPEATED_DISPLAY_COORDINATE =
      "fixture:" + REPEATED_ARTIFACT_ID + ":jar:" + PROJECT_VERSION + " (compile)";

  /** Text prefix that marks one occurrence-specific renderer row. */
  private static final String NODE_ID_MARKER = "{nodeId=";

  /** Temporary root for report snapshots and checkout identities. */
  @TempDir private Path temporaryDirectory;

  /** Creates the standalone report goal test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ReportMojoGraphRenderingTest() {}

  @Test
  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // The report must preserve several distinct persisted
  // totals.
  void reportsPersistedTotalsWithoutAnalysisInputs()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path snapshotFile = temporaryDirectory.resolve("report.json");
    final ArtifactCoordinate dropped = coordinate(REPEATED_ARTIFACT_ID);
    final ArtifactCoordinate trimmed = coordinate("partial");
    final MediatedGraphReport graph =
        MediatedGraphReportTestSupport.reportForOutputs(dropped, trimmed, PROJECT_GAV);
    MavenElisionReportWriter.write(snapshotFile, snapshot(graph, trimmed));
    final List<String> messages = new ArrayList<>();
    final ReportMojo mojo = mojo(snapshotFile, project(), messages);

    mojo.execute();

    assertThat(messages)
        .contains(
            "Snapshot: last successful elide run at 2026-10-25T12:00:00Z",
            "Whole artifacts dropped: 1 (original JAR file bytes: 2.00 KiB)",
            "Program classes pruned from retained JARs: 3 (uncompressed omitted"
                + " .class payload bytes: "
                + "1.50 KiB; excludes module descriptors and archive metadata)",
            "Mediated TEST dependency graph (captured and saved by the elide goal):");
    assertThat(messages).anySatisfy(message -> assertThat(message).contains("[EFFECTIVE_DROP]"));
    assertThat(messages)
        .anySatisfy(message -> assertThat(message).contains("[RETAINED, CLASS_TRIMMED]"));
  }

  @Test
  void rejectsReportRenderingWhenMediatedGraphIsUnavailable()
      throws IOException, ReflectiveOperationException {
    final Path snapshotFile = temporaryDirectory.resolve("graphless-report.json");
    final MavenElisionReportSnapshot graphless =
        new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            GROUP_ID,
            PROJECT_ARTIFACT_ID,
            PROJECT_VERSION,
            temporaryDirectory.toRealPath().toString(),
            "2026-10-25T12:00:00Z",
            0,
            0,
            List.of(),
            List.of(),
            0,
            0,
            List.of(),
            MediatedGraphReport.unavailable("No compatible TEST graph was captured"));
    MavenElisionReportWriter.write(snapshotFile, graphless);
    final ReportMojo mojo = mojo(snapshotFile, project(), new ArrayList<>());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Mediated dependency graph is unavailable")
        .hasMessageContaining("No compatible TEST graph was captured");
  }

  @Test
  @SuppressWarnings(
      "PMD.UnitTestContainsTooManyAsserts") // The counts jointly prove cycle termination and
  // occurrence identity.
  void rendersRepeatedOccurrencesAndCyclesFromSavedGraphOnly()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final ArtifactCoordinate leftCoordinate = coordinate("left");
    final ArtifactCoordinate rightCoordinate = coordinate("right");
    final ArtifactCoordinate sharedCoordinate = coordinate("shared");
    final ArtifactCoordinate droppedCoordinate = coordinate(REPEATED_ARTIFACT_ID);
    final org.eclipse.aether.graph.DependencyNode root =
        EffectiveGraphPolicyTestSupport.node("root");
    final org.eclipse.aether.graph.DependencyNode left =
        EffectiveGraphPolicyTestSupport.node("left");
    final org.eclipse.aether.graph.DependencyNode right =
        EffectiveGraphPolicyTestSupport.node("right");
    final org.eclipse.aether.graph.DependencyNode shared =
        EffectiveGraphPolicyTestSupport.node("shared");
    final org.eclipse.aether.graph.DependencyNode firstDrop =
        EffectiveGraphPolicyTestSupport.node(REPEATED_ARTIFACT_ID);
    final org.eclipse.aether.graph.DependencyNode secondDrop =
        EffectiveGraphPolicyTestSupport.node(REPEATED_ARTIFACT_ID);
    left.setChildren(List.of(firstDrop, shared));
    right.setChildren(List.of(secondDrop, shared));
    shared.setChildren(List.of(left));
    root.setChildren(List.of(left, right));
    final MediatedGraphReport graph =
        MediatedGraphReportTestSupport.report(
            root,
            MediatedGraphReportTestSupport.decision(
                Set.of(leftCoordinate, rightCoordinate, sharedCoordinate),
                Set.of(droppedCoordinate)),
            List.of(MediatedGraphReportTestSupport.trimRecord(sharedCoordinate)),
            PROJECT_GAV);
    final Path snapshotFile = temporaryDirectory.resolve("cycle-report.json");
    MavenElisionReportWriter.write(snapshotFile, snapshot(graph, sharedCoordinate));
    final List<String> messages = new ArrayList<>();

    mojo(snapshotFile, project(), messages).execute();

    assertThat(messages)
        .filteredOn(
            message -> message.contains(NODE_ID_MARKER) && message.contains("[EFFECTIVE_DROP]"))
        .hasSize(2);
    assertThat(messages)
        .anySatisfy(message -> assertThat(message).contains("[RETAINED, CLASS_TRIMMED]"));
    assertThat(messages)
        .filteredOn(
            message ->
                message.contains(NODE_ID_MARKER) && message.contains(REPEATED_DISPLAY_COORDINATE))
        .hasSize(2);
    final List<String> graphRows =
        messages.stream().filter(message -> message.contains(NODE_ID_MARKER)).toList();
    assertThat(graphRows).hasSize(6);
    assertThat(
            graphRows.stream()
                .map(
                    message ->
                        message.substring(message.indexOf(NODE_ID_MARKER), message.indexOf('}')))
                .distinct()
                .toList())
        .hasSize(6);
  }

  private MavenElisionReportSnapshot snapshot(
      final MediatedGraphReport graph, final ArtifactCoordinate trimmed) throws IOException {
    final ArtifactCoordinate dropped = coordinate(REPEATED_ARTIFACT_ID);
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        GROUP_ID,
        PROJECT_ARTIFACT_ID,
        PROJECT_VERSION,
        temporaryDirectory.toRealPath().toString(),
        "2026-10-25T12:00:00Z",
        1,
        2048,
        List.of(new MavenElisionReportSnapshot.DroppedArtifact(dropped.toString(), 2048)),
        List.of(dropped.toString()),
        3,
        1536,
        List.of(new MavenElisionReportSnapshot.TrimmedArtifact(trimmed.toString(), 3, 1536)),
        graph);
  }

  private static ArtifactCoordinate coordinate(final String artifactId) {
    return EffectiveGraphPolicyTestSupport.coordinate(
        artifactId, EffectiveGraphPolicyTestSupport.COMPILE_SCOPE);
  }

  private MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId(PROJECT_ARTIFACT_ID);
    project.setVersion(PROJECT_VERSION);
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
