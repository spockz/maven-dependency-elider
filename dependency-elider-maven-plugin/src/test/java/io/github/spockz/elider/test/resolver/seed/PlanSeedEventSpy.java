// WHY: Seeds the test-only JDK payload before Maven invokes the packaged production decorator.

package io.github.spockz.elider.test.resolver.seed;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.eventspy.EventSpy;
import org.apache.maven.project.DependencyResolutionRequest;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.SessionData;

/** Seeds one retained-JAR plan at the exact lifecycle request boundary. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired", "PMD.SystemPrintln"})
@Named("production-plan-seed-event-spy")
@Singleton
public final class PlanSeedEventSpy implements EventSpy {
  private static final String SESSION_DATA_KEY =
      "io.github.spockz.elider.resolver.artifact-plans.v1";

  private static final String PROJECT_ARTIFACT = "lifecycle-probe-consumer";

  private static final String GROUP_ID = "io.github.spockz.elider.test";

  private static final String ARTIFACT_ID = "keep-library";

  private static final String VERSION = "1.0.0";

  private final AtomicBoolean seeded = new AtomicBoolean();

  @Override
  public void init(final Context context) {
    // This test extension reads its plan path from the child Maven invocation.
  }

  @Override
  @SuppressWarnings("PMD.LawOfDemeter")
  public void onEvent(final Object event) {
    if (event instanceof DependencyResolutionRequest request
        && PROJECT_ARTIFACT.equals(request.getMavenProject().getArtifact().getArtifactId())
        && seeded.compareAndSet(false, true)) {
      seed(request.getRepositorySession().getData(), request.getMavenProject());
    }
  }

  @Override
  public void close() {
    // The extension owns no resources.
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static void seed(final SessionData data, final MavenProject project) {
    final Path replacement =
        Path.of(System.getProperty("lifecycle.replacementFile")).toAbsolutePath().normalize();
    if (!Files.isRegularFile(replacement)) {
      throw new IllegalStateException("Replacement file is missing: " + replacement);
    }
    final String basedir = project.getBasedir().toPath().toAbsolutePath().normalize().toString();
    final List<String> projectIdentity =
        List.of(basedir, project.getGroupId(), project.getArtifactId(), project.getVersion());
    final String projectKey = encodeTuple(projectIdentity);
    final String outputHash = sha256(replacement);
    final Map<String, Object> plan =
        Map.of(
            "project",
            projectIdentity,
            "replacements",
            List.of(
                List.of(
                    GROUP_ID,
                    ARTIFACT_ID,
                    VERSION,
                    "jar",
                    "",
                    replacement.toString(),
                    outputHash)));
    final Map<String, Object> payload =
        Map.of("schemaVersion", 1, "plans", Map.of(projectKey, plan));
    final Map<String, String> directArtifactsBefore = directArtifactFiles(project);
    data.set(SESSION_DATA_KEY, payload);
    if (!directArtifactsBefore.equals(directArtifactFiles(project))) {
      throw new IllegalStateException("Seeding resolver data changed direct artifact files");
    }
    System.out.println(
        "PRODUCTION_PLAN_EVENT_SEEDED artifact="
            + GROUP_ID
            + ":"
            + ARTIFACT_ID
            + ":jar::"
            + VERSION
            + " file="
            + replacement
            + " sha256="
            + outputHash);
  }

  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.UseConcurrentHashMap"})
  private static Map<String, String> directArtifactFiles(final MavenProject project) {
    final Map<String, String> files = new TreeMap<>();
    for (final org.apache.maven.artifact.Artifact artifact : project.getDependencyArtifacts()) {
      final java.io.File file = artifact.getFile();
      files.put(
          artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion(),
          file == null
              ? "<missing>"
              : file.toPath().toAbsolutePath().normalize() + ":" + sha256(file.toPath()));
    }
    return files;
  }

  private static String encodeTuple(final List<String> fields) {
    return fields.stream()
        .map(
            value ->
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(value.getBytes(StandardCharsets.UTF_8)))
        .collect(java.util.stream.Collectors.joining("."));
  }

  private static String sha256(final Path path) {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    } catch (final IOException exception) {
      throw new UncheckedIOException("Cannot hash production replacement", exception);
    } catch (final NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }
}
