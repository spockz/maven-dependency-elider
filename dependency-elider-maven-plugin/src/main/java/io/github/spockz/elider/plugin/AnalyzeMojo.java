// WHY: Exposes the core's trace-grounded dependency analysis through Maven without changing its
// build state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import io.github.spockz.elider.trace.CompositeTraceReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Analyzes a resolved Maven dependency set using explicit runtime traces. */
@SuppressWarnings("PMD.LawOfDemeter")
@Mojo(
    name = "analyze",
    requiresDependencyResolution = org.apache.maven.plugins.annotations.ResolutionScope.TEST,
    threadSafe = true)
public final class AnalyzeMojo extends AbstractMojo {
  /** Maven project whose resolved artifacts are analyzed. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Explicit trace files that supply runtime observations. */
  @Parameter(property = "elide.traceFiles", required = true)
  private List<File> traceFiles;

  /** Global artifact identities that analysis should retain. */
  @Parameter(property = "elide.excludedArtifacts")
  private List<String> excludedArtifacts;

  /** Creates a Mojo instance for Maven injection. */
  public AnalyzeMojo() {
    super();
  }

  /** Runs analysis and reports a conservative summary without mutating Maven state. */
  @Override
  public void execute() throws MojoFailureException {
    try {
      final List<Artifact> inputArtifacts = new ArrayList<>(project.getArtifacts());
      final List<ArtifactFileRef> scanCandidates = new ArrayList<>();
      for (final Artifact artifact : inputArtifacts) {
        if (isJarCandidate(artifact)) {
          scanCandidates.add(
              ArtifactFileRef.fromPath(toCoordinate(artifact), artifact.getFile().toPath()));
        }
      }
      final CompositeTraceReader traceReader = new CompositeTraceReader();
      final TraceData trace = traceReader.readAll(toPaths(traceFiles));
      final ArtifactClassIndex index = new JarIndexScanner().scan(scanCandidates);
      final ElisionDecision decision =
          new DependencyPruner().prune(scanCandidates, index, trace, config());
      final Set<ArtifactCoordinate> identities = new LinkedHashSet<>();
      for (final Artifact artifact : inputArtifacts) {
        identities.add(toCoordinate(artifact));
      }
      report(decision, identities.size());
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency analysis failed closed: " + exception.getMessage(), exception);
    }
  }

  private PruneConfig config() throws MojoFailureException {
    final Set<ArtifactCoordinate> exclusions = new LinkedHashSet<>();
    if (excludedArtifacts != null) {
      for (final String text : excludedArtifacts) {
        exclusions.add(parseExclusion(text));
      }
    }
    return new PruneConfig(Set.of(), Set.of(), Set.of("compile", "runtime"), exclusions);
  }

  private static ArtifactCoordinate parseExclusion(final String text) throws MojoFailureException {
    final String[] pieces = text.split(":", -1);
    validateExclusion(text, pieces);
    final String version = optionalPiece(pieces, 2, null);
    final String type = optionalPiece(pieces, 3, "jar");
    final String classifier = optionalPiece(pieces, 4, "");
    return new ArtifactCoordinate(pieces[0], pieces[1], version, type, classifier, "compile");
  }

  private static void validateExclusion(final String text, final String... pieces)
      throws MojoFailureException {
    if (pieces.length < 2 || pieces.length > 5 || pieces[0].isBlank() || pieces[1].isBlank()) {
      throw new MojoFailureException(
          "Invalid elide.excludedArtifacts coordinate '"
              + text
              + "'; expected groupId:artifactId[:version[:type[:classifier]]]");
    }
  }

  private static String optionalPiece(
      final String[] pieces, final int index, final String defaultValue) {
    return pieces.length > index && !pieces[index].isBlank() ? pieces[index] : defaultValue;
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static boolean isJarCandidate(final Artifact artifact) throws IOException {
    if (!"jar".equals(artifact.getType())) {
      return false;
    }
    final File file = artifact.getFile();
    if (file == null || !file.isFile()) {
      throw new IOException("Resolved artifact has no regular file: " + artifact);
    }
    return file.getName().endsWith(".jar");
  }

  private static ArtifactCoordinate toCoordinate(final Artifact artifact) {
    return new ArtifactCoordinate(
        artifact.getGroupId(),
        artifact.getArtifactId(),
        artifact.getVersion(),
        artifact.getType(),
        artifact.getClassifier(),
        artifact.getScope());
  }

  private static Collection<Path> toPaths(final List<File> files) {
    return files == null ? List.of() : files.stream().map(File::toPath).toList();
  }

  private void report(final ElisionDecision decision, final int inputCount) {
    final int removed = decision.elidedArtifacts().size();
    if (!getLog().isInfoEnabled()) {
      return;
    }
    final String percentage =
        inputCount == 0
            ? "N/A"
            : String.format(Locale.ROOT, "%.1f%%", removed * 100.0 / inputCount);
    getLog().info("Dependency Elider analysis summary");
    getLog().info("  Whole artifacts: " + removed + " / " + inputCount + " (" + percentage + ")");
    getLog().info("  Classes removed: 0 / N/A (N/A; stage not run)");
    getLog().info("  Methods removed: 0 / N/A (N/A; stage not run)");
    getLog().info("  Fields removed: 0 / N/A (N/A; stage not run)");
    getLog().info("  Cache: unavailable");
  }
}
